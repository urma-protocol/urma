//! Fixed connection admission limits for the public record transport.
//! Compose this behaviour before request-response so denial precedes its setup.
//! Only pending and established connection IDs are retained, never peer history.
use crate::DialLimit;
use libp2p::{
    Multiaddr, PeerId,
    core::{ConnectedPoint, Endpoint, transport::PortUse},
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
        THandlerOutEvent, ToSwarm, dummy,
    },
};
use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    fmt,
    task::{Context, Poll},
};

const PENDING_PER_DIRECTION: usize = 4;
pub(crate) const ESTABLISHED_PER_DIRECTION: usize = 8;
const ESTABLISHED_TOTAL: usize = 16;

/// Typed local admission refusal, recognisable by downcast instead of text.
#[derive(Debug)]
pub(crate) struct LimitDenied(pub(crate) DialLimit);

impl fmt::Display for LimitDenied {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "peer {} reached", self.0)
    }
}

impl std::error::Error for LimitDenied {}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    Inbound,
    Outbound,
}

#[derive(Default)]
pub(crate) struct Limits {
    pending_in: HashSet<ConnectionId>,
    pending_out: HashSet<ConnectionId>,
    established: HashMap<ConnectionId, (PeerId, Direction)>,
}

fn denied(limit: DialLimit) -> ConnectionDenied {
    ConnectionDenied::new(LimitDenied(limit))
}

fn reserve(pending: &mut HashSet<ConnectionId>, id: ConnectionId) -> Result<(), ConnectionDenied> {
    if !pending.contains(&id) {
        if pending.len() >= PENDING_PER_DIRECTION {
            return Err(denied(DialLimit::Pending));
        }
        pending.insert(id);
    }
    Ok(())
}

impl Limits {
    fn remove_pending(&mut self, id: ConnectionId) {
        self.pending_in.remove(&id);
        self.pending_out.remove(&id);
    }

    fn admit(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        direction: Direction,
    ) -> Result<dummy::ConnectionHandler, ConnectionDenied> {
        // Handshake completion ends the pending phase even when admission fails.
        self.remove_pending(id);
        let others = self.established.iter().filter(|(held, _)| **held != id);
        let mut total = 0;
        let mut same_direction = 0;
        for (_, (held_peer, held_direction)) in others {
            if *held_peer == peer {
                return Err(denied(DialLimit::Duplicate));
            }
            total += 1;
            same_direction += usize::from(*held_direction == direction);
        }
        if total >= ESTABLISHED_TOTAL || same_direction >= ESTABLISHED_PER_DIRECTION {
            return Err(denied(DialLimit::Established));
        }
        // A later behaviour can still deny this connection. Count it only when
        // the Swarm confirms establishment, not while constructing handlers.
        Ok(dummy::ConnectionHandler)
    }
}

impl NetworkBehaviour for Limits {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_pending_inbound_connection(
        &mut self,
        id: ConnectionId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        reserve(&mut self.pending_in, id)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        id: ConnectionId,
        _: Option<PeerId>,
        _: &[Multiaddr],
        _: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        reserve(&mut self.pending_out, id)?;
        Ok(Vec::new())
    }

    fn handle_established_inbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.admit(id, peer, Direction::Inbound)
    }

    fn handle_established_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.admit(id, peer, Direction::Outbound)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(event) => {
                self.remove_pending(event.connection_id);
                let direction = match event.endpoint {
                    ConnectedPoint::Listener { .. } => Direction::Inbound,
                    ConnectedPoint::Dialer { .. } => Direction::Outbound,
                };
                self.established
                    .entry(event.connection_id)
                    .or_insert((event.peer_id, direction));
            }
            FromSwarm::ConnectionClosed(event) => {
                self.remove_pending(event.connection_id);
                self.established.remove(&event.connection_id);
            }
            FromSwarm::DialFailure(event) => {
                self.remove_pending(event.connection_id);
                self.established.remove(&event.connection_id);
            }
            FromSwarm::ListenFailure(event) => {
                self.remove_pending(event.connection_id);
                self.established.remove(&event.connection_id);
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _: PeerId,
        _: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {}
    }

    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::swarm::{
        DialError, ListenError,
        behaviour::{ConnectionClosed, ConnectionEstablished, DialFailure, ListenFailure},
    };

    fn id(value: usize) -> ConnectionId {
        ConnectionId::new_unchecked(value)
    }

    fn address() -> Multiaddr {
        "/ip4/127.0.0.1/tcp/1234".parse().unwrap()
    }

    fn endpoint(direction: Direction) -> ConnectedPoint {
        match direction {
            Direction::Inbound => ConnectedPoint::Listener {
                local_addr: address(),
                send_back_addr: address(),
            },
            Direction::Outbound => ConnectedPoint::Dialer {
                address: address(),
                role_override: Endpoint::Dialer,
                port_use: PortUse::New,
            },
        }
    }

    fn begin(
        limits: &mut Limits,
        id: ConnectionId,
        direction: Direction,
    ) -> Result<(), ConnectionDenied> {
        match direction {
            Direction::Inbound => {
                limits.handle_pending_inbound_connection(id, &address(), &address())
            }
            Direction::Outbound => limits
                .handle_pending_outbound_connection(id, None, &[], Endpoint::Dialer)
                .map(|_| ()),
        }
    }

    fn admit(
        limits: &mut Limits,
        id: ConnectionId,
        peer: PeerId,
        direction: Direction,
    ) -> Result<(), ConnectionDenied> {
        match direction {
            Direction::Inbound => {
                limits.handle_established_inbound_connection(id, peer, &address(), &address())
            }
            Direction::Outbound => limits.handle_established_outbound_connection(
                id,
                peer,
                &address(),
                Endpoint::Dialer,
                PortUse::New,
            ),
        }
        .map(|_| ())
    }

    fn established(limits: &mut Limits, id: ConnectionId, peer: PeerId, direction: Direction) {
        limits.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
            peer_id: peer,
            connection_id: id,
            endpoint: &endpoint(direction),
            failed_addresses: &[],
            other_established: 0,
        }));
    }

    fn close(limits: &mut Limits, id: ConnectionId, peer: PeerId, direction: Direction) {
        limits.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
            peer_id: peer,
            connection_id: id,
            endpoint: &endpoint(direction),
            cause: None,
            remaining_established: 0,
        }));
    }

    fn failed(limits: &mut Limits, id: ConnectionId, direction: Direction, denied_elsewhere: bool) {
        match direction {
            Direction::Inbound => {
                let error = if denied_elsewhere {
                    ListenError::Denied {
                        cause: denied(DialLimit::Pending),
                    }
                } else {
                    ListenError::Aborted
                };
                limits.on_swarm_event(FromSwarm::ListenFailure(ListenFailure {
                    local_addr: &address(),
                    send_back_addr: &address(),
                    error: &error,
                    connection_id: id,
                    peer_id: None,
                }));
            }
            Direction::Outbound => {
                let error = if denied_elsewhere {
                    DialError::Denied {
                        cause: denied(DialLimit::Pending),
                    }
                } else {
                    DialError::Aborted
                };
                limits.on_swarm_event(FromSwarm::DialFailure(DialFailure {
                    peer_id: None,
                    error: &error,
                    connection_id: id,
                }));
            }
        }
    }

    fn empty(limits: &Limits) {
        assert!(limits.pending_in.is_empty());
        assert!(limits.pending_out.is_empty());
        assert!(limits.established.is_empty());
    }

    #[test]
    fn pending_limits_are_independent_and_duplicate_callbacks_do_not_fill_slots() {
        let mut limits = Limits::default();
        for value in 0..4 {
            begin(&mut limits, id(value), Direction::Inbound).unwrap();
            begin(&mut limits, id(value + 4), Direction::Outbound).unwrap();
        }
        begin(&mut limits, id(0), Direction::Inbound).unwrap();
        begin(&mut limits, id(4), Direction::Outbound).unwrap();
        assert!(begin(&mut limits, id(8), Direction::Inbound).is_err());
        assert!(begin(&mut limits, id(9), Direction::Outbound).is_err());
        assert_eq!(limits.pending_in.len(), 4);
        assert_eq!(limits.pending_out.len(), 4);
        for value in 0..8 {
            let direction = if value < 4 {
                Direction::Inbound
            } else {
                Direction::Outbound
            };
            failed(&mut limits, id(value), direction, false);
        }
        empty(&limits);
    }

    #[test]
    fn established_direction_limits_allow_eight_each_and_sixteen_total() {
        let mut limits = Limits::default();
        for (direction, offset) in [(Direction::Inbound, 0), (Direction::Outbound, 20)] {
            for value in 0..ESTABLISHED_PER_DIRECTION {
                let id = id(offset + value);
                let peer = PeerId::random();
                begin(&mut limits, id, direction).unwrap();
                admit(&mut limits, id, peer, direction).unwrap();
                established(&mut limits, id, peer, direction);
            }
            let denied_id = id(offset + ESTABLISHED_PER_DIRECTION);
            begin(&mut limits, denied_id, direction).unwrap();
            assert!(admit(&mut limits, denied_id, PeerId::random(), direction).is_err());
            assert!(!limits.pending_in.contains(&denied_id));
            assert!(!limits.pending_out.contains(&denied_id));
        }
        assert_eq!(limits.established.len(), ESTABLISHED_TOTAL);
        for direction in [Direction::Inbound, Direction::Outbound] {
            assert!(admit(&mut limits, id(99), PeerId::random(), direction).is_err());
        }
    }

    #[test]
    fn a_peer_has_one_connection_across_both_directions() {
        for direction in [Direction::Inbound, Direction::Outbound] {
            let mut limits = Limits::default();
            let peer = PeerId::random();
            let opposite = if direction == Direction::Inbound {
                Direction::Outbound
            } else {
                Direction::Inbound
            };
            begin(&mut limits, id(1), direction).unwrap();
            admit(&mut limits, id(1), peer, direction).unwrap();
            established(&mut limits, id(1), peer, direction);
            for denied_direction in [direction, opposite] {
                begin(&mut limits, id(2), denied_direction).unwrap();
                assert!(admit(&mut limits, id(2), peer, denied_direction).is_err());
            }
            assert!(limits.pending_in.is_empty());
            assert!(limits.pending_out.is_empty());
            close(&mut limits, id(1), peer, direction);
            begin(&mut limits, id(3), opposite).unwrap();
            admit(&mut limits, id(3), peer, opposite).unwrap();
        }
    }

    #[test]
    fn failed_handshakes_release_pending_slots_in_both_directions() {
        for direction in [Direction::Inbound, Direction::Outbound] {
            let mut limits = Limits::default();
            for value in 0..4 {
                begin(&mut limits, id(value), direction).unwrap();
            }
            failed(&mut limits, id(0), direction, false);
            begin(&mut limits, id(4), direction).unwrap();
            for value in 1..5 {
                failed(&mut limits, id(value), direction, false);
            }
            empty(&limits);
        }
    }

    #[test]
    fn downstream_denial_releases_state_without_counting_establishment() {
        for direction in [Direction::Inbound, Direction::Outbound] {
            let mut limits = Limits::default();
            for after_admission in [false, true] {
                begin(&mut limits, id(1), direction).unwrap();
                if after_admission {
                    admit(&mut limits, id(1), PeerId::random(), direction).unwrap();
                }
                assert!(limits.established.is_empty());
                failed(&mut limits, id(1), direction, true);
                empty(&limits);
            }
        }
    }

    #[test]
    fn distinct_peer_churn_retains_no_peer_history() {
        let mut limits = Limits::default();
        for value in 0..1000 {
            let direction = if value % 2 == 0 {
                Direction::Inbound
            } else {
                Direction::Outbound
            };
            let peer = PeerId::random();
            begin(&mut limits, id(value), direction).unwrap();
            admit(&mut limits, id(value), peer, direction).unwrap();
            established(&mut limits, id(value), peer, direction);
            close(&mut limits, id(value), peer, direction);
            empty(&limits);
        }
    }

    #[test]
    fn duplicate_established_events_and_redundant_cleanup_are_harmless() {
        let mut limits = Limits::default();
        let peer = PeerId::random();
        begin(&mut limits, id(1), Direction::Inbound).unwrap();
        admit(&mut limits, id(1), peer, Direction::Inbound).unwrap();
        established(&mut limits, id(1), peer, Direction::Inbound);
        established(&mut limits, id(1), peer, Direction::Inbound);
        admit(&mut limits, id(1), peer, Direction::Inbound).unwrap();
        assert_eq!(limits.established.len(), 1);
        close(&mut limits, id(1), peer, Direction::Inbound);
        close(&mut limits, id(1), peer, Direction::Inbound);
        failed(&mut limits, id(1), Direction::Inbound, false);
        failed(&mut limits, id(1), Direction::Outbound, false);
        empty(&limits);
    }
}
