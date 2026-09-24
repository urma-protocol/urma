use anyhow::Result;
use bitcoin::{
    Txid, XOnlyPublicKey,
    hashes::Hash,
    secp256k1::{Keypair, Secp256k1},
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use urma_names::{
    engine::Registry,
    name::Name,
    payload::{Approval, Genesis, Mode, NameOp, OwnerOp, Payload},
    state::{Binding, Bound, Commit, Observation, Rejection, Resolution, Target, Verdict},
};

const GENESIS: u8 = 0x10;
const EXPIRY: u64 = 5000;

fn key(seed: u8) -> XOnlyPublicKey {
    Keypair::from_seckey_slice(&Secp256k1::new(), &[seed; 32])
        .unwrap()
        .x_only_public_key()
        .0
}

fn txid(seed: u8) -> Txid {
    Txid::from_byte_array([seed; 32])
}

fn tx(id: u32) -> Txid {
    let mut bytes = [0xee; 32];
    bytes[..4].copy_from_slice(&id.to_le_bytes());
    Txid::from_byte_array(bytes)
}

fn name(text: &str) -> Name {
    Name::parse(text).unwrap()
}

fn approvers() -> Vec<XOnlyPublicKey> {
    let mut keys = vec![key(11), key(12), key(13)];
    keys.sort_by_key(|key| key.serialize());
    keys
}

fn open(expiry: u32, window: u16) -> Genesis {
    Genesis {
        mode: Mode::Open,
        expiry_blocks: expiry,
        reveal_max_blocks: window,
        threshold: 0,
        approvers: Vec::new(),
    }
}

fn administered() -> Genesis {
    Genesis {
        mode: Mode::Administered,
        expiry_blocks: 5000,
        reveal_max_blocks: 144,
        threshold: 2,
        approvers: approvers(),
    }
}

fn owner_in(registry: Txid, op: u8, text: &str, target: Txid) -> Payload {
    let inner = OwnerOp {
        registry,
        salt: [7; 16],
        name: name(text),
        target,
    };
    match op {
        1 => Payload::Claim(inner),
        2 => Payload::Update(inner),
        3 => Payload::Renew(inner),
        other => panic!("op {other}"),
    }
}

fn owner(op: u8, text: &str, target: Txid) -> Payload {
    owner_in(txid(GENESIS), op, text, target)
}

fn record_hash(payload: &Payload) -> [u8; 32] {
    Sha256::digest(payload.to_record().unwrap().encode().unwrap()).into()
}

fn approve(record: u32, hash: [u8; 32]) -> Payload {
    Payload::Approve(Approval {
        registry: txid(GENESIS),
        record_txid: tx(record),
        record_sha256: hash,
    })
}

fn suspend(text: &str) -> Payload {
    Payload::Suspend(NameOp {
        registry: txid(GENESIS),
        name: name(text),
    })
}

fn restore(text: &str) -> Payload {
    Payload::Restore(NameOp {
        registry: txid(GENESIS),
        name: name(text),
    })
}

fn observe(
    id: u32,
    author: XOnlyPublicKey,
    payload: Payload,
    height: u64,
    position: u32,
    commit: (u64, u32, u32),
) -> Observation {
    Observation {
        txid: tx(id),
        author,
        record_sha256: record_hash(&payload),
        payload,
        height,
        position,
        commit: Commit {
            txid: tx(id + 1_000_000),
            vout: commit.2,
            height: commit.0,
            position: commit.1,
        },
    }
}

fn advance(registry: &mut Registry, height: u64) {
    while registry.height() < height {
        registry.connect(registry.height() + 1, Vec::new()).unwrap();
    }
}

fn block(
    registry: &mut Registry,
    height: u64,
    observations: Vec<Observation>,
) -> BTreeMap<Txid, Verdict> {
    advance(registry, height - 1);
    registry
        .connect(height, observations)
        .unwrap()
        .into_iter()
        .map(|outcome| (outcome.txid, outcome.verdict))
        .collect()
}

fn one(
    registry: &mut Registry,
    id: u32,
    author: XOnlyPublicKey,
    payload: Payload,
    height: u64,
) -> Verdict {
    block(
        registry,
        height,
        vec![observe(id, author, payload, height, 1, (height - 1, 1, 0))],
    )[&tx(id)]
}

fn bound(registry: &Registry, text: &str) -> Bound {
    match registry.resolve(&name(text)) {
        Resolution::Bound(bound) => bound,
        other => panic!("{text}: {other:?}"),
    }
}

fn activate(
    registry: &mut Registry,
    id: u32,
    author: XOnlyPublicKey,
    text: &str,
    target: Txid,
    height: u64,
) -> u64 {
    let request = owner(1, text, target);
    let hash = record_hash(&request);
    assert_eq!(one(registry, id, author, request, height), Verdict::Pending);
    assert_eq!(
        one(registry, id + 1, key(11), approve(id, hash), height + 1),
        Verdict::Applied
    );
    assert_eq!(
        one(registry, id + 2, key(12), approve(id, hash), height + 2),
        Verdict::Applied
    );
    height + 2 + EXPIRY
}

#[test]
fn open_mode_assigns_at_the_first_valid_reveal_and_expires_by_height() -> Result<()> {
    let mut r = Registry::new(txid(GENESIS), 5_000_000, open(210_240, 144))?;
    let s1 = txid(0x51);
    let s2 = txid(0x52);
    let same = observe(
        1,
        key(9),
        owner(1, "bob", s1),
        5_000_050,
        2,
        (5_000_050, 1, 0),
    );
    assert_eq!(
        block(&mut r, 5_000_050, vec![same])[&tx(1)],
        Verdict::Invalid(Rejection::RevealWindow)
    );
    let early = observe(
        2,
        key(9),
        owner(1, "bob", s1),
        5_000_051,
        1,
        (5_000_000, 3, 0),
    );
    assert_eq!(
        block(&mut r, 5_000_051, vec![early])[&tx(2)],
        Verdict::Invalid(Rejection::CommitNotAfterGenesis)
    );
    let foreign = observe(
        3,
        key(9),
        owner_in(txid(0x11), 1, "bob", s1),
        5_000_052,
        1,
        (5_000_051, 1, 0),
    );
    assert_eq!(
        block(&mut r, 5_000_052, vec![foreign])[&tx(3)],
        Verdict::Invalid(Rejection::ForeignRegistry)
    );
    assert_eq!(r.resolve(&name("bob")), Resolution::Unbound);
    let bob = observe(
        10,
        key(1),
        owner(1, "bob", s1),
        5_000_101,
        3,
        (5_000_100, 7, 0),
    );
    assert_eq!(
        block(&mut r, 5_000_101, vec![bob])[&tx(10)],
        Verdict::Applied
    );
    let state = bound(&r, "bob");
    assert_eq!(
        (
            state.owner,
            state.target,
            state.expiry,
            state.claim_txid,
            state.last_txid
        ),
        (key(1), Target::Publication(s1), 5_210_341, tx(10), tx(10))
    );
    let mallory = observe(
        11,
        key(2),
        owner(1, "bob", s1),
        5_000_102,
        1,
        (5_000_101, 5, 0),
    );
    assert_eq!(
        block(&mut r, 5_000_102, vec![mallory])[&tx(11)],
        Verdict::Inert(Rejection::NameBound)
    );
    let late = observe(
        12,
        key(3),
        owner(1, "erin", s1),
        5_000_200,
        1,
        (5_000_001, 1, 0),
    );
    assert_eq!(
        block(&mut r, 5_000_200, vec![late])[&tx(12)],
        Verdict::Invalid(Rejection::RevealWindow)
    );
    assert_eq!(
        one(&mut r, 13, key(2), owner(2, "bob", s2), 5_050_000),
        Verdict::Invalid(Rejection::NotOwner)
    );
    assert_eq!(
        one(&mut r, 14, key(1), owner(2, "bob", s2), 5_100_000),
        Verdict::Applied
    );
    let state = bound(&r, "bob");
    assert_eq!(
        (state.target, state.expiry, state.last_txid),
        (Target::Publication(s2), 5_210_341, tx(14))
    );
    assert_eq!(
        one(&mut r, 15, key(1), owner(3, "bob", s2), 5_105_171),
        Verdict::Applied
    );
    assert_eq!(bound(&r, "bob").expiry, 5_315_411);
    assert_eq!(
        one(&mut r, 16, key(1), owner(3, "bob", s2), 5_315_411),
        Verdict::Invalid(Rejection::NameUnbound)
    );
    assert_eq!(r.resolve(&name("bob")), Resolution::Unbound);
    let dave = observe(
        17,
        key(4),
        owner(1, "bob", s1),
        5_315_412,
        9,
        (5_315_400, 2, 0),
    );
    let again = observe(
        18,
        key(1),
        owner(1, "bob", s2),
        5_315_412,
        1,
        (5_315_400, 9, 0),
    );
    let verdicts = block(&mut r, 5_315_412, vec![dave, again]);
    assert_eq!(verdicts[&tx(17)], Verdict::Applied);
    assert_eq!(verdicts[&tx(18)], Verdict::Inert(Rejection::LostRace));
    assert_eq!(
        (bound(&r, "bob").owner, bound(&r, "bob").expiry),
        (key(4), 5_525_652)
    );
    Ok(())
}

#[test]
fn open_mode_ties_go_to_the_oldest_commit_key_and_claims_at_expiry_are_valid() -> Result<()> {
    let mut r = Registry::new(txid(GENESIS), 1000, open(5000, 144))?;
    let s1 = txid(0x51);
    let carol = observe(1, key(3), owner(1, "bob", s1), 1101, 5, (1090, 3, 0));
    let bob = observe(2, key(1), owner(1, "bob", s1), 1101, 3, (1100, 7, 0));
    let v = block(&mut r, 1101, vec![bob, carol]);
    assert_eq!(
        (v[&tx(1)], v[&tx(2)]),
        (Verdict::Applied, Verdict::Inert(Rejection::LostRace))
    );
    assert_eq!(bound(&r, "bob").owner, key(3));
    let a = observe(3, key(5), owner(1, "pos", s1), 1102, 1, (1100, 9, 0));
    let b = observe(4, key(6), owner(1, "pos", s1), 1102, 2, (1100, 2, 1));
    let c = observe(5, key(7), owner(1, "pos", s1), 1102, 3, (1100, 2, 0));
    let v = block(&mut r, 1102, vec![a, b, c]);
    assert_eq!(v[&tx(5)], Verdict::Applied);
    assert_eq!(v[&tx(3)], Verdict::Inert(Rejection::LostRace));
    assert_eq!(v[&tx(4)], Verdict::Inert(Rejection::LostRace));
    assert_eq!(bound(&r, "pos").owner, key(7));
    let claim = observe(6, key(8), owner(1, "bob", s1), 6101, 1, (6100, 1, 0));
    let renew = observe(7, key(3), owner(3, "bob", s1), 6101, 2, (6100, 2, 0));
    let v = block(&mut r, 6101, vec![claim, renew]);
    assert_eq!(
        (v[&tx(6)], v[&tx(7)]),
        (Verdict::Applied, Verdict::Invalid(Rejection::NotOwner))
    );
    assert_eq!(bound(&r, "bob").owner, key(8));
    Ok(())
}

#[test]
fn reserved_names_reorg_replay_and_pruning() -> Result<()> {
    let mut r = Registry::new(txid(GENESIS), 1000, open(5000, 144))?;
    assert_eq!(
        one(&mut r, 1, key(1), owner(1, "park", txid(0)), 1010),
        Verdict::Applied
    );
    assert_eq!(bound(&r, "park").target, Target::Reserved);
    let before = r.clone();
    assert_eq!(
        one(&mut r, 2, key(1), owner(2, "park", txid(0x51)), 1011),
        Verdict::Applied
    );
    assert_eq!(bound(&r, "park").target, Target::Publication(txid(0x51)));
    assert_eq!(
        one(&mut r, 3, key(1), owner(3, "park", txid(0)), 1012),
        Verdict::Applied
    );
    assert_eq!(
        (bound(&r, "park").target, bound(&r, "park").expiry),
        (Target::Reserved, 6012)
    );
    let after = r.clone();
    assert_eq!(r.disconnect()?, 1012);
    assert_eq!(r.disconnect()?, 1011);
    assert_eq!(r, before);
    assert_eq!(
        one(&mut r, 2, key(1), owner(2, "park", txid(0x51)), 1011),
        Verdict::Applied
    );
    assert_eq!(
        one(&mut r, 3, key(1), owner(3, "park", txid(0)), 1012),
        Verdict::Applied
    );
    assert_eq!(r, after);
    while r.height() > 1000 {
        r.disconnect()?;
    }
    assert!(r.disconnect().is_err());
    assert_eq!(r.resolve(&name("park")), Resolution::Unbound);
    assert!(r.names().is_empty());
    assert_eq!(
        one(&mut r, 4, key(11), suspend("park"), 1002),
        Verdict::Invalid(Rejection::OpenRegistry)
    );
    assert_eq!(
        one(&mut r, 5, key(11), approve(1, [0; 32]), 1003),
        Verdict::Invalid(Rejection::OpenRegistry)
    );
    assert_eq!(r.reversible_blocks(), 3);
    r.prune(1);
    assert_eq!(r.reversible_blocks(), 1);
    assert_eq!(r.disconnect()?, 1003);
    assert!(r.disconnect().is_err());
    assert_eq!(r.height(), 1002);
    Ok(())
}

#[test]
fn blocks_are_contiguous_and_observations_belong_to_their_block() -> Result<()> {
    let mut r = Registry::new(txid(GENESIS), 1000, open(5000, 144))?;
    assert!(r.connect(1002, Vec::new()).is_err());
    let elsewhere = observe(1, key(1), owner(1, "a", txid(1)), 1002, 1, (1001, 1, 0));
    assert!(r.connect(1001, vec![elsewhere]).is_err());
    let first = observe(1, key(1), owner(1, "a", txid(1)), 1001, 1, (1000, 1, 0));
    let second = observe(2, key(1), owner(1, "b", txid(1)), 1001, 1, (1000, 1, 0));
    assert!(r.connect(1001, vec![first, second]).is_err());
    assert_eq!((r.height(), r.reversible_blocks()), (1000, 0));
    assert!(Registry::new(txid(GENESIS), 1000, open(144, 144)).is_err());
    Ok(())
}

#[test]
fn administered_activation_needs_m_distinct_approvals_of_the_exact_record() -> Result<()> {
    let mut r = Registry::new(txid(GENESIS), 1000, administered())?;
    let s1 = txid(0x51);
    let request = owner(1, "bob", s1);
    let hash = record_hash(&request);
    let same_block = vec![
        observe(100, key(1), request, 1010, 2, (1009, 1, 0)),
        observe(101, key(11), approve(100, hash), 1010, 3, (1009, 2, 0)),
    ];
    let v = block(&mut r, 1010, same_block);
    assert_eq!(
        (v[&tx(100)], v[&tx(101)]),
        (Verdict::Pending, Verdict::Invalid(Rejection::UnknownRecord))
    );
    assert_eq!(r.resolve(&name("bob")), Resolution::Unbound);
    assert_eq!(
        one(&mut r, 102, key(11), approve(100, hash), 1011),
        Verdict::Applied
    );
    assert_eq!(r.resolve(&name("bob")), Resolution::Unbound);
    assert_eq!(
        one(&mut r, 103, key(11), approve(100, hash), 1012),
        Verdict::Inert(Rejection::Repeated)
    );
    assert_eq!(
        one(&mut r, 104, key(2), approve(100, hash), 1013),
        Verdict::Invalid(Rejection::NotApprover)
    );
    assert_eq!(
        one(&mut r, 105, key(12), approve(100, [9; 32]), 1014),
        Verdict::Invalid(Rejection::HashMismatch)
    );
    assert_eq!(
        one(&mut r, 106, key(12), approve(999, hash), 1015),
        Verdict::Invalid(Rejection::UnknownRecord)
    );
    assert_eq!(
        one(&mut r, 107, key(12), approve(100, hash), 1016),
        Verdict::Applied
    );
    let state = bound(&r, "bob");
    assert_eq!(
        (
            state.owner,
            state.target,
            state.expiry,
            state.claim_txid,
            state.last_txid
        ),
        (key(1), Target::Publication(s1), 6016, tx(100), tx(107))
    );
    assert_eq!(
        one(&mut r, 108, key(13), approve(100, hash), 1017),
        Verdict::Inert(Rejection::Completed)
    );
    let pending = &r.pending()[&tx(100)];
    assert!(pending.completed);
    assert_eq!(pending.approvals.len(), 2);
    assert_eq!(
        one(&mut r, 109, key(5), owner(1, "zero", txid(0)), 1018),
        Verdict::Invalid(Rejection::ZeroTarget)
    );
    Ok(())
}

#[test]
fn losing_requests_are_inert_forever_even_after_expiry() -> Result<()> {
    let mut r = Registry::new(txid(GENESIS), 1000, administered())?;
    let s1 = txid(0x51);
    let s2 = txid(0x52);
    let bob = owner(1, "shop", s1);
    let bob_hash = record_hash(&bob);
    let eve = owner(1, "shop", s2);
    let eve_hash = record_hash(&eve);
    assert_eq!(one(&mut r, 100, key(1), bob, 1010), Verdict::Pending);
    assert_eq!(one(&mut r, 101, key(2), eve, 1011), Verdict::Pending);
    assert_eq!(
        one(&mut r, 102, key(11), approve(101, eve_hash), 1012),
        Verdict::Applied
    );
    assert_eq!(
        one(&mut r, 103, key(12), approve(101, eve_hash), 1013),
        Verdict::Applied
    );
    assert_eq!(bound(&r, "shop").owner, key(2));
    assert_eq!(
        one(&mut r, 104, key(11), approve(100, bob_hash), 1014),
        Verdict::Applied
    );
    assert_eq!(
        one(&mut r, 105, key(12), approve(100, bob_hash), 1015),
        Verdict::Inert(Rejection::NameBound)
    );
    assert_eq!(bound(&r, "shop").owner, key(2));
    advance(&mut r, 6013);
    assert_eq!(r.resolve(&name("shop")), Resolution::Unbound);
    assert_eq!(
        one(&mut r, 106, key(13), approve(100, bob_hash), 6014),
        Verdict::Inert(Rejection::Completed)
    );
    assert_eq!(r.resolve(&name("shop")), Resolution::Unbound);
    activate(&mut r, 110, key(1), "shop", s1, 6020);
    assert_eq!(bound(&r, "shop").owner, key(1));
    Ok(())
}

#[test]
fn updates_need_approval_and_renewals_need_the_served_target() -> Result<()> {
    let mut r = Registry::new(txid(GENESIS), 1000, administered())?;
    let s1 = txid(0x51);
    let s2 = txid(0x52);
    let expiry = activate(&mut r, 100, key(1), "bob", s1, 1010);
    assert_eq!(bound(&r, "bob").expiry, expiry);
    assert_eq!(
        one(&mut r, 200, key(2), owner(2, "bob", s2), 1020),
        Verdict::Invalid(Rejection::NotOwner)
    );
    assert_eq!(
        one(&mut r, 201, key(1), owner(2, "bob", txid(0)), 1021),
        Verdict::Invalid(Rejection::ZeroTarget)
    );
    assert_eq!(
        one(&mut r, 202, key(1), owner(2, "none", s2), 1022),
        Verdict::Invalid(Rejection::NameUnbound)
    );
    let update = owner(2, "bob", s2);
    let hash = record_hash(&update);
    assert_eq!(one(&mut r, 203, key(1), update, 1023), Verdict::Pending);
    assert_eq!(bound(&r, "bob").target, Target::Publication(s1));
    assert_eq!(
        one(&mut r, 204, key(13), approve(203, hash), 1024),
        Verdict::Applied
    );
    assert_eq!(bound(&r, "bob").target, Target::Publication(s1));
    assert_eq!(
        one(&mut r, 205, key(11), approve(203, hash), 1025),
        Verdict::Applied
    );
    let state = bound(&r, "bob");
    assert_eq!(
        (state.target, state.expiry, state.last_txid),
        (Target::Publication(s2), expiry, tx(205))
    );
    assert_eq!(
        one(&mut r, 206, key(1), owner(3, "bob", s1), 1030),
        Verdict::Invalid(Rejection::TargetChanged)
    );
    assert_eq!(
        one(&mut r, 207, key(2), owner(3, "bob", s2), 1031),
        Verdict::Invalid(Rejection::NotOwner)
    );
    assert_eq!(
        one(&mut r, 208, key(1), owner(3, "bob", s2), 1032),
        Verdict::Applied
    );
    assert_eq!(bound(&r, "bob").expiry, 6032);
    Ok(())
}

#[test]
fn suspension_counts_per_phase_blocks_activation_and_survives_expiry() -> Result<()> {
    let mut r = Registry::new(txid(GENESIS), 1000, administered())?;
    let s1 = txid(0x51);
    let s3 = txid(0x53);
    activate(&mut r, 100, key(1), "bob", s1, 1010);
    assert_eq!(
        one(&mut r, 300, key(11), suspend("bob"), 1020),
        Verdict::Applied
    );
    assert!(matches!(r.resolve(&name("bob")), Resolution::Bound(..)));
    assert_eq!(
        one(&mut r, 301, key(11), suspend("bob"), 1021),
        Verdict::Inert(Rejection::Repeated)
    );
    assert_eq!(
        one(&mut r, 302, key(2), suspend("bob"), 1022),
        Verdict::Invalid(Rejection::NotApprover)
    );
    assert_eq!(
        one(&mut r, 303, key(12), suspend("bob"), 1023),
        Verdict::Applied
    );
    assert_eq!(r.resolve(&name("bob")), Resolution::Suspended);
    assert_eq!(
        one(&mut r, 304, key(13), suspend("bob"), 1024),
        Verdict::Inert(Rejection::WrongPhase)
    );
    let update = owner(2, "bob", s3);
    let hash = record_hash(&update);
    assert_eq!(one(&mut r, 305, key(1), update, 1025), Verdict::Pending);
    assert_eq!(
        one(&mut r, 306, key(11), approve(305, hash), 1026),
        Verdict::Applied
    );
    assert_eq!(
        one(&mut r, 307, key(12), approve(305, hash), 1027),
        Verdict::Applied
    );
    assert_eq!(r.resolve(&name("bob")), Resolution::Suspended);
    let Binding::Bound(inner) = &r.names()[&name("bob")].binding else {
        panic!("unbound")
    };
    assert_eq!(inner.target, Target::Publication(s3));
    assert_eq!(
        one(&mut r, 308, key(1), owner(3, "bob", s3), 1028),
        Verdict::Applied
    );
    assert_eq!(r.resolve(&name("bob")), Resolution::Suspended);
    assert_eq!(
        one(&mut r, 309, key(11), restore("bob"), 1029),
        Verdict::Applied
    );
    assert_eq!(
        one(&mut r, 310, key(11), restore("bob"), 1030),
        Verdict::Inert(Rejection::Repeated)
    );
    assert_eq!(
        one(&mut r, 311, key(12), restore("bob"), 1031),
        Verdict::Applied
    );
    assert_eq!(
        (bound(&r, "bob").target, bound(&r, "bob").expiry),
        (Target::Publication(s3), 6028)
    );
    assert_eq!(
        one(&mut r, 312, key(13), suspend("bob"), 1032),
        Verdict::Applied
    );
    assert!(matches!(r.resolve(&name("bob")), Resolution::Bound(..)));
    assert_eq!(
        one(&mut r, 313, key(11), suspend("bob"), 1033),
        Verdict::Applied
    );
    assert_eq!(r.resolve(&name("bob")), Resolution::Suspended);
    advance(&mut r, 6028);
    assert_eq!(r.resolve(&name("bob")), Resolution::Suspended);
    assert_eq!(r.names()[&name("bob")].binding, Binding::Unbound);
    let eve = owner(1, "bob", s1);
    let eve_hash = record_hash(&eve);
    assert_eq!(one(&mut r, 400, key(2), eve, 6030), Verdict::Pending);
    assert_eq!(
        one(&mut r, 401, key(11), approve(400, eve_hash), 6031),
        Verdict::Applied
    );
    assert_eq!(
        one(&mut r, 402, key(12), approve(400, eve_hash), 6032),
        Verdict::Inert(Rejection::NameSuspended)
    );
    assert_eq!(r.resolve(&name("bob")), Resolution::Suspended);
    assert_eq!(
        one(&mut r, 403, key(12), restore("bob"), 6033),
        Verdict::Applied
    );
    assert_eq!(
        one(&mut r, 404, key(13), restore("bob"), 6034),
        Verdict::Applied
    );
    assert_eq!(r.resolve(&name("bob")), Resolution::Unbound);
    assert_eq!(
        one(&mut r, 405, key(13), approve(400, eve_hash), 6035),
        Verdict::Inert(Rejection::Completed)
    );
    activate(&mut r, 410, key(2), "bob", s1, 6040);
    assert_eq!(bound(&r, "bob").owner, key(2));
    Ok(())
}

#[test]
fn registry_state_round_trips_through_json() -> Result<()> {
    let mut r = Registry::new(txid(GENESIS), 1000, administered())?;
    activate(&mut r, 100, key(1), "bob", txid(0x51), 1010);
    assert_eq!(
        one(&mut r, 300, key(11), suspend("bob"), 1020),
        Verdict::Applied
    );
    let json = serde_json::to_string(&r)?;
    let back: Registry = serde_json::from_str(&json)?;
    assert_eq!(back, r);
    assert_eq!(back.resolve(&name("bob")), r.resolve(&name("bob")));
    Ok(())
}
