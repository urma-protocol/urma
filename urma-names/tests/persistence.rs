use bitcoin::{
    Txid, XOnlyPublicKey,
    hashes::Hash,
    secp256k1::{Keypair, Secp256k1},
};
use serde_json::json;
use std::collections::BTreeMap;
use urma_core::error::Error;
use urma_names::{
    engine::{AppliedBlock, BlockDelta, Change, Registry},
    name::Name,
    payload::{Approval, Genesis, Mode, NameOp, OwnerOp, Payload},
    state::{Binding, Commit, NameState, Observation, Rejection, Verdict},
};

fn txid(seed: u8) -> Txid {
    Txid::from_byte_array([seed; 32])
}

fn key(seed: u8) -> XOnlyPublicKey {
    Keypair::from_seckey_slice(&Secp256k1::new(), &[seed; 32])
        .unwrap()
        .x_only_public_key()
        .0
}

fn name(text: &str) -> Name {
    Name::parse(text).unwrap()
}

fn open() -> Genesis {
    Genesis {
        mode: Mode::Open,
        expiry_blocks: 5,
        reveal_max_blocks: 2,
        threshold: 0,
        approvers: Vec::new(),
    }
}

fn administered() -> Genesis {
    let mut approvers = vec![key(11), key(12), key(13)];
    approvers.sort_by_key(|key| key.serialize());
    Genesis {
        mode: Mode::Administered,
        expiry_blocks: 20,
        reveal_max_blocks: 4,
        threshold: 2,
        approvers,
    }
}

fn owner(update: bool, text: &str, target: u8) -> Payload {
    let op = OwnerOp {
        registry: txid(1),
        salt: [7; 16],
        name: name(text),
        target: txid(target),
    };
    if update {
        Payload::Update(op)
    } else {
        Payload::Claim(op)
    }
}

fn approval(record: u8) -> Payload {
    Payload::Approve(Approval {
        registry: txid(1),
        record_txid: txid(record),
        record_sha256: [record; 32],
    })
}

fn vote(restore: bool) -> Payload {
    let op = NameOp {
        registry: txid(1),
        name: name("alice"),
    };
    if restore {
        Payload::Restore(op)
    } else {
        Payload::Suspend(op)
    }
}

// Pure engine inputs: no signature, inclusion or consensus claim is made here.
fn observation(
    id: u8,
    author: XOnlyPublicKey,
    payload: Payload,
    height: u64,
    position: u32,
) -> Observation {
    Observation {
        txid: txid(id),
        author,
        record_sha256: [id; 32],
        payload,
        height,
        position,
        commit: Commit {
            txid: txid(id.wrapping_add(100)),
            vout: 0,
            height: height - 1,
            position,
        },
    }
}

fn open_blocks() -> Vec<Vec<Observation>> {
    vec![
        Vec::new(),
        vec![observation(20, key(2), owner(false, "alice", 90), 2, 0)],
        vec![observation(30, key(2), owner(true, "alice", 91), 3, 0)],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(), // Expiry at height 7, with no record to produce an outcome.
    ]
}

fn admin_blocks() -> Vec<Vec<Observation>> {
    let keys = administered().approvers;
    vec![
        Vec::new(),
        vec![observation(20, key(2), owner(false, "alice", 90), 2, 0)],
        vec![observation(30, keys[0], approval(20), 3, 0)],
        vec![observation(40, keys[1], approval(20), 4, 0)],
        vec![observation(50, key(3), owner(false, "alice", 91), 5, 0)],
        vec![
            observation(60, keys[0], approval(50), 6, 0),
            observation(61, keys[0], vote(false), 6, 1),
        ],
        vec![
            // Completion becomes inert because alice is already bound, but
            // approvals and completed still change and must be persisted.
            observation(70, keys[1], approval(50), 7, 0),
            observation(71, keys[1], vote(false), 7, 1),
        ],
        vec![observation(80, keys[0], vote(true), 8, 0)],
        vec![observation(90, keys[1], vote(true), 9, 0)],
    ]
}

fn history(rules: Genesis, blocks: &[Vec<Observation>]) -> (Registry, Vec<BlockDelta>) {
    let mut registry = Registry::new(txid(1), 0, rules).unwrap();
    let frames = blocks
        .iter()
        .enumerate()
        .map(|(index, observations)| {
            registry
                .connect_delta(index as u64 + 1, observations.clone())
                .unwrap()
                .delta
        })
        .collect();
    (registry, frames)
}

fn restore(registry: &Registry, frames: Vec<BlockDelta>) -> Result<Registry, Error> {
    Registry::from_parts(
        registry.genesis(),
        registry.genesis_height(),
        registry.rules().clone(),
        registry.height(),
        registry.names().clone(),
        registry.pending().clone(),
        frames,
    )
}

fn write_changes<K: Ord + Clone, V: Clone>(
    map: &mut BTreeMap<K, V>,
    changes: &[Change<K, V>],
    forward: bool,
) {
    for change in changes {
        match if forward {
            &change.after
        } else {
            &change.before
        } {
            Some(value) => {
                map.insert(change.key.clone(), value.clone());
            }
            None => {
                map.remove(&change.key);
            }
        }
    }
}

#[test]
fn deltas_match_legacy_transitions_and_support_inverse_and_replay() {
    for (rules, blocks) in [(open(), open_blocks()), (administered(), admin_blocks())] {
        let initial = Registry::new(txid(1), 0, rules).unwrap();
        let mut legacy = initial.clone();
        let mut projected = initial.clone();
        let mut names = BTreeMap::new();
        let mut pending = BTreeMap::new();
        let mut frames = Vec::new();
        for (index, observations) in blocks.iter().enumerate() {
            let height = index as u64 + 1;
            let outcomes = legacy.connect(height, observations.clone()).unwrap();
            let applied = projected
                .connect_delta(height, observations.clone())
                .unwrap();
            assert_eq!(applied.outcomes, outcomes);
            assert_eq!(projected, legacy);
            write_changes(&mut names, &applied.delta.names, true);
            write_changes(&mut pending, &applied.delta.pending, true);
            assert_eq!(&names, projected.names());
            assert_eq!(&pending, projected.pending());
            frames.push(applied.delta);
        }
        let final_state = projected.clone();
        for frame in frames.iter().rev() {
            assert_eq!(legacy.disconnect().unwrap(), frame.height);
            assert_eq!(projected.disconnect_delta().unwrap(), *frame);
            write_changes(&mut names, &frame.names, false);
            write_changes(&mut pending, &frame.pending, false);
            assert_eq!(&names, projected.names());
            assert_eq!(&pending, projected.pending());
            assert_eq!(projected, legacy);
        }
        assert_eq!(projected, initial);
        for (index, observations) in blocks.iter().enumerate() {
            let replay = projected
                .connect_delta(index as u64 + 1, observations.clone())
                .unwrap();
            assert_eq!(replay.delta, frames[index]);
        }
        assert_eq!(projected, final_state);
    }
}

#[test]
fn empty_blocks_and_expiry_are_persisted_without_outcomes() {
    let (registry, frames) = history(open(), &open_blocks());
    assert_eq!(
        frames[0],
        BlockDelta {
            height: 1,
            names: Vec::new(),
            pending: Vec::new()
        }
    );
    let expiry = frames.last().unwrap();
    assert_eq!(expiry.height, 7);
    assert_eq!(expiry.names.len(), 1);
    assert!(matches!(
        expiry.names[0].before.as_ref().unwrap().binding,
        Binding::Bound(_)
    ));
    assert_eq!(expiry.names[0].after, Some(NameState::unbound()));
    let mut restored = restore(&registry, frames).unwrap();
    restored.disconnect_delta().unwrap();
    let reapplied = restored.connect_delta(7, Vec::new()).unwrap();
    assert!(reapplied.outcomes.is_empty());
    assert_eq!(restored, registry);
}

#[test]
fn pending_approvals_votes_and_inert_completion_are_in_the_delta() {
    let (registry, frames) = history(administered(), &admin_blocks());
    let pending = &frames[1].pending[0];
    assert_eq!(pending.key, txid(20));
    assert!(pending.before.is_none());
    assert!(pending.after.as_ref().unwrap().approvals.is_empty());
    assert_eq!(
        frames[2].pending[0].after.as_ref().unwrap().approvals.len(),
        1
    );
    assert!(frames[3].pending[0].after.as_ref().unwrap().completed);
    let partial_vote = frames[5].names[0].after.as_ref().unwrap();
    assert_eq!(partial_vote.suspend_votes.len(), 1);
    let completed = &frames[6].pending[0];
    assert_eq!(completed.key, txid(50));
    assert!(!completed.before.as_ref().unwrap().completed);
    assert!(completed.after.as_ref().unwrap().completed);
    assert_eq!(completed.after.as_ref().unwrap().approvals.len(), 2);
    let mut previous = restore(&registry, frames.clone()).unwrap();
    for _ in 0..3 {
        previous.disconnect_delta().unwrap();
    }
    let block = previous
        .connect_delta(7, admin_blocks()[6].clone())
        .unwrap();
    assert!(block.outcomes.iter().any(|outcome| outcome.txid == txid(70)
        && outcome.verdict == Verdict::Inert(Rejection::NameBound)));
    assert_eq!(block.delta, frames[6]);
    assert_eq!(
        frames[7].names[0]
            .after
            .as_ref()
            .unwrap()
            .restore_votes
            .len(),
        1
    );
    let final_name = registry.names().get(&name("alice")).unwrap();
    assert!(!final_name.suspended);
    assert!(final_name.suspend_votes.is_empty() && final_name.restore_votes.is_empty());
}

#[test]
fn pruned_suffix_restores_exact_state_and_rebuilds_expiries() {
    let (mut registry, frames) = history(administered(), &admin_blocks());
    registry.prune(3);
    let suffix = frames[frames.len() - 3..].to_vec();
    let mut restored = restore(&registry, suffix.clone()).unwrap();
    assert_eq!(restored, registry);
    assert_eq!(restored.reversible_blocks(), 3);
    for height in 10..=24 {
        assert_eq!(
            registry.connect_delta(height, Vec::new()).unwrap(),
            restored.connect_delta(height, Vec::new()).unwrap()
        );
    }
    assert_eq!(registry.names()[&name("alice")].binding, Binding::Unbound);
    assert_eq!(restored, registry);
    let (mut registry, _) = history(administered(), &admin_blocks());
    registry.prune(0);
    let mut restored = restore(&registry, Vec::new()).unwrap();
    assert_eq!(restored, registry);
    assert!(matches!(
        restored.disconnect_delta(),
        Err(Error::Missing(_))
    ));
}

#[test]
fn absent_and_present_unbound_have_distinct_undo() {
    for (before, after) in [
        (None, Some(NameState::unbound())),
        (Some(NameState::unbound()), None),
    ] {
        let frame = BlockDelta {
            height: 1,
            names: vec![Change {
                key: name("alice"),
                before: before.clone(),
                after: after.clone(),
            }],
            pending: Vec::new(),
        };
        let names = after
            .into_iter()
            .map(|state| (name("alice"), state))
            .collect();
        let mut registry = Registry::from_parts(
            txid(1),
            0,
            open(),
            1,
            names,
            BTreeMap::new(),
            vec![frame.clone()],
        )
        .unwrap();
        assert_eq!(registry.disconnect_delta().unwrap(), frame);
        assert_eq!(registry.names().get(&name("alice")), before.as_ref());
    }
}

#[test]
fn restoration_rejects_malformed_heights_rules_and_suffixes() {
    let (registry, frames) = history(open(), &open_blocks()[..3]);
    for malformed in [
        {
            let mut f = frames.clone();
            f[2].height = 4;
            f
        },
        {
            let mut f = frames.clone();
            f.remove(1);
            f
        },
        {
            let mut f = frames.clone();
            f.swap(0, 1);
            f
        },
        {
            let mut f = frames.clone();
            f[0].height = 0;
            f
        },
    ] {
        assert!(restore(&registry, malformed).is_err());
    }
    assert!(
        Registry::from_parts(
            txid(1),
            5,
            open(),
            4,
            BTreeMap::new(),
            BTreeMap::new(),
            Vec::new()
        )
        .is_err()
    );
    let at_genesis = BlockDelta {
        height: 5,
        names: Vec::new(),
        pending: Vec::new(),
    };
    assert!(
        Registry::from_parts(
            txid(1),
            5,
            open(),
            5,
            BTreeMap::new(),
            BTreeMap::new(),
            vec![at_genesis]
        )
        .is_err()
    );
    let mut invalid_rules = open();
    invalid_rules.reveal_max_blocks = 0;
    assert!(
        Registry::from_parts(
            txid(1),
            0,
            invalid_rules,
            0,
            BTreeMap::new(),
            BTreeMap::new(),
            Vec::new()
        )
        .is_err()
    );
}

#[test]
fn restoration_checks_duplicates_and_after_values_through_the_whole_suffix() {
    let (registry, frames) = history(open(), &open_blocks()[..3]);
    let mut duplicate = frames.clone();
    let repeated = duplicate[2].names[0].clone();
    duplicate[2].names.push(repeated);
    assert!(restore(&registry, duplicate).is_err());
    let mut mismatch = frames.clone();
    mismatch[2].names[0].after = None;
    assert!(restore(&registry, mismatch).is_err());
    let mut older_mismatch = frames;
    older_mismatch[1].names[0].after = Some(NameState::unbound());
    assert!(restore(&registry, older_mismatch).is_err());

    let (registry, frames) = history(administered(), &admin_blocks());
    let mut duplicate = frames.clone();
    let repeated = duplicate[6].pending[0].clone();
    duplicate[6].pending.push(repeated);
    assert!(restore(&registry, duplicate).is_err());
    let mut mismatch = frames.clone();
    mismatch[6].pending[0].after.as_mut().unwrap().completed = false;
    assert!(restore(&registry, mismatch).is_err());
    let mut older_mismatch = frames;
    older_mismatch[1].pending[0].after = None;
    assert!(restore(&registry, older_mismatch).is_err());
}

#[test]
fn legacy_json_keeps_registry_fields_and_previous_encoding() {
    let (registry, frames) = history(open(), &open_blocks()[..3]);
    let alice = name("alice");
    let state = registry.names()[&alice].clone();
    let previous = frames[2].names[0].before.clone().unwrap();
    let expected = json!({
        "genesis": txid(1), "genesis_height": 0, "rules": open(), "height": 3,
        "names": {"alice": state}, "pending": {}, "expiries": [[7, "alice"]],
        "undo": [
            {"names": [], "pending": []},
            {"names": [["alice", "Absent"]], "pending": []},
            {"names": [["alice", {"Present": previous}]], "pending": []}
        ]
    });
    assert_eq!(serde_json::to_value(&registry).unwrap(), expected);
    let restored = restore(&registry, frames).unwrap();
    assert_eq!(serde_json::to_value(&restored).unwrap(), expected);
    let decoded: Registry = serde_json::from_value(expected).unwrap();
    assert_eq!(decoded, registry);
}

#[test]
fn new_dtos_are_strict_and_invalid_connects_do_not_mutate_state() {
    let mut registry = Registry::new(txid(1), 0, open()).unwrap();
    let initial = registry.clone();
    assert!(matches!(registry.disconnect(), Err(Error::Missing(_))));
    assert!(registry.connect_delta(2, Vec::new()).is_err());
    let outside = observation(20, key(2), owner(false, "alice", 90), 2, 0);
    assert!(registry.connect_delta(1, vec![outside]).is_err());
    let duplicate = observation(20, key(2), owner(false, "alice", 90), 1, 0);
    assert!(
        registry
            .connect_delta(1, vec![duplicate.clone(), duplicate])
            .is_err()
    );
    assert_eq!(registry, initial);
    let mut ceiling = Registry::new(txid(1), u64::MAX, open()).unwrap();
    assert!(matches!(
        ceiling.connect_delta(0, Vec::new()),
        Err(Error::Capacity(_))
    ));
    assert_eq!(ceiling.height(), u64::MAX);
    assert_eq!(ceiling.reversible_blocks(), 0);
    let applied = registry.connect_delta(1, Vec::new()).unwrap();
    let encoded = serde_json::to_value(&applied).unwrap();
    assert_eq!(
        serde_json::from_value::<AppliedBlock>(encoded.clone()).unwrap(),
        applied
    );
    let mut unknown = encoded;
    unknown["extra"] = json!(true);
    assert!(serde_json::from_value::<AppliedBlock>(unknown).is_err());
    let mut unknown = serde_json::to_value(&applied.delta).unwrap();
    unknown["extra"] = json!(true);
    assert!(serde_json::from_value::<BlockDelta>(unknown).is_err());
    let mut unknown = serde_json::to_value(Change {
        key: name("alice"),
        before: None::<NameState>,
        after: Some(NameState::unbound()),
    })
    .unwrap();
    unknown["extra"] = json!(true);
    assert!(serde_json::from_value::<Change<Name, NameState>>(unknown).is_err());
}
