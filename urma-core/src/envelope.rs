use crate::error::{Context, Error, bail, ensure};
use crate::{
    container,
    format::{PublicRecord, RecordKind, Urma},
    multipart::{Geometry, MultipartRecord},
};
use bitcoin::{
    Script, ScriptBuf, Transaction, TxOut, Witness, XOnlyPublicKey,
    hashes::Hash,
    opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF},
    script::{Builder, Instruction, PushBytesBuf},
    secp256k1::{Keypair, Message, Secp256k1},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo},
    transaction::Version,
};

pub struct ParsedEnvelope {
    pub author: XOnlyPublicKey,
    pub record: Vec<u8>,
    pub script: ScriptBuf,
    pub control: ControlBlock,
}

fn validate_record(record: &[u8]) -> Result<(), Error> {
    match RecordKind::parse(record)? {
        RecordKind::Private => {
            container::inspect_header(record)?;
        }
        RecordKind::DataPart | RecordKind::LeafManifest | RecordKind::RootManifest => {
            MultipartRecord::decode(record)?;
        }
        RecordKind::Container => bail!("offline container cannot be published as a record"),
        RecordKind::Post
        | RecordKind::Reply
        | RecordKind::Profile
        | RecordKind::Avatar
        | RecordKind::WirePost
        | RecordKind::WireReply
        | RecordKind::ProfileRecord => {
            PublicRecord::decode(record)?;
        }
    }
    Ok(())
}

fn record_script(record: &[u8], author: XOnlyPublicKey) -> Result<ScriptBuf, Error> {
    let mut builder = Builder::new()
        .push_x_only_key(&author)
        .push_opcode(OP_CHECKSIG)
        .push_int(0)
        .push_opcode(OP_IF)
        .push_slice(Urma::MAGIC);
    for part in record.chunks(520) {
        builder = match part {
            [value @ 1..=16] => builder.push_int(i64::from(*value)),
            [0x81] => builder.push_int(-1),
            bytes => builder.push_slice(PushBytesBuf::try_from(bytes.to_vec())?),
        };
    }
    Ok(builder.push_opcode(OP_ENDIF).into_script())
}

pub fn build(record: &[u8], signer: &Keypair) -> Result<(ScriptBuf, TaprootSpendInfo), Error> {
    build_for_author(record, signer.x_only_public_key().0)
}

pub fn build_for_author(
    record: &[u8],
    author: XOnlyPublicKey,
) -> Result<(ScriptBuf, TaprootSpendInfo), Error> {
    validate_record(record)?;
    let script = record_script(record, author)?;
    let info = TaprootBuilder::new()
        .add_leaf(0, script.clone())?
        .finalize(&Secp256k1::new(), author)
        .map_err(|tree| Error::Invalid(format!("invalid single-leaf Taproot tree: {tree:?}")))?;
    Ok((script, info))
}

pub fn witness(
    signature: &[u8],
    script: &ScriptBuf,
    info: &TaprootSpendInfo,
) -> Result<Witness, Error> {
    ensure!(
        signature.len() == 64,
        "URMA requires implicit SIGHASH_DEFAULT"
    );
    let control = info
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .context("script missing from Taproot tree")?
        .serialize();
    ensure!(control.len() == 33, "URMA requires one leaf");
    Ok(Witness::from_slice(&[
        signature,
        script.as_bytes(),
        &control,
    ]))
}

pub fn is_candidate(witness: &Witness) -> bool {
    if witness.len() != 3 {
        return false;
    }
    let Some(script) = witness.iter().nth(1) else {
        return false;
    };
    script.len() >= 41 && script[34..41] == [0, 99, 4, b'U', b'R', b'M', b'A']
}

pub fn extract(witness: &Witness) -> Result<ParsedEnvelope, Error> {
    let parsed = extract_envelope(witness)?;
    validate_record(&parsed.record)?;
    Ok(parsed)
}

fn extract_envelope(witness: &Witness) -> Result<ParsedEnvelope, Error> {
    ensure!(witness.len() == 3, "invalid witness item count");
    let items: Vec<_> = witness.iter().collect();
    ensure!(
        items[0].len() == 64 && items[2].len() == 33,
        "invalid signature or control length"
    );
    ensure!(
        items[1].len() >= 42
            && items[1].len()
                <= Geometry::RECORD_BYTES + 3 * Geometry::RECORD_BYTES.div_ceil(520) + 42,
        "script size out of bounds"
    );
    let script = ScriptBuf::from_bytes(items[1].to_vec());
    let author = XOnlyPublicKey::from_slice(&items[1][1..33])?;
    let control = ControlBlock::decode(items[2])?;
    ensure!(
        control.leaf_version == LeafVersion::TapScript && control.internal_key == author,
        "invalid author/internal-key commitment"
    );
    let mut ops = script.instructions_minimal().skip(5);
    let mut record = Vec::new();
    loop {
        let instruction = ops.next().context("missing envelope end")??;
        match instruction {
            Instruction::PushBytes(part) => {
                ensure!(
                    !part.is_empty() && part.len() <= 520,
                    "invalid record segment"
                );
                record.extend_from_slice(part.as_bytes());
            }
            Instruction::Op(opcode) if opcode == OP_ENDIF => {
                let Some(instruction) = ops.next() else { break };
                bail!("trailing script instruction: {instruction:?}");
            }
            Instruction::Op(opcode) if (0x51..=0x60).contains(&opcode.to_u8()) => {
                record.push(opcode.to_u8() - 0x50)
            }
            Instruction::Op(opcode) if opcode.to_u8() == 0x4f => record.push(0x81),
            instruction => bail!("invalid envelope instruction {instruction:?}"),
        }
        ensure!(record.len() <= Geometry::RECORD_BYTES, "record too large");
    }
    ensure!(
        record_script(&record, author)? == script,
        "noncanonical envelope or segmentation"
    );
    Ok(ParsedEnvelope {
        author,
        record,
        script,
        control,
    })
}

pub fn verify_reveal(reveal: &Transaction, commit: &Transaction) -> Result<ParsedEnvelope, Error> {
    let parsed = verify_record_proof(reveal, commit)?;
    validate_record(&parsed.record)?;
    Ok(parsed)
}

pub(crate) fn verify_record_proof(
    reveal: &Transaction,
    commit: &Transaction,
) -> Result<ParsedEnvelope, Error> {
    ensure!(reveal.input.len() == 1, "reveal must have one input");
    let source = reveal.input[0].previous_output;
    ensure!(
        source.txid == commit.compute_txid(),
        "reveal does not spend the supplied commit"
    );
    let prevout = commit
        .output
        .get(usize::try_from(source.vout)?)
        .context("commit outpoint absent")?;
    verify_prevout_proof(reveal, prevout)
}

pub fn verify_prevout(reveal: &Transaction, prevout: &TxOut) -> Result<ParsedEnvelope, Error> {
    let parsed = verify_prevout_proof(reveal, prevout)?;
    validate_record(&parsed.record)?;
    Ok(parsed)
}

fn verify_prevout_proof(reveal: &Transaction, prevout: &TxOut) -> Result<ParsedEnvelope, Error> {
    let parsed = extract_reveal_envelope(reveal)?;
    ensure!(
        reveal.output[0].value <= prevout.value,
        "reveal spends more than prevout"
    );
    ensure!(
        prevout.script_pubkey.is_p2tr(),
        "commit output must be P2TR"
    );
    let secp = Secp256k1::verification_only();
    let output_key = XOnlyPublicKey::from_slice(&prevout.script_pubkey.as_bytes()[2..34])?;
    ensure!(
        parsed
            .control
            .verify_taproot_commitment(&secp, output_key, &parsed.script),
        "invalid Taproot commitment"
    );
    let signature = bitcoin::secp256k1::schnorr::Signature::from_slice(
        reveal.input[0]
            .witness
            .iter()
            .next()
            .context("signature absent")?,
    )?;
    let hash = SighashCache::new(reveal).taproot_script_spend_signature_hash(
        0,
        &Prevouts::All(std::slice::from_ref(prevout)),
        TapLeafHash::from_script(&parsed.script, LeafVersion::TapScript),
        TapSighashType::Default,
    )?;
    secp.verify_schnorr(
        &signature,
        &Message::from_digest(hash.to_byte_array()),
        &parsed.author,
    )
    .context("invalid author signature")?;
    Ok(parsed)
}
pub fn extract_reveal(reveal: &Transaction) -> Result<ParsedEnvelope, Error> {
    let parsed = extract_reveal_envelope(reveal)?;
    validate_record(&parsed.record)?;
    Ok(parsed)
}

fn extract_reveal_envelope(reveal: &Transaction) -> Result<ParsedEnvelope, Error> {
    validate_reveal_shape(reveal.version.0, reveal.input.len(), reveal.output.len())?;
    validate_reveal_scripts(&reveal.input[0].script_sig, &reveal.output[0].script_pubkey)?;
    extract_envelope(&reveal.input[0].witness)
}

pub fn validate_reveal_shape(version: i32, inputs: usize, outputs: usize) -> Result<(), Error> {
    ensure!(
        version == Version::TWO.0 && inputs == 1 && outputs == 1,
        "invalid reveal transaction shape"
    );
    Ok(())
}

pub fn validate_reveal_scripts(script_sig: &Script, return_script: &Script) -> Result<(), Error> {
    ensure!(script_sig.is_empty(), "reveal scriptSig must be empty");
    ensure!(
        return_script.is_p2wpkh() || return_script.is_p2tr(),
        "invalid reveal return output"
    );
    Ok(())
}
