use crate::config::BITCOIN_RETURN_SATS;
use crate::{
    envelope,
    error::{Context, Error, ensure},
};
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute,
    hashes::Hash,
    secp256k1::{Keypair, Message, Secp256k1},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TapLeafHash, TaprootSpendInfo},
    transaction::Version,
};
use rand::{CryptoRng, RngCore};

pub(crate) fn transaction(prevout: OutPoint, payout: &ScriptBuf) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prevout,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(BITCOIN_RETURN_SATS),
            script_pubkey: payout.clone(),
        }],
    }
}

pub(crate) struct PreparedReveal {
    signer: Keypair,
    script: ScriptBuf,
    info: TaprootSpendInfo,
    pub fee: u64,
}
impl PreparedReveal {
    pub fn new<R: RngCore + CryptoRng>(
        record: &[u8],
        payout: &ScriptBuf,
        rate: u64,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let signer = Keypair::new(&Secp256k1::new(), rng);
        let (script, info) = envelope::build(record, &signer)?;
        let mut preview = transaction(OutPoint::null(), payout);
        preview.input[0].witness = envelope::witness(&[0; 64], &script, &info)?;
        ensure!(
            preview.weight().to_wu() <= 400_000,
            "reveal exceeds standard transaction weight"
        );
        let fee = u64::try_from(preview.vsize())?
            .checked_mul(rate)
            .context("reveal fee overflow")?;
        Ok(Self {
            signer,
            script,
            info,
            fee,
        })
    }
    pub fn output(&self) -> TxOut {
        TxOut {
            value: Amount::from_sat(BITCOIN_RETURN_SATS + self.fee),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(self.info.output_key()),
        }
    }
    pub fn sign(
        self,
        commit: &Transaction,
        vout: u32,
        payout: &ScriptBuf,
    ) -> Result<Transaction, Error> {
        let output = commit
            .output
            .get(usize::try_from(vout)?)
            .context("missing commit output")?;
        ensure!(
            *output == self.output(),
            "commit output changed before signing"
        );
        let mut tx = transaction(
            OutPoint {
                txid: commit.compute_txid(),
                vout,
            },
            payout,
        );
        let hash = SighashCache::new(&tx).taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(std::slice::from_ref(output)),
            TapLeafHash::from_script(&self.script, LeafVersion::TapScript),
            TapSighashType::Default,
        )?;
        let signature = Secp256k1::new()
            .sign_schnorr_no_aux_rand(&Message::from_digest(hash.to_byte_array()), &self.signer);
        tx.input[0].witness = envelope::witness(signature.as_ref(), &self.script, &self.info)?;
        Ok(tx)
    }
}
