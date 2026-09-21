use crate::error::{Context, Error, ensure};
use crate::reveal;
use crate::transaction::transaction;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Transaction, TxOut,
    secp256k1::{Keypair, Secp256k1},
    taproot::TaprootSpendInfo,
};
use rand::{CryptoRng, RngCore};
use urma_core::envelope;

pub(crate) struct PreparedReveal {
    signer: Keypair,
    script: ScriptBuf,
    info: TaprootSpendInfo,
    pub fee: u64,
    retained: u64,
}
impl PreparedReveal {
    pub fn new<R: RngCore + CryptoRng>(
        record: &[u8],
        payout: &ScriptBuf,
        rate: u64,
        retained: u64,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let signer = Keypair::new(&Secp256k1::new(), rng);
        let (script, info) = envelope::build(record, &signer)?;
        let preview = reveal::preview(
            TxOut {
                value: Amount::from_sat(retained),
                script_pubkey: payout.clone(),
            },
            &script,
            &info,
        )?;
        let fee = reveal::fee(&preview, rate)?;
        Ok(Self {
            signer,
            script,
            info,
            fee,
            retained,
        })
    }
    pub fn output(&self) -> TxOut {
        TxOut {
            value: Amount::from_sat(self.retained + self.fee),
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
            TxOut {
                value: Amount::from_sat(self.retained),
                script_pubkey: payout.clone(),
            },
        );
        let signature = Secp256k1::new()
            .sign_schnorr_no_aux_rand(&reveal::digest(&tx, output, &self.script)?, &self.signer);
        tx.input[0].witness = envelope::witness(signature.as_ref(), &self.script, &self.info)?;
        Ok(tx)
    }
}
