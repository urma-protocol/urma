use crate::archive_cli;
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use std::path::PathBuf;
use urma::error::Error;
use urma_chain::observation::Chain;
use urma_identity::{
    identity::{IdentitySigner, IdentitySlot},
    phrase::IdentityPhrase,
    vault::{UnlockCredential, UnlockedVault},
};
use urma_workflows::vault::{self, VaultChange};

#[derive(Args)]
#[group(required = true, multiple = false)]
pub(crate) struct CredentialFiles {
    #[arg(long)]
    password_file: Option<PathBuf>,
    #[arg(long)]
    phrase_file: Option<PathBuf>,
}
#[derive(Args)]
pub(crate) struct VaultAccess {
    #[arg(long)]
    vault: PathBuf,
    #[command(flatten)]
    credential: CredentialFiles,
}
impl VaultAccess {
    pub(crate) fn open(&self) -> Result<UnlockedVault, Error> {
        match (&self.credential.password_file, &self.credential.phrase_file) {
            (Some(path), None) => {
                let password = vault::read_secret(path)?;
                vault::load(&self.vault, UnlockCredential::Password(&password))
            }
            (None, Some(path)) => {
                let words = vault::read_secret(path)?;
                let phrase = IdentityPhrase::parse(&words)?;
                vault::load(&self.vault, UnlockCredential::RecoveryPhrase(&phrase))
            }
            (Some(_password), Some(_phrase)) => {
                Err(Error::Invalid("supply exactly one credential file".into()))
            }
            (None, None) => Err(Error::Invalid("supply exactly one credential file".into())),
        }
    }
}

#[derive(Subcommand)]
pub(crate) enum KeyCommand {
    RecoveryGenerate(archive_cli::KeygenArgs),
    Create {
        #[arg(long)]
        vault: PathBuf,
        #[arg(long)]
        password_file: PathBuf,
        #[arg(long)]
        recovery_out: PathBuf,
        #[arg(long)]
        name: String,
    },
    Recover {
        #[arg(long)]
        phrase_file: PathBuf,
        #[arg(long)]
        password_file: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    List {
        #[command(flatten)]
        access: VaultAccess,
    },
    Add {
        #[command(flatten)]
        access: VaultAccess,
        #[arg(long)]
        name: String,
        #[arg(long)]
        output: PathBuf,
    },
    Select {
        #[command(flatten)]
        access: VaultAccess,
        #[arg(long)]
        slot: u16,
        #[arg(long)]
        output: PathBuf,
    },
    Rename {
        #[command(flatten)]
        access: VaultAccess,
        #[arg(long)]
        slot: u16,
        #[arg(long)]
        name: String,
        #[arg(long)]
        output: PathBuf,
    },
    ResetPassword {
        #[command(flatten)]
        access: VaultAccess,
        #[arg(long)]
        new_password_file: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

pub(crate) fn public_summary(vault: &UnlockedVault) -> Result<Value, Error> {
    let keyring = vault.keyring();
    let mut identities = Vec::new();
    for entry in keyring.identities() {
        let signer = keyring.identity(entry.slot)?;
        identities.push(json!({"slot": entry.slot.index(), "name": entry.name,
            "active":entry.slot == keyring.active_slot(), "author":signer.author().0.to_string(),
            "funding_public_key": signer.public_key().to_string(),
            "bitcoin_testnet4_address":urma_wallet::address::receive_address(&signer, Chain::BitcoinTestnet4)?,
            "litecoin_testnet_address":urma_wallet::address::receive_address(&signer, Chain::LitecoinTestnet)?}));
    }
    Ok(json!({"identities":identities,"broadcast":false}))
}

fn modify(access: VaultAccess, change: VaultChange<'_>, output: PathBuf) -> Result<Value, Error> {
    let mut opened = access.open()?;
    vault::change(&mut opened, change)?;
    vault::save_new(&output, &opened)?;
    Ok(
        json!({"status":"saved","vault":output,"active_slot":opened.keyring().active_slot().index()}),
    )
}

pub(crate) fn run(command: KeyCommand) -> Result<Value, Error> {
    match command {
        KeyCommand::RecoveryGenerate(args) => {
            archive_cli::keygen(args)?;
            Ok(Value::Null)
        }
        KeyCommand::Create {
            vault: path,
            password_file,
            recovery_out,
            name,
        } => {
            let password = vault::read_secret(&password_file)?;
            vault::create(&path, &password, &name, &recovery_out)?;
            Ok(json!({"status":"created","vault":path,"recovery_written":true,"active_slot":0}))
        }
        KeyCommand::Recover {
            phrase_file,
            password_file,
            output,
        } => {
            let words = vault::read_secret(&phrase_file)?;
            let phrase = IdentityPhrase::parse(&words)?;
            let password = vault::read_secret(&password_file)?;
            vault::recover(&output, &phrase, &password)?;
            Ok(
                json!({"status":"recovered","vault":output,"candidate_slots":64,"metadata_recovered":false,"active_slot":0}),
            )
        }
        KeyCommand::List { access } => public_summary(&access.open()?),
        KeyCommand::Add {
            access,
            name,
            output,
        } => modify(access, VaultChange::Add(&name), output),
        KeyCommand::Select {
            access,
            slot,
            output,
        } => modify(
            access,
            VaultChange::Select(IdentitySlot::new(slot)?),
            output,
        ),
        KeyCommand::Rename {
            access,
            slot,
            name,
            output,
        } => modify(
            access,
            VaultChange::Rename {
                slot: IdentitySlot::new(slot)?,
                name: &name,
            },
            output,
        ),
        KeyCommand::ResetPassword {
            access,
            new_password_file,
            output,
        } => {
            let password = vault::read_secret(&new_password_file)?;
            let opened = access
                .open()?
                .reset_password(&password, &mut rand::rngs::OsRng)?;
            vault::save_new(&output, &opened)?;
            Ok(json!({"status":"saved","vault":output,"identities_changed":false}))
        }
    }
}
