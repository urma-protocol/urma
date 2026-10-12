use bitcoin::{
    NetworkKind, base58,
    bip32::{DerivationPath, Xpriv, Xpub},
    secp256k1::Secp256k1,
};
use std::str::FromStr;
use urma_chain::observation::Chain;
use urma_identity::{
    bip85, descriptor,
    phrase::IdentityPhrase,
    root::{Branch, Root},
};

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const BIP85_MASTER: &str = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";

#[test]
fn bip39_published_vector_and_phrase_parsing() {
    let mnemonic = bip39::Mnemonic::parse(ABANDON).unwrap();
    let seed = mnemonic.to_seed("TREZOR");
    assert_eq!(
        hex::encode(seed),
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
    );
    assert_eq!(
        Xpriv::new_master(NetworkKind::Main, &seed)
            .unwrap()
            .to_string(),
        "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
    );
    let phrase = IdentityPhrase::parse(ABANDON).unwrap();
    assert_eq!(phrase.export_words().unwrap().as_str(), ABANDON);
    assert_eq!(
        hex::encode(&phrase.seed().unwrap()[..]),
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
    );
    let spaced = format!(" \n{}\t ", ABANDON.replace(' ', " \t  "));
    let reparsed = IdentityPhrase::parse(&spaced).unwrap();
    assert_eq!(reparsed.export_words().unwrap().as_str(), ABANDON);
    assert!(IdentityPhrase::parse(&ABANDON.to_uppercase()).is_err());
    assert!(IdentityPhrase::parse(&" ".repeat(513)).is_err());
}

#[test]
fn bip32_published_vector_one() {
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(
        NetworkKind::Main,
        &hex::decode("000102030405060708090a0b0c0d0e0f").unwrap(),
    )
    .unwrap();
    assert_eq!(
        master.to_string(),
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    );
    assert_eq!(
        Xpub::from_priv(&secp, &master).to_string(),
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
    );
    let child = master
        .derive_priv(&secp, &DerivationPath::from_str("m/0h").unwrap())
        .unwrap();
    assert_eq!(
        child.to_string(),
        "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
    );
    let grandchild = master
        .derive_priv(&secp, &DerivationPath::from_str("m/0h/1").unwrap())
        .unwrap();
    assert_eq!(
        Xpub::from_priv(&secp, &grandchild).to_string(),
        "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
    );
}

#[test]
fn bip84_published_vector() {
    let root = Root::from_phrase(&IdentityPhrase::parse(ABANDON).unwrap()).unwrap();
    let ours = base58::decode_check(
        &root
            .account_xpub(Chain::BitcoinMainnet)
            .unwrap()
            .to_string(),
    )
    .unwrap();
    let published = base58::decode_check("zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs").unwrap();
    assert_eq!(ours[..4], [0x04, 0x88, 0xb2, 0x1e]);
    assert_eq!(ours[4..], published[4..]);
    let address = |branch, index| root.address(Chain::BitcoinMainnet, branch, index).unwrap();
    assert_eq!(
        address(Branch::External, 0),
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
    );
    assert_eq!(
        address(Branch::External, 1),
        "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"
    );
    assert_eq!(
        address(Branch::Internal, 0),
        "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"
    );
    let account = root.account(Chain::BitcoinMainnet).unwrap();
    assert_eq!(
        account.to_string(),
        bip32_with_version(
            "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE",
            [0x04, 0x88, 0xad, 0xe4]
        )
    );
}

#[test]
fn bip85_published_vectors() {
    let secp = Secp256k1::new();
    let master = Xpriv::from_str(BIP85_MASTER).unwrap();
    let cases = [
        (
            0,
            "cca20ccb0e9a90feb0912870c3323b24874b0ca3d8018c4b96d0b97c0e82ded0",
            "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7",
        ),
        (
            1,
            "503776919131758bb7de7beb6c0ae24894f4ec042c26032890c29359216e21ba",
            "70c6e3e8ebee8dc4c0dbba66076819bb8c09672527c4277ca8729532ad711872218f826919f6b67218adde99018a6df9095ab2b58d803b5b93ec9802085a690e",
        ),
    ];
    for (index, key, entropy) in cases {
        let path = DerivationPath::from_str(&format!("m/83696968h/0h/{index}h")).unwrap();
        let child = master.derive_priv(&secp, &path).unwrap();
        assert_eq!(hex::encode(child.private_key.secret_bytes()), key);
        let derived = bip85::entropy(&master, &[83696968, 0, index]).unwrap();
        assert_eq!(hex::encode(&derived[..]), entropy);
    }
    assert_eq!(
        hex::encode(bip85::hex(&master, 64, 0).unwrap().as_slice()),
        "492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c"
    );
    assert_eq!(bip85::hex(&master, 16, 0).unwrap().len(), 16);
    assert!(bip85::hex(&master, 15, 0).is_err());
    assert!(bip85::hex(&master, 65, 0).is_err());
    assert!(bip85::entropy(&master, &[1 << 31]).is_err());
}

#[test]
fn bip380_published_checksum() {
    assert_eq!(
        descriptor::with_checksum("raw(deadbeef)").unwrap(),
        "raw(deadbeef)#89f8spxm"
    );
    assert!(descriptor::with_checksum("raw(Ü)").is_err());
}

fn bip32_with_version(text: &str, version: [u8; 4]) -> String {
    let mut data = base58::decode_check(text).unwrap();
    data[..4].copy_from_slice(&version);
    base58::encode_check(&data)
}
