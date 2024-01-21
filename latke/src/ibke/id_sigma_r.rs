//! Implements the SIGMA-R protocol described in the [SIGMA paper](https://iacr.org/archive/crypto2003/27290399/27290399.pdf), modified  by [Peikert](https://eprint.iacr.org/2014/070) to use KEMs, and transformed using the AKE-to-IBKE transform describe in LATKE.

use crate::{
    auth_enc::{auth_decrypt, auth_encrypt, AuthEncKey, ZERO_AUTH_ENC_KEY},
    AsBytes, Id, IdentityBasedKeyExchange, MyKdf, MyMac, Nonce, PartyRole, SessKey, Ssid,
};

use ed25519_dalek::{
    ed25519::Error as EdError, Signature as EdSignature, Signer, SigningKey as EdSecretKey,
    Verifier, VerifyingKey as EdVerifyingKey,
};
use hkdf::hmac::digest::{Mac, MacError};
use pqcrypto_dilithium::dilithium2::{
    detached_sign as dilithium_detached_sign, keypair_det as dilithium_gen_sig_keypair_det,
    public_key_bytes as dilithium_sig_pubkey_size, signature_bytes as dilithium_sig_size,
    verify_detached_signature as dilithium_verify_detached_signature,
    DetachedSignature as DilithiumSignature, KeygenCoins as DilithiumKeygenCoins,
    PublicKey as DilithiumPubkey, SecretKey as DilithiumPrivkey,
};
use pqcrypto_traits::sign::{
    DetachedSignature as DilithiumSignatureTrait, PublicKey, VerificationError as DilithiumError,
};
use rand_core::{CryptoRng, RngCore};
use saber::{
    lightsaber::{
        decapsulate_ind_cpa as kem_decap, encapsulate_ind_cpa as kem_encap,
        keygen_ind_cpa as kem_keygen, Ciphertext as EncappedKey, INDCPAPublicKey as KemPubkey,
        INDCPASecretKey as KemPrivkey, BYTES_CCA_DEC, INDCPA_PUBLICKEYBYTES as KEM_PUBKEY_SIZE,
    },
    Error as SaberError,
};

#[derive(Copy, Clone)]
enum IdSigmaSignatureScheme {
    Dilithium2,
    Ed25519,
}

#[derive(Clone)]
pub enum IdSigmaPrivkey {
    Dilithium2(DilithiumPrivkey),
    Ed25519(EdSecretKey),
}

impl IdSigmaPrivkey {
    fn sign(&self, bytes: &[u8]) -> IdSigmaSignature {
        match self {
            Self::Dilithium2(sk) => {
                let sig = dilithium_detached_sign(bytes, sk);
                IdSigmaSignature::Dilithium2(sig)
            }
            Self::Ed25519(sk) => {
                let sig = sk.sign(bytes);
                IdSigmaSignature::Ed25519(sig)
            }
        }
    }
}

#[derive(Clone)]
pub enum IdSigmaPubkey {
    Dilithium2(DilithiumPubkey),
    Ed25519(EdVerifyingKey),
}

impl IdSigmaPubkey {
    fn kind(&self) -> IdSigmaSignatureScheme {
        match self {
            Self::Dilithium2(_) => IdSigmaSignatureScheme::Dilithium2,
            Self::Ed25519(_) => IdSigmaSignatureScheme::Ed25519,
        }
    }
}

impl AsBytes for IdSigmaPubkey {
    fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Dilithium2(pk) => {
                <DilithiumPubkey as pqcrypto_traits::sign::PublicKey>::as_bytes(&pk)
            }
            Self::Ed25519(pk) => pk.as_bytes(),
        }
    }
}

impl IdSigmaPubkey {
    fn verify(&self, bytes: &[u8], sig: &IdSigmaSignature) -> Result<(), IdSigmaSigError> {
        match self {
            Self::Dilithium2(pk) => {
                if let IdSigmaSignature::Dilithium2(sig) = sig {
                    dilithium_verify_detached_signature(sig, bytes, pk).map_err(Into::into)
                } else {
                    panic!("Signature scheme mismatch")
                }
            }
            Self::Ed25519(pk) => {
                if let IdSigmaSignature::Ed25519(sig) = sig {
                    pk.verify(bytes, sig).map_err(Into::into)
                } else {
                    panic!("Signature scheme mismatch")
                }
            }
        }
    }
}

#[derive(Clone)]
enum IdSigmaSignature {
    Dilithium2(DilithiumSignature),
    Ed25519(EdSignature),
}

impl IdSigmaSignature {
    fn size(ty: IdSigmaSignatureScheme) -> usize {
        match ty {
            IdSigmaSignatureScheme::Dilithium2 => dilithium_sig_size(),
            IdSigmaSignatureScheme::Ed25519 => ed25519_dalek::SIGNATURE_LENGTH,
        }
    }

    fn from_bytes(ty: IdSigmaSignatureScheme, bytes: &[u8]) -> Self {
        match ty {
            IdSigmaSignatureScheme::Dilithium2 => {
                IdSigmaSignature::Dilithium2(DilithiumSignature::from_bytes(bytes).unwrap())
            }
            IdSigmaSignatureScheme::Ed25519 => {
                IdSigmaSignature::Ed25519(EdSignature::from_bytes(bytes.try_into().unwrap()))
            }
        }
    }
}

impl IdSigmaSignature {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Dilithium2(sig) => sig.as_bytes().to_vec(),
            Self::Ed25519(sig) => sig.to_bytes().to_vec(),
        }
    }
}

#[derive(Debug)]
pub enum IdSigmaSigError {
    Dilithium2(DilithiumError),
    Ed25519(EdError),
}

impl From<DilithiumError> for IdSigmaSigError {
    fn from(err: DilithiumError) -> Self {
        Self::Dilithium2(err)
    }
}

impl From<EdError> for IdSigmaSigError {
    fn from(err: EdError) -> Self {
        Self::Ed25519(err)
    }
}

#[derive(Debug)]
pub enum SigmaError {
    Kem(SaberError),
    InvalidLength(pqcrypto_traits::Error),
    Sig(IdSigmaSigError),
    Mac(MacError),
}

impl From<SaberError> for SigmaError {
    fn from(err: SaberError) -> Self {
        Self::Kem(err)
    }
}

impl From<MacError> for SigmaError {
    fn from(err: MacError) -> Self {
        Self::Mac(err)
    }
}

impl From<pqcrypto_traits::Error> for SigmaError {
    fn from(err: pqcrypto_traits::Error) -> Self {
        Self::InvalidLength(err)
    }
}

impl From<IdSigmaSigError> for SigmaError {
    fn from(err: IdSigmaSigError) -> Self {
        Self::Sig(err)
    }
}

/// A certificate is a signed statement that a party with a given ID has a certain public key.
/// For our PQ Sigma protocol, the signature is a Dilithium signature, and the public key is a Dilithium public key.
#[derive(Clone)]
pub struct SigmaCert {
    id: Id,
    upk: IdSigmaPubkey,
    sig: IdSigmaSignature,
}

impl SigmaCert {
    fn size(ty: IdSigmaSignatureScheme) -> usize {
        match ty {
            IdSigmaSignatureScheme::Dilithium2 => {
                Id::default().len() + dilithium_sig_pubkey_size() + dilithium_sig_size()
            }
            IdSigmaSignatureScheme::Ed25519 => Id::default().len() + 32 + EdSignature::BYTE_SIZE,
        }
    }

    /// Serialize as upk || sig
    fn to_bytes(&self) -> Vec<u8> {
        [&self.id, self.upk.as_bytes(), &self.sig.to_bytes()].concat()
    }

    /// Deserialize from id || upk || sig
    fn from_bytes(ty: IdSigmaSignatureScheme, bytes: &[u8]) -> Result<Self, SigmaError> {
        if bytes.len() != Self::size(ty) {
            return Err(SigmaError::InvalidLength(
                pqcrypto_traits::Error::BadLength {
                    name: "cert",
                    actual: bytes.len(),
                    expected: Self::size(ty),
                },
            ));
        }

        let rest = bytes;
        let (id, rest) = rest.split_at(Id::default().len());
        let (upk_bytes, sig_bytes) = rest.split_at(match ty {
            IdSigmaSignatureScheme::Dilithium2 => dilithium_sig_pubkey_size(),
            IdSigmaSignatureScheme::Ed25519 => 32,
        });

        let (upk, sig) = match ty {
            IdSigmaSignatureScheme::Dilithium2 => (
                IdSigmaPubkey::Dilithium2(DilithiumPubkey::from_bytes(upk_bytes)?),
                IdSigmaSignature::Dilithium2(DilithiumSignature::from_bytes(sig_bytes)?),
            ),
            IdSigmaSignatureScheme::Ed25519 => (
                IdSigmaPubkey::Ed25519(
                    EdVerifyingKey::from_bytes(upk_bytes.try_into().unwrap()).unwrap(),
                ),
                IdSigmaSignature::Ed25519(EdSignature::from_bytes(sig_bytes.try_into().unwrap())),
            ),
        };

        Ok(Self {
            id: id.try_into().unwrap(),
            upk,
            sig,
        })
    }
}

/// The SIGMA-R protocol described in the [SIGMA paper](https://iacr.org/archive/crypto2003/27290399/27290399.pdf), modified  by [Peikert](https://eprint.iacr.org/2014/070) to use KEMs, and transformed using the AKE-to-IBKE transform describe in LATKE.
/// The KEM used is LightSaber, and the signature scheme for SIGMA-R and the AKE-to-IBKE transform is Dilithium2.
struct IdSigmaR {
    /// The SSID for the session. For consistency in benches we assume this is negotiated beforehand. But SIGMA does define a way to negotiate this.
    ssid: Ssid,
    /// The nonces for the two parties
    nonces: (Option<Nonce>, Option<Nonce>),
    /// The main public key of this identity-based system. This is used to verify certificates.
    mpk: IdSigmaPubkey,
    /// The certificate Extracted for this party by the key generation center
    cert: SigmaCert,
    /// The corresponding secret key for the public key in `cert`
    sig_privkey: IdSigmaPrivkey,

    // Ephemeral values
    kem_pubkey: Option<KemPubkey>,
    kem_privkey: Option<KemPrivkey>,
    encapped_key: Option<EncappedKey>,
    mac_key: Option<[u8; 32]>,
    enc_keys: Option<(AuthEncKey, AuthEncKey)>,

    // The output of a post-specified peer IBKE is (ID, session_key)
    output_id: Option<Id>,
    output_key: Option<SessKey>,

    next_step: usize,
    done: bool,
}

impl IdSigmaR {
    fn gen_main_keypair<R: RngCore + CryptoRng>(
        sig_ty: IdSigmaSignatureScheme,
        mut rng: R,
    ) -> (IdSigmaPubkey, IdSigmaPrivkey) {
        match sig_ty {
            IdSigmaSignatureScheme::Dilithium2 => {
                // Generate random coins and use them for generation. We have to do this because gen_sig_keypair uses its own RNG
                let mut coins = DilithiumKeygenCoins::default();
                rng.fill_bytes(&mut coins);
                let (pk, sk) = dilithium_gen_sig_keypair_det(coins);
                (
                    IdSigmaPubkey::Dilithium2(pk),
                    IdSigmaPrivkey::Dilithium2(sk),
                )
            }
            IdSigmaSignatureScheme::Ed25519 => {
                let sk = EdSecretKey::generate(&mut rng);
                let pk = sk.verifying_key();
                (IdSigmaPubkey::Ed25519(pk), IdSigmaPrivkey::Ed25519(sk))
            }
        }
    }

    fn gen_user_keypair<R: RngCore + CryptoRng>(
        sig_ty: IdSigmaSignatureScheme,
        rng: R,
    ) -> (IdSigmaPubkey, IdSigmaPrivkey) {
        // Same thing as above
        Self::gen_main_keypair(sig_ty, rng)
    }

    fn extract<R: RngCore + CryptoRng>(
        _: R,
        msk: &IdSigmaPrivkey,
        id: &Id,
        upk: &IdSigmaPubkey,
    ) -> SigmaCert {
        let sig = msk.sign(&[id, upk.as_bytes()].concat());
        SigmaCert {
            id: id.clone(),
            upk: upk.clone(),
            sig,
        }
    }

    /// Creates a new IBKE executor from a main public key, a certificate, a user signing key for the `upk` in that certificate, and a protocol role
    fn new_session<R: RngCore + CryptoRng>(
        mut rng: R,
        ssid: Ssid,
        mpk: IdSigmaPubkey,
        cert: SigmaCert,
        usk: IdSigmaPrivkey,
        role: PartyRole,
    ) -> Self {
        let mut my_nonce = Nonce::default();
        rng.fill_bytes(&mut my_nonce);

        let nonces = if role == PartyRole::Initiator {
            (Some(my_nonce), None)
        } else {
            (None, Some(my_nonce))
        };

        // The initiator does even steps, the responder does odd steps
        let next_step = if role == PartyRole::Initiator { 0 } else { 1 };

        Self {
            ssid,
            nonces,
            mpk,
            cert,
            sig_privkey: usk,
            kem_pubkey: None,
            kem_privkey: None,
            encapped_key: None,
            mac_key: None,
            enc_keys: None,

            output_id: None,
            output_key: None,

            next_step,
            done: false,
        }
    }

    fn is_done(&self) -> bool {
        self.done
    }

    fn finalize(&self) -> (Id, SessKey) {
        (self.output_id.unwrap(), self.output_key.unwrap())
    }

    fn run_sim(&mut self) -> Option<usize> {
        let sig_ty = self.mpk.kind();

        let out = match self.next_step {
            0 => {
                // Sends a nonce followed by a KEM pubkey
                Some(Nonce::default().len() + KEM_PUBKEY_SIZE)
            }
            1 => {
                // Sends a nonce followed by an encapsulated key
                Some(Nonce::default().len() + BYTES_CCA_DEC)
            }
            2 => {
                // Sends an authenticated ciphertext of (sig, mac, cert). So include that length, plus the length of the authenticated encryption tag
                Some(
                    IdSigmaSignature::size(sig_ty)
                        + 32
                        + SigmaCert::size(sig_ty)
                        + crate::auth_enc::TAGLEN,
                )
            }
            3 => {
                // Same as above
                self.done = true;
                Some(
                    IdSigmaSignature::size(sig_ty)
                        + 32
                        + SigmaCert::size(sig_ty)
                        + crate::auth_enc::TAGLEN,
                )
            }
            4 => {
                // All done
                self.done = true;
                None
            }
            _ => panic!("protocol already finished"),
        };

        self.next_step += 2;

        out
    }

    fn run<R: RngCore + CryptoRng>(
        &mut self,
        mut rng: R,
        incoming_msg: &[u8],
    ) -> Result<Option<Vec<u8>>, SigmaError> {
        let sig_ty = self.mpk.kind();

        let out = match self.next_step {
            // Generate an ephemeral keypair and send the pubkey
            0 => {
                assert_eq!(incoming_msg.len(), 0);

                // Generate an ephemeral KEM keypair
                let (kem_pubkey, kem_privkey) = kem_keygen();
                self.kem_pubkey = Some(kem_pubkey);
                self.kem_privkey = Some(kem_privkey);

                // Send (nonce_a, pubkey)
                Some(
                    [
                        self.nonces.0.as_ref().unwrap().as_slice(),
                        self.kem_pubkey.as_ref().unwrap().to_bytes().as_bytes(),
                    ]
                    .concat(),
                )
            }
            1 => {
                // Deserialize everything
                let (nonce, kem_pubkey_bytes) = incoming_msg.split_at(Nonce::default().len());
                self.nonces.0 = Some(nonce.try_into().unwrap());
                self.kem_pubkey = Some(KemPubkey::from_bytes(kem_pubkey_bytes));

                // Encapsulate to the pubkey
                let (shared_secret, encapped_key) = kem_encap(&self.kem_pubkey.as_ref().unwrap());
                self.encapped_key = Some(encapped_key);

                // Generate the session key and the MAC key from the shared secret
                let mut output_key = SessKey::default();
                let mut mac_key = [0u8; 32];
                let mut enc_key_a = ZERO_AUTH_ENC_KEY;
                let mut enc_key_b = ZERO_AUTH_ENC_KEY;
                let hk = MyKdf::from_prk(shared_secret.as_slice()).unwrap();
                hk.expand(b"output_key", &mut output_key).unwrap();
                hk.expand(b"mac_key", &mut mac_key).unwrap();
                hk.expand(b"enc_key_a", &mut enc_key_a).unwrap();
                hk.expand(b"enc_key_b", &mut enc_key_b).unwrap();
                self.output_key = Some(output_key);
                self.mac_key = Some(mac_key);
                self.enc_keys = Some((enc_key_a, enc_key_b));

                // Output (nonce_b, encapped_key)
                Some(
                    [
                        self.nonces.1.as_ref().unwrap().as_slice(),
                        self.encapped_key.as_ref().unwrap().as_bytes().as_slice(),
                    ]
                    .concat(),
                )
            }
            2 => {
                // Deserialize everything
                let (nonce_b, encapped_key_bytes) = incoming_msg.split_at(Nonce::default().len());
                assert_eq!(encapped_key_bytes.len(), BYTES_CCA_DEC);

                // Save all the values and check that the ssid_a matches what we gave the peer
                self.encapped_key = Some(EncappedKey::from_bytes(encapped_key_bytes)?);
                self.nonces.1 = Some(nonce_b.try_into().unwrap());

                // Compute the shared secret and derive all the keys
                let shared_secret = kem_decap(
                    self.encapped_key.as_ref().unwrap(),
                    self.kem_privkey.as_ref().unwrap(),
                );
                let mut output_key = SessKey::default();
                let mut mac_key = [0u8; 32];
                let mut enc_key_a = ZERO_AUTH_ENC_KEY;
                let mut enc_key_b = ZERO_AUTH_ENC_KEY;
                let hk = MyKdf::from_prk(shared_secret.as_slice()).unwrap();
                hk.expand(b"output_key", &mut output_key).unwrap();
                hk.expand(b"mac_key", &mut mac_key).unwrap();
                hk.expand(b"enc_key_a", &mut enc_key_a).unwrap();
                hk.expand(b"enc_key_b", &mut enc_key_b).unwrap();
                self.output_key = Some(output_key);
                self.mac_key = Some(mac_key);
                self.enc_keys = Some((enc_key_a, enc_key_b));

                let cert_bytes = self.cert.to_bytes();

                // Time for some key confirmation. Send the cert, a signature over the transcript, and a MAC over the ID
                // Now compute the signature over what's happened so far
                let sig = self.sig_privkey.sign(
                    &[
                        &[0x00],
                        self.nonces.1.as_ref().unwrap().as_slice(),
                        &self.ssid,
                        self.kem_pubkey.as_ref().unwrap().to_bytes().as_bytes(),
                        self.encapped_key.as_ref().unwrap().as_bytes(),
                        &cert_bytes,
                    ]
                    .concat(),
                );

                // Compute the MAC over the (ssid, ID)
                let mac = MyMac::new_from_slice(self.mac_key.as_ref().unwrap())
                    .unwrap()
                    .chain_update(&[0x00])
                    .chain_update(self.cert.id)
                    .finalize()
                    .into_bytes();

                // Encrypt (sig, mac, cert)
                let msg_to_encrypt = [&sig.to_bytes(), mac.as_slice(), &cert_bytes].concat();
                let ciphertext = auth_encrypt(&mut rng, enc_key_a, &msg_to_encrypt);

                // Send the ciphertext
                Some(ciphertext)
            }
            3 => {
                // Deserialize and decrypt everything
                let ciphertext = incoming_msg;
                let sig_mac_cert = auth_decrypt(self.enc_keys.as_ref().unwrap().0, ciphertext)?;
                let (sig_mac, incoming_cert_bytes) =
                    sig_mac_cert.split_at(sig_mac_cert.len() - SigmaCert::size(sig_ty));
                let (sig, incoming_mac) = sig_mac.split_at(IdSigmaSignature::size(sig_ty));

                let incoming_sig = IdSigmaSignature::from_bytes(sig_ty, sig);
                let incoming_cert = SigmaCert::from_bytes(sig_ty, incoming_cert_bytes)?;
                self.output_id = Some(incoming_cert.id);

                // Do the verifications. Check that the certificate verifies and that the signature and MAC verify
                // Check the certificate verifies
                self.mpk.verify(
                    &[&incoming_cert.id, incoming_cert.upk.as_bytes()].concat(),
                    &incoming_cert.sig,
                )?;
                // Check the other signature verifies
                incoming_cert.upk.verify(
                    &[
                        &[0x00],
                        self.nonces.1.as_ref().unwrap().as_slice(),
                        &self.ssid,
                        self.kem_pubkey.as_ref().unwrap().to_bytes().as_bytes(),
                        self.encapped_key.as_ref().unwrap().as_bytes(),
                        &incoming_cert_bytes,
                    ]
                    .concat(),
                    &incoming_sig,
                )?;
                MyMac::new_from_slice(self.mac_key.as_ref().unwrap())
                    .unwrap()
                    .chain_update(&[0x00])
                    .chain_update(self.output_id.as_ref().unwrap())
                    .verify_slice(incoming_mac)?;

                // Now compute the final message. Compute the signature and MAC, similar to above
                let my_cert_bytes = self.cert.to_bytes();
                let sig = self.sig_privkey.sign(
                    &[
                        &[0x01],
                        self.nonces.0.as_ref().unwrap().as_slice(),
                        &self.ssid,
                        self.encapped_key.as_ref().unwrap().as_bytes(),
                        self.kem_pubkey.as_ref().unwrap().to_bytes().as_bytes(),
                        &my_cert_bytes,
                    ]
                    .concat(),
                );

                // Compute the MAC over the (ssid, ID)
                let mac = MyMac::new_from_slice(self.mac_key.as_ref().unwrap())
                    .unwrap()
                    .chain_update(&[0x01])
                    .chain_update(self.cert.id)
                    .finalize()
                    .into_bytes();

                // Encrypt (sig, mac, cert)
                let ciphertext = auth_encrypt(
                    &mut rng,
                    self.enc_keys.as_ref().unwrap().1,
                    &[&sig.to_bytes(), mac.as_slice(), &my_cert_bytes].concat(),
                );

                // This is the last message for this party
                self.done = true;

                // Send the ciphertext
                Some(ciphertext)
            }
            4 => {
                // Deserialize and decrypt everything
                let ciphertext = incoming_msg;
                let sig_mac_cert = auth_decrypt(self.enc_keys.as_ref().unwrap().1, ciphertext)?;
                let (sig_mac, incoming_cert_bytes) =
                    sig_mac_cert.split_at(sig_mac_cert.len() - SigmaCert::size(sig_ty));
                let (sig, incoming_mac) = sig_mac.split_at(IdSigmaSignature::size(sig_ty));

                let incoming_sig = IdSigmaSignature::from_bytes(sig_ty, sig);
                let incoming_cert = SigmaCert::from_bytes(sig_ty, incoming_cert_bytes)?;
                self.output_id = Some(incoming_cert.id);

                // Do the verifications. Check that that the certificate verifies and that the signature and MAC verify
                // Check the certificate verifies
                self.mpk.verify(
                    &[&incoming_cert.id, incoming_cert.upk.as_bytes()].concat(),
                    &incoming_cert.sig,
                )?;
                // Check the other signature verifies
                incoming_cert.upk.verify(
                    &[
                        &[0x01],
                        self.nonces.0.as_ref().unwrap().as_slice(),
                        &self.ssid,
                        self.encapped_key.as_ref().unwrap().as_bytes(),
                        self.kem_pubkey.as_ref().unwrap().to_bytes().as_bytes(),
                        &incoming_cert_bytes,
                    ]
                    .concat(),
                    &incoming_sig,
                )?;
                // Compute the MAC over the (ssid, ID)
                MyMac::new_from_slice(self.mac_key.as_ref().unwrap())
                    .unwrap()
                    .chain_update(&[0x01])
                    .chain_update(self.output_id.as_ref().unwrap())
                    .verify_slice(incoming_mac)?;

                self.done = true;
                None
            }
            _ => {
                panic!("protocol already finished")
            }
        };

        // The initiator has the even steps, the responder has the odd steps
        self.next_step += 2;

        Ok(out)
    }
}

// Now make some newtypes that implement the IdentityBasedKeyExchange trait

pub struct IdSigmaREd25519(IdSigmaR);
pub struct IdSigmaRDilithium2(IdSigmaR);

impl IdentityBasedKeyExchange for IdSigmaREd25519 {
    type MainPubkey = IdSigmaPubkey;
    type MainPrivkey = IdSigmaPrivkey;
    type UserPubkey = IdSigmaPubkey;
    type UserPrivkey = IdSigmaPrivkey;
    type Certificate = SigmaCert;
    type Error = SigmaError;

    fn gen_main_keypair<R: RngCore + CryptoRng>(rng: R) -> (Self::MainPubkey, Self::MainPrivkey) {
        IdSigmaR::gen_main_keypair(IdSigmaSignatureScheme::Ed25519, rng)
    }

    fn gen_user_keypair<R: RngCore + CryptoRng>(rng: R) -> (Self::UserPubkey, Self::UserPrivkey) {
        IdSigmaR::gen_user_keypair(IdSigmaSignatureScheme::Ed25519, rng)
    }

    fn extract<R: RngCore + CryptoRng>(
        rng: R,
        msk: &Self::MainPrivkey,
        id: &Id,
        upk: &Self::UserPubkey,
    ) -> Self::Certificate {
        IdSigmaR::extract(rng, msk, id, upk)
    }

    fn new_session<R: RngCore + CryptoRng>(
        rng: R,
        ssid: Ssid,
        mpk: Self::MainPubkey,
        cert: Self::Certificate,
        usk: Self::UserPrivkey,
        role: PartyRole,
    ) -> Self {
        IdSigmaREd25519(IdSigmaR::new_session(rng, ssid, mpk, cert, usk, role))
    }

    fn run<R: RngCore + CryptoRng>(
        &mut self,
        rng: R,
        incoming_msg: &[u8],
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0.run(rng, incoming_msg)
    }

    fn run_sim(&mut self) -> Option<usize> {
        self.0.run_sim()
    }

    fn is_done(&self) -> bool {
        self.0.is_done()
    }

    fn finalize(&self) -> (Id, SessKey) {
        self.0.finalize()
    }
}

impl IdentityBasedKeyExchange for IdSigmaRDilithium2 {
    type MainPubkey = IdSigmaPubkey;
    type MainPrivkey = IdSigmaPrivkey;
    type UserPubkey = IdSigmaPubkey;
    type UserPrivkey = IdSigmaPrivkey;
    type Certificate = SigmaCert;
    type Error = SigmaError;

    fn gen_main_keypair<R: RngCore + CryptoRng>(rng: R) -> (Self::MainPubkey, Self::MainPrivkey) {
        IdSigmaR::gen_main_keypair(IdSigmaSignatureScheme::Dilithium2, rng)
    }

    fn gen_user_keypair<R: RngCore + CryptoRng>(rng: R) -> (Self::UserPubkey, Self::UserPrivkey) {
        IdSigmaR::gen_user_keypair(IdSigmaSignatureScheme::Dilithium2, rng)
    }

    fn extract<R: RngCore + CryptoRng>(
        rng: R,
        msk: &Self::MainPrivkey,
        id: &Id,
        upk: &Self::UserPubkey,
    ) -> Self::Certificate {
        IdSigmaR::extract(rng, msk, id, upk)
    }

    fn new_session<R: RngCore + CryptoRng>(
        rng: R,
        ssid: Ssid,
        mpk: Self::MainPubkey,
        cert: Self::Certificate,
        usk: Self::UserPrivkey,
        role: PartyRole,
    ) -> Self {
        IdSigmaRDilithium2(IdSigmaR::new_session(rng, ssid, mpk, cert, usk, role))
    }

    fn run<R: RngCore + CryptoRng>(
        &mut self,
        rng: R,
        incoming_msg: &[u8],
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0.run(rng, incoming_msg)
    }

    fn run_sim(&mut self) -> Option<usize> {
        self.0.run_sim()
    }

    fn is_done(&self) -> bool {
        self.0.is_done()
    }

    fn finalize(&self) -> (Id, SessKey) {
        self.0.finalize()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::Rng;

    fn sigma_r_correctness_generic<I: IdentityBasedKeyExchange>() {
        let mut rng = rand::thread_rng();

        // Generate the KGC keypair
        let (mpk, msk) = I::gen_main_keypair(&mut rng);

        // Pick the user IDs randomly
        let id1 = rng.gen();
        let id2 = rng.gen();

        // Have the users generate their keypairs
        let (upk1, usk1) = I::gen_user_keypair(&mut rng);
        let (upk2, usk2) = I::gen_user_keypair(&mut rng);

        // Have the KGC sign the user's pubkeys
        let cert1 = I::extract(&mut rng, &msk, &id1, &upk1);
        let cert2 = I::extract(&mut rng, &msk, &id2, &upk2);

        // Start a new session
        let ssid = rng.gen();
        let mut user1 = I::new_session(
            &mut rng,
            ssid,
            mpk.clone(),
            cert1,
            usk1,
            PartyRole::Initiator,
        );
        let mut user2 = I::new_session(
            &mut rng,
            ssid,
            mpk.clone(),
            cert2,
            usk2,
            PartyRole::Responder,
        );

        // Run the session until completion
        let msg1 = user1.run(&mut rng, &[]).unwrap().unwrap();
        let msg2 = user2.run(&mut rng, &msg1).unwrap().unwrap();
        let msg3 = user1.run(&mut rng, &msg2).unwrap().unwrap();
        let msg4 = user2.run(&mut rng, &msg3).unwrap().unwrap();
        let msg5 = user1.run(&mut rng, &msg4).unwrap();

        let (user1_interlocutor, user1_key) = user1.finalize();
        let (user2_interlocutor, user2_key) = user2.finalize();

        // Ensure that there are no more messages to be sent, that the parties believe they're talking to each other, and that they have the same key
        assert!(msg5.is_none());
        assert!(user1_interlocutor == id2);
        assert!(user2_interlocutor == id1);
        assert_eq!(user1_key, user2_key);
    }

    #[test]
    fn sigma_r_correctness() {
        sigma_r_correctness_generic::<IdSigmaREd25519>();
        sigma_r_correctness_generic::<IdSigmaRDilithium2>();
    }
}
