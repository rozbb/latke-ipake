//! The HMQV-C protocol, due to [Krawczyk](https://eprint.iacr.org/2005/176), with the AKE-to-IBKE transformation applied

use crate::{
    Id, IdCertificate, IdentityBasedKeyExchange, MyHash512, MyKdf, PartyRole, SessKey, Ssid,
};

use blake2::digest::MacError;
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use ed25519_dalek::{
    Signature, Signer, SigningKey as SigPrivkey, Verifier, VerifyingKey as SigPubkey,
};
use hkdf::hmac::digest::Digest;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

type UserPubkey = RistrettoPoint;
type UserPrivkey = Scalar;

type EphemeralPubkey = RistrettoPoint;
type EphemeralPrivkey = Scalar;

#[derive(Clone)]
pub struct IdHmqvCCert {
    id: Id,
    upk: RistrettoPoint,
    upk_sig: Signature,
}

impl IdHmqvCCert {
    fn to_bytes(&self) -> Vec<u8> {
        [
            &self.id[..],
            self.upk.compress().as_bytes(),
            &self.upk_sig.to_bytes(),
        ]
        .concat()
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let rest = bytes;
        let (id, rest) = rest.split_at(Id::default().len());
        let (upk, rest) = rest.split_at(32);
        let sig = rest;

        IdHmqvCCert {
            id: id.try_into().unwrap(),
            upk: CompressedRistretto::from_slice(upk)
                .unwrap()
                .decompress()
                .unwrap(),
            upk_sig: Signature::from_bytes(sig.try_into().unwrap()),
        }
    }

    fn size() -> usize {
        Id::default().len() + 32 + Signature::BYTE_SIZE
    }
}

impl IdCertificate for IdHmqvCCert {
    fn id(&self) -> Id {
        self.id
    }
}

pub struct IdHmqvC {
    ssid: Ssid,
    my_cert: IdHmqvCCert,

    mpk: SigPubkey,
    usk: UserPrivkey,

    eph_sk: Option<EphemeralPrivkey>,
    eph_pk: Option<EphemeralPubkey>,

    macs: Option<([u8; 32], [u8; 32])>,
    output_key: Option<SessKey>,
    output_id: Option<Id>,

    next_step: usize,
    done: bool,
}

#[derive(Debug)]
pub enum IdHmqvCError {
    Mac(MacError),
    Sig(ed25519_dalek::SignatureError),
}

impl From<MacError> for IdHmqvCError {
    fn from(e: MacError) -> Self {
        IdHmqvCError::Mac(e)
    }
}

impl From<ed25519_dalek::SignatureError> for IdHmqvCError {
    fn from(e: ed25519_dalek::SignatureError) -> Self {
        IdHmqvCError::Sig(e)
    }
}

impl IdentityBasedKeyExchange for IdHmqvC {
    type MainPubkey = SigPubkey;
    type MainPrivkey = SigPrivkey;
    type UserPubkey = UserPubkey;
    type UserPrivkey = UserPrivkey;
    type Certificate = IdHmqvCCert;
    type Error = IdHmqvCError;

    fn new_session<R: RngCore + CryptoRng>(
        _rng: R,
        ssid: Ssid,
        mpk: SigPubkey,
        cert: IdHmqvCCert,
        usk: UserPrivkey,
        role: PartyRole,
    ) -> Self {
        let next_step = if role == PartyRole::Initiator { 0 } else { 1 };
        IdHmqvC {
            ssid,
            my_cert: cert,
            mpk,
            usk,
            macs: None,
            eph_sk: None,
            eph_pk: None,
            output_key: None,
            output_id: None,
            next_step,
            done: false,
        }
    }

    fn gen_main_keypair<R: RngCore + CryptoRng>(mut rng: R) -> (SigPubkey, SigPrivkey) {
        let sig_sk = SigPrivkey::generate(&mut rng);
        let sig_pk = SigPubkey::from(&sig_sk);
        (sig_pk, sig_sk)
    }

    fn gen_user_keypair<R: RngCore + CryptoRng>(mut rng: R) -> (UserPubkey, UserPrivkey) {
        let usk = UserPrivkey::random(&mut rng);
        let upk = UserPubkey::mul_base(&usk);
        (upk, usk)
    }

    fn extract<R: RngCore + CryptoRng>(
        _: R,
        msk: &SigPrivkey,
        id: &Id,
        upk: &UserPubkey,
    ) -> IdHmqvCCert {
        let upk_sig = msk.sign(&[&id[..], upk.compress().as_bytes()].concat());
        IdHmqvCCert {
            id: id.clone(),
            upk: upk.clone(),
            upk_sig,
        }
    }

    fn finalize(&self) -> (Id, SessKey) {
        (self.output_id.unwrap(), self.output_key.unwrap())
    }

    fn is_done(&self) -> bool {
        self.done
    }

    fn run_sim(&mut self) -> Option<usize> {
        let out = match self.next_step {
            0 => {
                // Sends an ephemeral pubkey and a certificate
                Some(32 + IdHmqvCCert::size())
            }
            1 => {
                // Sends an ephemeral pubkey, a MAC, and a certificate
                Some(32 + 32 + IdHmqvCCert::size())
            }
            2 => {
                // Sends a MAC
                Some(32)
            }
            3 => None,
            _ => {
                panic!("protocol already finished")
            }
        };

        // Increment the step counter. The initiator gets the even steps, the responder the odd steps.
        self.next_step += 2;

        out
    }

    fn run<R: RngCore + CryptoRng>(
        &mut self,
        mut rng: R,
        incoming_msg: &[u8],
    ) -> Result<Option<Vec<u8>>, IdHmqvCError> {
        let out = match self.next_step {
            0 => {
                assert!(incoming_msg.is_empty());

                // Generate an ephemeral keypair (user keypair is the same as ephemeral)
                let (eph_pk, eph_sk) = Self::gen_user_keypair(&mut rng);
                self.eph_pk = Some(eph_pk.clone());
                self.eph_sk = Some(eph_sk);

                // Send the ephemeral public key and certificate
                Some(
                    [
                        eph_pk.compress().as_bytes(),
                        self.my_cert.to_bytes().as_slice(),
                    ]
                    .concat(),
                )
            }
            1 => {
                // Receive the ephemeral pubkey and the cert
                let rest = incoming_msg;
                let (incoming_eph_pk_bytes, rest) = rest.split_at(32);
                let incoming_cert_bytes = rest;

                let incoming_eph_pk = CompressedRistretto::from_slice(incoming_eph_pk_bytes)
                    .unwrap()
                    .decompress()
                    .unwrap();
                let incoming_cert = IdHmqvCCert::from_bytes(incoming_cert_bytes);

                // Verify the certificate
                self.mpk.verify(
                    &[
                        &incoming_cert.id[..],
                        incoming_cert.upk.compress().as_bytes(),
                    ]
                    .concat(),
                    &incoming_cert.upk_sig,
                )?;
                // If that all works out, then we can use the other user's pubkey and ID
                let other_upk = incoming_cert.upk;
                self.output_id = Some(incoming_cert.id);

                // Make a new ephemeral keypair
                let (eph_pk, eph_sk) = Self::gen_user_keypair(&mut rng);

                // Do the HMQV algebra
                let d = {
                    let hash = MyHash512::new()
                        .chain_update(incoming_eph_pk_bytes)
                        .chain_update(self.my_cert.id);
                    Scalar::from_hash(hash)
                };
                let e = {
                    let hash = MyHash512::new()
                        .chain_update(eph_pk.compress().as_bytes())
                        .chain_update(incoming_cert.id);
                    Scalar::from_hash(hash)
                };
                let sigma = (incoming_eph_pk + d * other_upk) * (eph_sk + e * self.usk);

                // Extract sigma to a session key and 2 MACs
                let hk = MyKdf::from_prk(sigma.compress().as_bytes()).unwrap();
                let mut output_key = SessKey::default();
                let mut mac0 = [0u8; 32];
                let mut mac1 = [0u8; 32];
                hk.expand_multi_info(&[&self.ssid, b"mac0"], &mut mac0)
                    .unwrap();
                hk.expand_multi_info(&[&self.ssid, b"mac1"], &mut mac1)
                    .unwrap();
                hk.expand_multi_info(&[&self.ssid, b"sess key"], &mut output_key)
                    .unwrap();
                self.macs = Some((mac0, mac1));
                self.output_key = Some(output_key);

                // Send the ephemeral public key, mac0, and certificate
                Some(
                    [
                        eph_pk.compress().as_bytes(),
                        &mac1,
                        self.my_cert.to_bytes().as_slice(),
                    ]
                    .concat(),
                )
            }

            2 => {
                // Receive the ephemeral pubkey and the cert
                let rest = incoming_msg;
                let (incoming_eph_pk_bytes, rest) = rest.split_at(32);
                let (incoming_mac1, rest) = rest.split_at(32);
                let incoming_cert_bytes = rest;

                let incoming_eph_pk = CompressedRistretto::from_slice(incoming_eph_pk_bytes)
                    .unwrap()
                    .decompress()
                    .unwrap();
                let incoming_cert = IdHmqvCCert::from_bytes(incoming_cert_bytes);

                // Verify the certificate
                self.mpk.verify(
                    &[
                        &incoming_cert.id[..],
                        incoming_cert.upk.compress().as_bytes(),
                    ]
                    .concat(),
                    &incoming_cert.upk_sig,
                )?;
                // If that all works out, then we can use the other user's pubkey and ID
                let other_upk = incoming_cert.upk;
                self.output_id = Some(incoming_cert.id);

                // Do the HMQV algebra
                let d = {
                    let hash = MyHash512::new()
                        .chain_update(self.eph_pk.as_ref().unwrap().compress().as_bytes())
                        .chain_update(incoming_cert.id);
                    Scalar::from_hash(hash)
                };
                let e = {
                    let hash = MyHash512::new()
                        .chain_update(incoming_eph_pk_bytes)
                        .chain_update(self.my_cert.id);
                    Scalar::from_hash(hash)
                };
                let sigma =
                    (incoming_eph_pk + e * other_upk) * (self.eph_sk.unwrap() + d * self.usk);

                // Extract sigma to a session key and 2 MACs
                let hk = MyKdf::from_prk(sigma.compress().as_bytes()).unwrap();
                let mut output_key = SessKey::default();
                let mut mac0 = [0u8; 32];
                let mut mac1 = [0u8; 32];
                hk.expand_multi_info(&[&self.ssid, b"mac0"], &mut mac0)
                    .unwrap();
                hk.expand_multi_info(&[&self.ssid, b"mac1"], &mut mac1)
                    .unwrap();
                hk.expand_multi_info(&[&self.ssid, b"sess key"], &mut output_key)
                    .unwrap();
                self.output_key = Some(output_key);

                // Verify the given mac0
                if !bool::from(incoming_mac1.ct_eq(&mac1)) {
                    return Err(MacError.into());
                }

                // Send mac0
                self.done = true;
                Some(mac0.to_vec())
            }
            3 => {
                // Receive mac0
                let incoming_mac0 = incoming_msg;

                // Verify the given mac0
                if !bool::from(incoming_mac0.ct_eq(&self.macs.as_ref().unwrap().0)) {
                    return Err(MacError.into());
                }

                // All done
                self.done = true;
                None
            }
            _ => {
                panic!("protocol already ended");
            }
        };

        // Increment the step counter. The initiator gets the even steps, the responder the odd steps.
        self.next_step += 2;

        Ok(out)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use rand::Rng;

    #[test]
    fn hmqv_c_correctness() {
        let mut rng = rand::thread_rng();

        let (mpk, msk) = IdHmqvC::gen_main_keypair(&mut rng);

        let id1 = rng.gen();
        let id2 = rng.gen();
        let (upk1, usk1) = IdHmqvC::gen_user_keypair(&mut rng);
        let (upk2, usk2) = IdHmqvC::gen_user_keypair(&mut rng);

        let cert1 = IdHmqvC::extract(&mut rng, &msk, &id1, &upk1);
        let cert2 = IdHmqvC::extract(&mut rng, &msk, &id2, &upk2);

        let ssid = rng.gen();

        let mut user1 =
            IdHmqvC::new_session(&mut rng, ssid, mpk, cert1, usk1, PartyRole::Initiator);
        let mut user2 =
            IdHmqvC::new_session(&mut rng, ssid, mpk, cert2, usk2, PartyRole::Responder);

        let msg1 = user1.run(&mut rng, &[]).unwrap().unwrap();
        let msg2 = user2.run(&mut rng, &msg1).unwrap().unwrap();
        let msg3 = user1.run(&mut rng, &msg2).unwrap().unwrap();
        let msg4 = user2.run(&mut rng, &msg3).unwrap();

        let (user1_interlocutor, user1_key) = user1.finalize();
        let (user2_interlocutor, user2_key) = user2.finalize();

        assert!(msg4.is_none());
        assert!(user1_interlocutor == id2);
        assert!(user2_interlocutor == id1);
        assert_eq!(user1_key, user2_key);
    }
}
