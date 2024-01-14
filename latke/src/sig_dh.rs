//! Defines the SIG-DH AKE protocol by [Canetti and Krawczyk](https://eprint.iacr.org/2002/059), with the AKE-to-IBKE transform applied

use crate::{Id, MyKdf, PartyRole, SessKey, Ssid};

use ed25519_dalek::{
    ed25519::SignatureEncoding, Signature, Signer, SigningKey as SigPrivkey, Verifier,
    VerifyingKey as SigPubkey,
};
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{
    PublicKey as DhPubkey, ReusableSecret as DhEphemeralSecret, StaticSecret as DhPrivkey,
};

type UserPubkey = (SigPubkey, DhPubkey);
type UserPrivkey = (SigPrivkey, DhPrivkey);

struct SigDhCert {
    id: Id,
    upk: UserPubkey,
    upk_sig: Signature,
}

impl SigDhCert {
    fn to_bytes(&self) -> Vec<u8> {
        [
            &self.id[..],
            self.upk.0.as_bytes().as_slice(),
            self.upk.1.as_bytes().as_slice(),
            self.upk_sig.to_bytes().as_slice(),
        ]
        .concat()
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let rest = bytes;
        let (id, rest) = rest.split_at(Id::default().len());
        let (sig_upk, rest) = rest.split_at(32);
        let (dh_upk, rest) = rest.split_at(32);
        let sig = rest;

        SigDhCert {
            id: id.try_into().unwrap(),
            upk: (
                SigPubkey::from_bytes(sig_upk.try_into().unwrap()).unwrap(),
                DhPubkey::from(<[u8; 32]>::try_from(dh_upk).unwrap()),
            ),
            upk_sig: Signature::from_bytes(sig.try_into().unwrap()),
        }
    }
}

struct SigDh {
    ssid: Ssid,
    cert: SigDhCert,
    mpk: SigPubkey,
    usk: UserPrivkey,
    other_id: Id,

    // Ephemeral values, determined during the protocol
    eph_sk: Option<DhEphemeralSecret>,
    eph_pk: Option<DhPubkey>,
    output_key: Option<SessKey>,

    next_step: usize,
}

impl SigDh {
    fn new(
        ssid: Ssid,
        mpk: SigPubkey,
        cert: SigDhCert,
        usk: UserPrivkey,
        role: PartyRole,
        other_id: Id,
    ) -> Self {
        let next_step = if role == PartyRole::Initiator { 0 } else { 1 };
        SigDh {
            ssid,
            cert,
            mpk,
            usk,
            other_id,
            output_key: None,
            eph_sk: None,
            eph_pk: None,
            next_step,
        }
    }

    fn finalize(&self) -> SessKey {
        self.output_key.unwrap()
    }

    fn gen_main_keypair<R: RngCore + CryptoRng>(mut rng: R) -> (SigPubkey, SigPrivkey) {
        let sig_sk = SigPrivkey::generate(&mut rng);
        let sig_pk = SigPubkey::from(&sig_sk);
        (sig_pk, sig_sk)
    }

    fn gen_user_keypair<R: RngCore + CryptoRng>(mut rng: R) -> (UserPubkey, UserPrivkey) {
        let sig_sk = SigPrivkey::generate(&mut rng);
        let sig_pk = SigPubkey::from(&sig_sk);
        let dh_sk = DhPrivkey::random_from_rng(&mut rng);
        let dh_pk = DhPubkey::from(&dh_sk);
        ((sig_pk, dh_pk), (sig_sk, dh_sk))
    }

    fn extract(msk: &SigPrivkey, id: &Id, upk: &UserPubkey) -> SigDhCert {
        let upk_sig = msk.sign(
            &[
                &id[..],
                upk.0.as_bytes().as_slice(),
                upk.1.as_bytes().as_slice(),
            ]
            .concat(),
        );
        SigDhCert {
            id: id.clone(),
            upk: upk.clone(),
            upk_sig,
        }
    }

    fn run<R: RngCore + CryptoRng>(
        &mut self,
        _: R,
        incoming_msg: &[u8],
    ) -> Result<Option<Vec<u8>>, ed25519_dalek::SignatureError> {
        let out = match self.next_step {
            // Send an ephemeral keyshare and a signature on it
            0 => {
                assert!(incoming_msg.is_empty());

                // Generate a fresh ephemeral keypair
                let eph_sk = DhEphemeralSecret::random_from_rng(&mut rand::thread_rng());
                let eph_pk = DhPubkey::from(&eph_sk);
                self.eph_sk = Some(eph_sk);
                self.eph_pk = Some(eph_pk);

                // Sign the ephemeral pubkey
                let sig = self
                    .usk
                    .0
                    .sign(&[&[0x00], self.ssid.as_slice(), eph_pk.as_bytes()].concat());

                // Send the ephemeral pubkey, the signature, and the certificate
                Some(
                    [
                        eph_pk.as_bytes().as_slice(),
                        &sig.to_bytes(),
                        &self.cert.to_bytes(),
                    ]
                    .concat(),
                )
            }
            // Process the keyshare with signature and send a new keyshare and signature
            1 => {
                // Receive the ephemeral pubkey, the signature, and the cert
                let rest = incoming_msg;
                let (incoming_eph_pk_bytes, rest) = rest.split_at(32);
                let (incoming_sig_bytes, rest) = rest.split_at(Signature::BYTE_SIZE);
                let incoming_cert_bytes = rest;

                let incoming_eph_pk =
                    DhPubkey::from(<[u8; 32]>::try_from(incoming_eph_pk_bytes).unwrap());
                let incoming_sig = Signature::from_bytes(incoming_sig_bytes.try_into().unwrap());
                let incoming_cert = SigDhCert::from_bytes(incoming_cert_bytes);

                // Verify the certificate
                self.mpk.verify(
                    &[
                        &incoming_cert.id[..],
                        incoming_cert.upk.0.as_bytes().as_slice(),
                        incoming_cert.upk.1.as_bytes().as_slice(),
                    ]
                    .concat(),
                    &incoming_cert.upk_sig,
                )?;
                // Verify that the ID is the same as the one we expect
                assert_eq!(incoming_cert.id, self.other_id);
                // If that all works out, then we can use the other user's pubkey
                let other_upk = incoming_cert.upk;

                // Verify the signature over the ephemeral key
                other_upk.0.verify(
                    &[&[0x00], self.ssid.as_slice(), incoming_eph_pk.as_bytes()].concat(),
                    &incoming_sig,
                )?;

                // Generate a fresh ephemeral keypair
                let eph_sk = DhEphemeralSecret::random_from_rng(&mut rand::thread_rng());
                let eph_pk = DhPubkey::from(&eph_sk);

                // Sign the ephemeral pubkey
                let sig = self
                    .usk
                    .0
                    .sign(&[&[0x01], self.ssid.as_slice(), eph_pk.as_bytes()].concat());

                // Calculate the DH shared secrets and extract the session key from all the shared secrets and the transcript
                let z1 = self.usk.1.diffie_hellman(&other_upk.1);
                let z2 = self.usk.1.diffie_hellman(&incoming_eph_pk);
                let z3 = eph_sk.diffie_hellman(&other_upk.1);
                let z4 = eph_sk.diffie_hellman(&incoming_eph_pk);
                let (_, hk) = MyKdf::extract(
                    None,
                    &[z1.to_bytes(), z2.to_bytes(), z3.to_bytes(), z4.to_bytes()].concat(),
                );
                let mut sess_key = SessKey::default();
                hk.expand_multi_info(
                    &[
                        &self.ssid,
                        &incoming_eph_pk_bytes,
                        eph_pk.as_bytes().as_slice(),
                    ],
                    &mut sess_key,
                )
                .unwrap();
                self.output_key = Some(sess_key);

                // Send the ephemeral pubkey, the signature, and the cert
                Some(
                    [
                        eph_pk.as_bytes().as_slice(),
                        &sig.to_bytes(),
                        &self.cert.to_bytes(),
                    ]
                    .concat(),
                )
            }
            2 => {
                let rest = incoming_msg;
                let (incoming_eph_pk_bytes, rest) = rest.split_at(32);
                let (incoming_sig_bytes, rest) = rest.split_at(Signature::BYTE_SIZE);
                let incoming_cert_bytes = rest;

                let incoming_eph_pk =
                    DhPubkey::from(<[u8; 32]>::try_from(incoming_eph_pk_bytes).unwrap());
                let incoming_sig = Signature::from_bytes(incoming_sig_bytes.try_into().unwrap());
                let incoming_cert = SigDhCert::from_bytes(incoming_cert_bytes);

                // Verify the certificate
                self.mpk.verify(
                    &[
                        &incoming_cert.id[..],
                        incoming_cert.upk.0.as_bytes().as_slice(),
                        incoming_cert.upk.1.as_bytes().as_slice(),
                    ]
                    .concat(),
                    &incoming_cert.upk_sig,
                )?;
                // Verify that the ID is the same as the one we expect
                assert_eq!(incoming_cert.id, self.other_id);
                // If that all works out, then we can use the other user's pubkey
                let other_upk = incoming_cert.upk;

                // Verify the signature over the ephemeral key
                other_upk.0.verify(
                    &[&[0x01], self.ssid.as_slice(), incoming_eph_pk.as_bytes()].concat(),
                    &incoming_sig,
                )?;

                // Calculate the DH shared secrets and extract the session key from all the shared secrets and the transcript
                let z1 = self.usk.1.diffie_hellman(&other_upk.1);
                let z2 = self.eph_sk.as_ref().unwrap().diffie_hellman(&other_upk.1);
                let z3 = self.usk.1.diffie_hellman(&incoming_eph_pk);
                let z4 = self
                    .eph_sk
                    .as_ref()
                    .unwrap()
                    .diffie_hellman(&incoming_eph_pk);
                let (_, hk) = MyKdf::extract(
                    None,
                    &[z1.to_bytes(), z2.to_bytes(), z3.to_bytes(), z4.to_bytes()].concat(),
                );
                let mut sess_key = SessKey::default();
                hk.expand_multi_info(
                    &[
                        &self.ssid,
                        self.eph_pk.as_ref().unwrap().as_bytes().as_slice(),
                        &incoming_eph_pk_bytes,
                    ],
                    &mut sess_key,
                )
                .unwrap();
                self.output_key = Some(sess_key);

                None
            }
            _ => panic!("protocol already ended"),
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
    fn sig_dh_correctness() {
        let mut rng = rand::thread_rng();

        let (mpk, msk) = SigDh::gen_main_keypair(&mut rng);

        let id1 = rng.gen();
        let id2 = rng.gen();
        let (upk1, usk1) = SigDh::gen_user_keypair(&mut rng);
        let (upk2, usk2) = SigDh::gen_user_keypair(&mut rng);

        let cert1 = SigDh::extract(&msk, &id1, &upk1);
        let cert2 = SigDh::extract(&msk, &id2, &upk2);

        let ssid = rng.gen();

        let mut user1 = SigDh::new(ssid, mpk, cert1, usk1, PartyRole::Initiator, id2);
        let mut user2 = SigDh::new(ssid, mpk, cert2, usk2, PartyRole::Responder, id1);

        let msg1 = user1.run(&mut rng, &[]).unwrap().unwrap();
        let msg2 = user2.run(&mut rng, &msg1).unwrap().unwrap();
        let msg3 = user1.run(&mut rng, &msg2).unwrap();

        assert!(msg3.is_none());
        assert_eq!(user1.finalize(), user2.finalize());
    }
}
