//! Implements the [Fiore-Gennaro IBKE](https://www.dariofiore.it/papers/ib-ka-journal-final.pdf) with the addition of key confirmation
#![allow(non_snake_case)]

use blake2::digest::{Digest, MacError};
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

use crate::{
    AsBytes, Id, IdentityBasedKeyExchange, MyHash512, MyKdf, MyKdfExtract, PartyRole, SessKey, Ssid,
};

type MainPubkey = CompressedRistretto;
type MainPrivkey = Scalar;

type EphemeralPubkey = RistrettoPoint;
type EphemeralPrivkey = Scalar;

#[derive(Clone)]
pub struct FgIbkeCCert {
    id: Id,
    X: RistrettoPoint,
    xhat: Scalar,
}

/// The [Fiore-Gennaro IBKE](https://www.dariofiore.it/papers/ib-ka-journal-final.pdf) with the addition of key confirmation. It also hashes the transcript
pub struct FgIbkeC {
    ssid: Ssid,
    mpk: MainPubkey,
    cert: FgIbkeCCert,

    running_transcript_hash: MyKdfExtract,
    eph_sk: Option<EphemeralPrivkey>,
    eph_pk: Option<EphemeralPubkey>,
    output_id: Option<Id>,
    macs: Option<([u8; 32], [u8; 32])>,
    // The session key before it's hashed with the transcript hash
    sess_key: Option<SessKey>,

    done: bool,
    next_step: usize,
}

impl IdentityBasedKeyExchange for FgIbkeC {
    type MainPubkey = MainPubkey;
    type MainPrivkey = MainPrivkey;
    type UserPubkey = ();
    type UserPrivkey = ();
    type Certificate = FgIbkeCCert;

    type Error = MacError;

    fn gen_main_keypair<R: RngCore + CryptoRng>(mut rng: R) -> (MainPubkey, MainPrivkey) {
        let msk = MainPrivkey::random(&mut rng);
        let mpk = RistrettoPoint::mul_base(&msk);
        (mpk.compress(), msk)
    }

    fn gen_user_keypair<R: RngCore + CryptoRng>(_: R) -> ((), ()) {
        ((), ())
    }

    fn extract<R: RngCore + CryptoRng>(mut rng: R, msk: &Scalar, id: &Id, _: &()) -> FgIbkeCCert {
        let x = Scalar::random(&mut rng);

        let X = RistrettoPoint::mul_base(&x);
        let h = Scalar::from_hash(
            MyHash512::new()
                .chain_update([0x02])
                .chain_update(&id)
                .chain_update(X.compress().as_bytes()),
        );
        let xhat = x + h * msk;

        FgIbkeCCert { id: *id, X, xhat }
    }

    fn new_session<R: RngCore + CryptoRng>(
        _: R,
        ssid: crate::Ssid,
        mpk: MainPubkey,
        cert: FgIbkeCCert,
        _: (),
        role: crate::PartyRole,
    ) -> Self {
        let next_step = if role == PartyRole::Initiator { 0 } else { 1 };

        FgIbkeC {
            ssid,
            mpk,
            cert,

            running_transcript_hash: MyKdfExtract::new(Some(b"fgibke-tr-hash")),
            eph_sk: None,
            eph_pk: None,
            macs: None,
            sess_key: None,
            output_id: None,

            done: false,
            next_step,
        }
    }

    fn run<R: RngCore + CryptoRng>(
        &mut self,
        mut rng: R,
        incoming_msg: &[u8],
    ) -> Result<Option<Vec<u8>>, MacError> {
        let out = match self.next_step {
            0 => {
                assert!(incoming_msg.is_empty());

                // Generate an ephemeral keypair
                let eph_sk = Scalar::random(&mut rng);
                let eph_pk = RistrettoPoint::mul_base(&eph_sk);

                self.eph_sk = Some(eph_sk.clone());
                self.eph_pk = Some(eph_pk.clone());

                // Send id, X, eph_pk
                Some(
                    [
                        &self.cert.id,
                        self.cert.X.compress().as_bytes().as_slice(),
                        eph_pk.compress().as_bytes().as_slice(),
                    ]
                    .concat(),
                )
            }
            1 => {
                // Receive id, X, eph_pk
                let rest = incoming_msg;
                let (other_id, rest) = incoming_msg.split_at(Id::default().len());
                let (incoming_X_bytes, incoming_eph_pk_bytes) = rest.split_at(32);
                let incoming_X = CompressedRistretto::from_slice(incoming_X_bytes)
                    .unwrap()
                    .decompress()
                    .unwrap();
                let incoming_eph_pk = CompressedRistretto::from_slice(incoming_eph_pk_bytes)
                    .unwrap()
                    .decompress()
                    .unwrap();
                self.output_id = Some(other_id.try_into().unwrap());

                // Generate an ephemeral keypair
                let eph_sk = Scalar::random(&mut rng);
                let eph_pk = RistrettoPoint::mul_base(&eph_sk);

                // Do the key agreement arithmetic
                let other_h = Scalar::from_hash(
                    MyHash512::new()
                        .chain_update([0x02])
                        .chain_update(&other_id)
                        .chain_update(incoming_X_bytes),
                );
                let alpha = incoming_eph_pk * eph_sk;
                let beta =
                    (incoming_eph_pk + incoming_X + (self.mpk.decompress().unwrap() * other_h))
                        * (eph_sk + self.cert.xhat);

                // Now compute the session key and MACs
                let mut sess_hash = [0u8; 64 + core::mem::size_of::<SessKey>()];
                let hk = MyKdf::from_prk(
                    &[
                        alpha.compress().as_bytes().as_slice(),
                        beta.compress().as_bytes().as_slice(),
                    ]
                    .concat(),
                )
                .unwrap();
                hk.expand(b"fg-expand", &mut sess_hash).unwrap();
                let (macs, sess_key) = sess_hash.split_at(64);
                let (mac0, mac1) = macs.split_at(32);
                self.macs = Some((mac0.try_into().unwrap(), mac1.try_into().unwrap()));
                self.sess_key = Some(sess_key.try_into().unwrap());

                // Send id, X, eph_pk, mac1
                Some(
                    [
                        &self.cert.id,
                        self.cert.X.compress().as_bytes().as_slice(),
                        eph_pk.compress().as_bytes().as_slice(),
                        mac1,
                    ]
                    .concat(),
                )
            }
            2 => {
                // Receive id, X, eph_pk
                let rest = incoming_msg;
                let (other_id, rest) = incoming_msg.split_at(Id::default().len());
                let (incoming_X_bytes, rest) = rest.split_at(32);
                let (incoming_eph_pk_bytes, incoming_mac1) = rest.split_at(32);
                let incoming_X = CompressedRistretto::from_slice(incoming_X_bytes)
                    .unwrap()
                    .decompress()
                    .unwrap();
                let incoming_eph_pk = CompressedRistretto::from_slice(incoming_eph_pk_bytes)
                    .unwrap()
                    .decompress()
                    .unwrap();
                self.output_id = Some(other_id.try_into().unwrap());

                // Do the key agreement arithmetic
                let other_h = Scalar::from_hash(
                    MyHash512::new()
                        .chain_update([0x02])
                        .chain_update(&other_id)
                        .chain_update(incoming_X_bytes),
                );
                let alpha = incoming_eph_pk * self.eph_sk.as_ref().unwrap();
                let beta =
                    (incoming_eph_pk + incoming_X + (self.mpk.decompress().unwrap() * other_h))
                        * (self.eph_sk.as_ref().unwrap() + self.cert.xhat);

                // Now compute the session key and MACs
                let mut sess_hash = [0u8; 64 + core::mem::size_of::<SessKey>()];
                let hk = MyKdf::from_prk(
                    &[
                        alpha.compress().as_bytes().as_slice(),
                        beta.compress().as_bytes().as_slice(),
                    ]
                    .concat(),
                )
                .unwrap();
                hk.expand(b"fg-expand", &mut sess_hash).unwrap();
                let (macs, sess_key) = sess_hash.split_at(64);
                let (mac0, mac1) = macs.split_at(32);
                self.sess_key = Some(sess_key.try_into().unwrap());

                // Check the MAC
                if !bool::from(mac1.ct_eq(incoming_mac1)) {
                    return Err(MacError);
                }

                // Send the MAC
                self.done = true;
                Some(mac0.to_vec())
            }
            3 => {
                // Receive mac0
                let incoming_mac0 = incoming_msg;
                let mac0 = self.macs.as_ref().unwrap().0;

                // Check the MAC
                if !bool::from(mac0.ct_eq(&incoming_mac0)) {
                    return Err(MacError);
                }

                // All done
                self.done = true;
                None
            }

            _ => {
                panic!("protocol already ended")
            }
        };

        // Initiator gets the even steps, responder gets the odd steps
        self.next_step += 2;

        // Add the incoming and outgoing messages to the running transcript hash, if they exist
        if incoming_msg.len() > 0 {
            self.running_transcript_hash.input_ikm(incoming_msg);
        }
        out.as_ref()
            .map(|v| self.running_transcript_hash.input_ikm(v));

        Ok(out)
    }

    fn run_sim(&mut self) -> Option<usize> {
        todo!()
    }

    fn is_done(&self) -> bool {
        self.done
    }

    fn finalize(&self) -> (Id, SessKey) {
        // Add the IBKE output to the running transcript hash
        let mut trh = self.running_transcript_hash.clone();
        trh.input_ikm(self.sess_key.as_ref().unwrap());

        // The final session key is the KDF of the transcript with the IBKE session key
        let (_, hk) = trh.finalize();
        let mut sess_key = [0u8; 32];
        hk.expand_multi_info(&[&self.ssid, b"fgibke-final"], &mut sess_key)
            .unwrap();

        (self.output_id.unwrap(), sess_key)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::{thread_rng, Rng};

    #[test]
    fn fg_ibke_correctness() {
        let mut rng = thread_rng();

        let (mpk, msk) = FgIbkeC::gen_main_keypair(&mut rng);

        let id1 = rng.gen();
        let id2 = rng.gen();

        let cert1 = FgIbkeC::extract(&mut rng, &msk, &id1, &());
        let cert2 = FgIbkeC::extract(&mut rng, &msk, &id2, &());

        let ssid = rng.gen();
        let mut user1 = FgIbkeC::new_session(&mut rng, ssid, mpk, cert1, (), PartyRole::Initiator);
        let mut user2 = FgIbkeC::new_session(&mut rng, ssid, mpk, cert2, (), PartyRole::Responder);

        let msg1 = user1.run(&mut rng, &[]).unwrap().unwrap();
        let msg2 = user2.run(&mut rng, &msg1).unwrap().unwrap();
        let msg3 = user1.run(&mut rng, &msg2).unwrap().unwrap();
        let msg4 = user2.run(&mut rng, &msg3).unwrap();

        assert!(msg4.is_none());
        let (user1_interlocutor, user1_key) = user1.finalize();
        let (user2_interlocutor, user2_key) = user2.finalize();

        // Check that the users agree on the interlocutor and the session key
        assert!(user1_interlocutor == id2);
        assert!(user2_interlocutor == id1);
        assert_eq!(dbg!(user1_key), user2_key);
    }
}

impl AsBytes for CompressedRistretto {
    fn as_bytes(&self) -> &[u8] {
        CompressedRistretto::as_bytes(self)
    }
}
