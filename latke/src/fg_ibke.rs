//! Implements the Fiore-Gennaro IBKE with key confirmation
#![allow(non_snake_case)]

use blake2::digest::{Digest, MacError};
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use rand_core::{CryptoRng, RngCore};

use crate::{
    AsBytes, Id, IdentityBasedKeyExchange, MyHash512, MyKdfExtract, PartyRole, SessKey, Ssid,
};

type MainPubkey = RistrettoPoint;
type MainPrivkey = Scalar;

type EphemeralPubkey = RistrettoPoint;
type EphemeralPrivkey = Scalar;

#[derive(Clone)]
struct Certificate {
    id: Id,
    X: RistrettoPoint,
    xhat: Scalar,
}

struct FgIbke {
    ssid: Ssid,
    mpk: MainPubkey,
    cert: Certificate,

    running_transcript_hash: MyKdfExtract,
    eph_sk: Option<EphemeralPrivkey>,
    eph_pk: Option<EphemeralPubkey>,
    // The output values. These need to be hashed in with other things before they're output as the session key
    alpha: Option<RistrettoPoint>,
    beta: Option<RistrettoPoint>,
    output_id: Option<Id>,

    done: bool,
    next_step: usize,
}

impl FgIbke {
    //type MainPubkey = MainPubkey;
    //type MainPrivkey = MainPrivkey;
    //type UserPubkey = ();
    //type UserPrivkey = ();
    //type Certificate = Certificate;

    //type Error = ();

    fn gen_main_keypair<R: RngCore + CryptoRng>(mut rng: R) -> (MainPubkey, MainPrivkey) {
        let msk = MainPrivkey::random(&mut rng);
        let mpk = MainPubkey::mul_base(&msk);
        (mpk, msk)
    }

    fn gen_user_keypair<R: RngCore + CryptoRng>(_: R) -> ((), ()) {
        ((), ())
    }

    fn extract<R: RngCore + CryptoRng>(mut rng: R, msk: &Scalar, id: &Id, _: &()) -> Certificate {
        let x = Scalar::random(&mut rng);

        let X = RistrettoPoint::mul_base(&x);
        let h = Scalar::from_hash(
            MyHash512::new()
                .chain_update([0x02])
                .chain_update(&id)
                .chain_update(X.compress().as_bytes()),
        );
        let xhat = x + h * msk;

        Certificate { id: *id, X, xhat }
    }

    fn new_session<R: rand::prelude::RngCore + rand::prelude::CryptoRng>(
        rng: R,
        ssid: crate::Ssid,
        mpk: MainPubkey,
        cert: Certificate,
        _: (),
        role: crate::PartyRole,
    ) -> Self {
        let next_step = if role == PartyRole::Initiator { 0 } else { 1 };

        FgIbke {
            ssid,
            mpk,
            cert,

            running_transcript_hash: MyKdfExtract::new(Some(b"fgibke-tr-hash")),
            eph_sk: None,
            eph_pk: None,
            alpha: None,
            beta: None,
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

                // Generate an ephemeral keypair
                let eph_sk = Scalar::random(&mut rng);
                let eph_pk = RistrettoPoint::mul_base(&eph_sk);

                let other_h = Scalar::from_hash(
                    MyHash512::new()
                        .chain_update([0x02])
                        .chain_update(&other_id)
                        .chain_update(incoming_X_bytes),
                );
                self.alpha = Some(incoming_eph_pk * eph_sk);
                self.beta = Some(
                    (incoming_eph_pk + incoming_X + (self.mpk * other_h))
                        * (eph_sk + self.cert.xhat),
                );
                self.output_id = Some(other_id.try_into().unwrap());

                // Send id, X, eph_pk
                self.done = true;
                Some(
                    [
                        &self.cert.id,
                        self.cert.X.compress().as_bytes().as_slice(),
                        eph_pk.compress().as_bytes().as_slice(),
                    ]
                    .concat(),
                )
            }
            2 => {
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

                let other_h = Scalar::from_hash(
                    MyHash512::new()
                        .chain_update([0x02])
                        .chain_update(&other_id)
                        .chain_update(incoming_X_bytes),
                );
                self.alpha = Some(incoming_eph_pk * self.eph_sk.as_ref().unwrap());
                self.beta = Some(
                    (incoming_eph_pk + incoming_X + (self.mpk * other_h))
                        * (self.eph_sk.as_ref().unwrap() + self.cert.xhat),
                );
                self.output_id = Some(other_id.try_into().unwrap());

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
        trh.input_ikm(self.alpha.as_ref().unwrap().compress().as_bytes());
        trh.input_ikm(self.beta.as_ref().unwrap().compress().as_bytes());

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

        let (mpk, msk) = FgIbke::gen_main_keypair(&mut rng);

        let id1 = rng.gen();
        let id2 = rng.gen();

        let cert1 = FgIbke::extract(&mut rng, &msk, &id1, &());
        let cert2 = FgIbke::extract(&mut rng, &msk, &id2, &());

        let ssid = rng.gen();
        let mut user1 = FgIbke::new_session(&mut rng, ssid, mpk, cert1, (), PartyRole::Initiator);
        let mut user2 = FgIbke::new_session(&mut rng, ssid, mpk, cert2, (), PartyRole::Responder);

        let msg1 = user1.run(&mut rng, &[]).unwrap().unwrap();
        let msg2 = user2.run(&mut rng, &msg1).unwrap().unwrap();
        let msg3 = user1.run(&mut rng, &msg2).unwrap();

        assert!(msg3.is_none());
        let (user1_interlocutor, user1_key) = user1.finalize();
        let (user2_interlocutor, user2_key) = user2.finalize();

        // Check that the users agree on the interlocutor and the session key
        assert!(user1_interlocutor == id2);
        assert!(user2_interlocutor == id1);
        assert_eq!(dbg!(user1_key), user2_key);
    }
}

/*
impl AsBytes for RistrettoPoint {
    fn as_bytes(&self) -> &[u8] {
        self.compress().as_bytes()
    }
}
*/
