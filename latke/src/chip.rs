//! The [CHIP](https://eprint.iacr.org/2020/529.pdf) iPAKE. See Figure 6.

#![allow(non_snake_case)]

use crate::{Id, Pake, PartyRole, SessKey, Ssid};

use blake2::Blake2b512;
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoBasepointTable, RistrettoPoint},
    scalar::Scalar,
};
use hkdf::hmac::digest::{consts::U64, Digest};
use rand::{CryptoRng, RngCore};

struct PwFile {
    id: Id,
    X: RistrettoPoint,
    Y: RistrettoPoint,
    xhat: Scalar,
}

impl PwFile {
    fn new<R: RngCore + CryptoRng>(mut rng: R, pw: Vec<u8>, id: Id) -> Self {
        let x = Scalar::random(&mut rng);
        let y = Scalar::from_hash(Blake2b512::new().chain_update([0x01]).chain_update(pw));

        let X = RistrettoPoint::mul_base(&x);
        let Y = RistrettoPoint::mul_base(&y);
        let h = Scalar::from_hash(
            Blake2b512::new()
                .chain_update([0x02])
                .chain_update(&id)
                .chain_update(X.compress().as_bytes()),
        );
        let xhat = x + h * y;

        PwFile { id, X, Y, xhat }
    }
}

// The protocol is perfectly symmetric, so we can use the same struct for both roles.
struct Executor<R: RngCore + CryptoRng, P: Pake> {
    // The IBKE portion
    pwfile: PwFile,
    ssid: Ssid,
    other_id: Id,
    role: PartyRole,
    r: Scalar,

    // The PAKE portion
    pake_state: Option<P>,
    key: Option<SessKey>,

    /// The transcript of every message sent
    tr_sent: Vec<Vec<u8>>,
    /// The transcript of every message received
    tr_recv: Vec<Vec<u8>>,
    /// The RNG for this session
    rng: R,
}

impl<R: RngCore + CryptoRng, P: Pake> Executor<R, P> {
    fn new(mut rng: R, pwfile: PwFile, ssid: Ssid, other_id: Id, role: PartyRole) -> Self {
        Executor {
            pwfile,
            ssid,
            other_id,
            role,
            r: Scalar::random(&mut rng),
            pake_state: None,
            key: None,
            tr_sent: Vec::new(),
            tr_recv: Vec::new(),
            rng,
        }
    }

    fn round_1(&mut self) -> Vec<u8> {
        self.r = Scalar::random(&mut self.rng);
        let R = RistrettoPoint::mul_base(&self.r);

        // Send X, R
        let msg = [
            self.pwfile.X.compress().as_bytes().as_slice(),
            R.compress().as_bytes().as_slice(),
        ]
        .concat();
        self.tr_sent.push(msg.clone());
        msg
    }

    fn round_2(&mut self, msg: &[u8]) -> Vec<u8> {
        self.tr_recv.push(msg.to_vec());

        let (other_X_bytes, other_R_bytes) = msg.split_at(32);
        assert_eq!(other_R_bytes.len(), 32);

        let other_X = CompressedRistretto::from_slice(other_X_bytes)
            .unwrap()
            .decompress()
            .unwrap();
        let other_R = CompressedRistretto::from_slice(other_R_bytes)
            .unwrap()
            .decompress()
            .unwrap();

        let other_h = Scalar::from_hash(
            Blake2b512::new()
                .chain_update([0x02])
                .chain_update(&self.other_id)
                .chain_update(other_X_bytes),
        );
        let alpha = other_R * self.r;
        let beta = (other_R + other_X + (self.pwfile.Y * other_h)) * (self.r + self.pwfile.xhat);
        let tr = if self.role == PartyRole::Initiator {
            self.tr_sent
                .iter()
                .zip(self.tr_recv.iter())
                .flat_map(|(v, w)| [v.as_slice(), w.as_slice()].concat())
                .collect::<Vec<_>>()
        } else {
            self.tr_recv
                .iter()
                .zip(self.tr_sent.iter())
                .flat_map(|(v, w)| [v.as_slice(), w.as_slice()].concat())
                .collect::<Vec<_>>()
        };

        let pake_input = [
            alpha.compress().as_bytes().as_slice(),
            beta.compress().as_bytes().as_slice(),
            &tr.as_slice(),
        ]
        .concat();

        pake_input
    }

    fn step_1(&mut self) -> Vec<u8> {
        self.round_1()
    }

    fn step_2(&mut self, msg: &[u8]) -> Vec<u8> {
        self.tr_recv.push(msg.to_vec());
        self.round_1()
    }

    fn step_3(&mut self, msg: &[u8]) -> Vec<u8> {
        self.tr_recv.push(msg.to_vec());
        let ibke_out = self.round_2(msg);

        // Initialize the PAKE and send the first message
        let mut pake_state = P::new(&mut self.rng, PartyRole::Initiator, &ibke_out);
        let pake_msg = pake_state.run(&[]);
        self.pake_state = Some(pake_state);

        pake_msg.unwrap()
    }

    fn step_4(&mut self, msg: &[u8]) -> Vec<u8> {
        let last_msg = self.tr_recv.last().cloned().unwrap();
        let ibke_out = self.round_2(&last_msg);

        // Initialize the PAKE, process the first message, and send the second
        let mut pake_state = P::new(&mut self.rng, PartyRole::Responder, &ibke_out);
        let pake_msg = pake_state.run(msg);
        self.pake_state = Some(pake_state);

        pake_msg.unwrap()
    }

    fn step_5(&mut self, msg: &[u8]) {
        // Process the second PAKE message
        self.pake_state.as_mut().unwrap().run(msg);
    }

    fn finalize(&self) -> SessKey {
        self.pake_state.as_ref().unwrap().finalize().unwrap()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::spake2::MySpake2;

    use rand::Rng;

    #[test]
    fn fg_ibke_correctness() {
        let mut rng = rand::thread_rng();

        let id1 = rng.gen();
        let id2 = rng.gen();
        let ssid = rng.gen();

        let pw = b"password";

        let pwfile1 = PwFile::new(&mut rng, pw.to_vec(), id1);
        let pwfile2 = PwFile::new(&mut rng, pw.to_vec(), id2);

        let mut user1 = Executor::<_, MySpake2>::new(
            rand::thread_rng(),
            pwfile1,
            ssid,
            id2,
            PartyRole::Initiator,
        );
        let mut user2 = Executor::<_, MySpake2>::new(
            rand::thread_rng(),
            pwfile2,
            ssid,
            id1,
            PartyRole::Responder,
        );

        let msg1 = user1.step_1();
        let msg2 = user2.step_2(&msg1);
        let msg3 = user1.step_3(&msg2);
        let msg4 = user2.step_4(&msg3);
        user1.step_5(&msg4);

        assert_eq!(user1.finalize(), user2.finalize());
    }
}
