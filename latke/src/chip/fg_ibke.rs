//! The Fiore-Gennaro IBKE used by [CHIP](https://eprint.iacr.org/2020/529.pdf). See CHIP Figure 6.

#![allow(non_snake_case)]

use crate::{Id, SessKey, Ssid};

use blake2::Blake2b512;
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoBasepointTable, RistrettoPoint},
    scalar::Scalar,
};
use hkdf::hmac::digest::{consts::U64, Digest};
use rand::{CryptoRng, RngCore};

//type MyHash = Blake2b<U64>;

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

#[derive(PartialEq, Eq)]
enum Role {
    Initiator,
    Responder,
}

// The protocol is perfectly symmetric, so we can use the same struct for both roles.
struct Executor {
    pwfile: PwFile,
    ssid: Ssid,
    other_id: Id,
    role: Role,
    r: Scalar,

    // The transcript of every message sent
    tr_sent: Vec<Vec<u8>>,
    // The transcript of every message received
    tr_recv: Vec<Vec<u8>>,
}

impl Executor {
    fn new<R: RngCore + CryptoRng>(
        mut rng: R,
        pwfile: PwFile,
        ssid: Ssid,
        other_id: Id,
        role: Role,
    ) -> Self {
        Executor {
            pwfile,
            ssid,
            other_id,
            role,
            r: Scalar::random(&mut rng),
            tr_sent: Vec::new(),
            tr_recv: Vec::new(),
        }
    }

    fn step_1<R: RngCore + CryptoRng>(&mut self, mut rng: R) -> Vec<u8> {
        self.r = Scalar::random(&mut rng);
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

    fn step_2(mut self, msg: &[u8]) -> Vec<u8> {
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
        let beta = RistrettoPoint::default();
        let tr = if self.role == Role::Initiator {
            self.tr_sent
                .into_iter()
                .zip(self.tr_recv.into_iter())
                .flat_map(|(v, w)| [v, w].concat())
                .collect::<Vec<_>>()
        } else {
            self.tr_recv
                .into_iter()
                .zip(self.tr_sent.into_iter())
                .flat_map(|(v, w)| [v, w].concat())
                .collect::<Vec<_>>()
        };

        let pake_input = [
            alpha.compress().as_bytes().as_slice(),
            beta.compress().as_bytes().as_slice(),
            &tr.as_slice(),
        ]
        .concat();

        pake_input

        //todo!()
    }
}

#[cfg(test)]
mod test {
    use super::*;

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

        let mut user1 = Executor::new(&mut rng, pwfile1, ssid, id2, Role::Initiator);
        let mut user2 = Executor::new(&mut rng, pwfile2, ssid, id1, Role::Responder);

        let msg1 = user1.step_1(&mut rng);
        let msg2 = user2.step_1(&mut rng);

        let tmp_out1 = user1.step_2(&msg2);
        let tmp_out2 = user2.step_2(&msg1);

        assert_eq!(tmp_out1, tmp_out2);
    }
}
