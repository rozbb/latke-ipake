//! The [CHIP](https://eprint.iacr.org/2020/529.pdf) iPAKE. See Figure 6.

#![allow(non_snake_case)]

use crate::{Id, Pake, PartyRole, SessKey, Ssid};

use blake2::{digest::MacError, Blake2b512};
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoBasepointTable, RistrettoPoint},
    scalar::Scalar,
};
use hkdf::hmac::digest::{consts::U64, Digest};
use rand::{CryptoRng, RngCore};

/// The password file for the CHIP protocol
struct ChipPwFile {
    X: RistrettoPoint,
    Y: RistrettoPoint,
    xhat: Scalar,
}

impl ChipPwFile {
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

        ChipPwFile { X, Y, xhat }
    }
}

// The protocol is perfectly symmetric, so we can use the same struct for both roles.
struct Executor<R: RngCore + CryptoRng, P: Pake> {
    // The IBKE portion
    pwfile: ChipPwFile,
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

    next_step: usize,
}

impl<R: RngCore + CryptoRng, P: Pake> Executor<R, P> {
    fn new(mut rng: R, pwfile: ChipPwFile, ssid: Ssid, other_id: Id, role: PartyRole) -> Self {
        // The initiator does even steps, the responder does odd steps
        let next_step = if role == PartyRole::Initiator { 0 } else { 1 };

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

            next_step,
        }
    }

    /// The first step of the Fiore-Gennaro IBKE
    fn ibke_step_1(&mut self) -> Vec<u8> {
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

    /// The second step of the Fiore-Gennaro IBKE
    fn ibke_step_2(&mut self, msg: &[u8]) -> Vec<u8> {
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

    /// The all-in-one run function. This does the IBKE for the first two steps, then does the PAKE for the rest
    fn run(&mut self, incoming_msg: &[u8]) -> Result<Option<Vec<u8>>, P::Error> {
        // Remember the initiator does even steps and the responder does odd steps
        let out_msg = match self.next_step {
            0 => Some(self.ibke_step_1()),
            1 => {
                self.tr_recv.push(incoming_msg.to_vec());
                Some(self.ibke_step_1())
            }
            2 => {
                self.tr_recv.push(incoming_msg.to_vec());
                let ibke_out = self.ibke_step_2(incoming_msg);

                // Initialize the PAKE and send the first message
                let mut pake_state = P::new(&mut self.rng, PartyRole::Initiator, &ibke_out);
                let pake_msg = pake_state.run(&[])?;
                self.pake_state = Some(pake_state);

                pake_msg
            }
            3 => {
                let last_msg = self.tr_recv.last().cloned().unwrap();
                let ibke_out = self.ibke_step_2(&last_msg);

                // Initialize the PAKE, process the first message, and send the second
                let mut pake_state = P::new(&mut self.rng, PartyRole::Responder, &ibke_out);
                let pake_msg = pake_state.run(incoming_msg)?;
                self.pake_state = Some(pake_state);

                pake_msg
            }
            _ => self.pake_state.as_mut().unwrap().run(incoming_msg)?,
        };

        self.next_step += 2;
        Ok(out_msg)
    }

    /// Returns the final session key. Panics if it is called before the protocol successfully completes
    fn finalize(&self) -> SessKey {
        self.pake_state.as_ref().unwrap().finalize()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::kc_spake2::KcSpake2;

    use rand::Rng;

    #[test]
    fn chip_correctness() {
        let mut rng = rand::thread_rng();

        // Create random user IDs
        let id1 = rng.gen();
        let id2 = rng.gen();

        // Create a random session ID
        let ssid = rng.gen();

        let password = b"torque (construction noise) lewith";

        let pwfile1 = ChipPwFile::new(&mut rng, password.to_vec(), id1);
        let pwfile2 = ChipPwFile::new(&mut rng, password.to_vec(), id2);

        let mut user1 = Executor::<_, KcSpake2>::new(
            rand::thread_rng(),
            pwfile1,
            ssid,
            id2,
            PartyRole::Initiator,
        );
        let mut user2 = Executor::<_, KcSpake2>::new(
            rand::thread_rng(),
            pwfile2,
            ssid,
            id1,
            PartyRole::Responder,
        );

        // Run through the whole protocol
        let mut cur_step = 0;
        let mut cur_msg = Some(Vec::new());
        while cur_msg.is_some() {
            cur_msg = if cur_step % 2 == 0 {
                user1.run(&cur_msg.unwrap()).unwrap()
            } else {
                user2.run(&cur_msg.unwrap()).unwrap()
            };

            cur_step += 1;
        }

        // Check that the final keys are the same
        assert_eq!(user1.finalize(), user2.finalize());
    }
}
