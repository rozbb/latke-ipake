//! Implements the [CHIP](https://eprint.iacr.org/2020/529) iPAKE protocol. See Figure 6.

#![allow(non_snake_case)]

use crate::{Id, MyHash512, Pake, PartyRole, SessKey, Ssid};

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use hkdf::hmac::digest::Digest;
use rand::{CryptoRng, RngCore};

/// The password file for the CHIP protocol
#[derive(Clone)]
pub struct ChipPwfile {
    X: RistrettoPoint,
    Y: RistrettoPoint,
    xhat: Scalar,
}

/// The [CHIP](https://eprint.iacr.org/2020/529) iPAKE protocol
// This is annoying: it is not straightforward to reuse the FgIbkeC protocol, since that has key confirmation, and CHIP doesn't require it. So we just implement all of CHIP from scratch.
pub struct Chip<P: Pake> {
    // The IBKE portion
    pwfile: ChipPwfile,
    ssid: Ssid,
    other_id: Id,
    role: PartyRole,
    r: Scalar,

    // The PAKE portion
    pake_state: Option<P>,

    /// The transcript of every message sent
    tr_sent: Vec<Vec<u8>>,
    /// The transcript of every message received
    tr_recv: Vec<Vec<u8>>,

    next_step: usize,
}

impl<P: Pake> Chip<P> {
    pub fn gen_pwfile<R: RngCore + CryptoRng>(mut rng: R, pw: Vec<u8>, id: Id) -> ChipPwfile {
        let x = Scalar::random(&mut rng);
        let y = Scalar::from_hash(MyHash512::new().chain_update([0x01]).chain_update(pw));

        let X = RistrettoPoint::mul_base(&x);
        let Y = RistrettoPoint::mul_base(&y);
        let h = Scalar::from_hash(
            MyHash512::new()
                .chain_update([0x02])
                .chain_update(&id)
                .chain_update(X.compress().as_bytes()),
        );
        let xhat = x + h * y;

        ChipPwfile { X, Y, xhat }
    }

    pub fn new_session<R: RngCore + CryptoRng>(
        mut rng: R,
        ssid: Ssid,
        pwfile: ChipPwfile,
        role: PartyRole,
        other_id: Id,
    ) -> Self {
        // The initiator does even steps, the responder does odd steps
        let next_step = if role == PartyRole::Initiator { 0 } else { 1 };

        Chip {
            pwfile,
            ssid,
            other_id,
            role,
            r: Scalar::random(&mut rng),
            pake_state: None,
            tr_sent: Vec::new(),
            tr_recv: Vec::new(),

            next_step,
        }
    }

    /// The all-in-one run function. This does the IBKE for the first two steps, then does the PAKE for the rest
    pub fn run<R: RngCore + CryptoRng>(
        &mut self,
        mut rng: R,
        incoming_msg: &[u8],
    ) -> Result<Option<Vec<u8>>, P::Error> {
        // Remember the initiator does even steps and the responder does odd steps
        let out_msg = match self.next_step {
            0 => Some(self.ibke_step_1(&mut rng)),
            1 => {
                self.tr_recv.push(incoming_msg.to_vec());
                Some(self.ibke_step_1(&mut rng))
            }
            2 => {
                self.tr_recv.push(incoming_msg.to_vec());
                let ibke_out = self.ibke_step_2(incoming_msg);

                // Initialize the PAKE and send the first message
                let mut pake_state = P::new(&mut rng, self.ssid, &ibke_out, PartyRole::Initiator);
                let pake_msg = pake_state.run(&[])?;
                self.pake_state = Some(pake_state);

                pake_msg
            }
            3 => {
                let last_msg = self.tr_recv.last().cloned().unwrap();
                let ibke_out = self.ibke_step_2(&last_msg);

                // Initialize the PAKE, process the first message, and send the second
                let mut pake_state = P::new(&mut rng, self.ssid, &ibke_out, PartyRole::Responder);
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
    pub fn finalize(&self) -> SessKey {
        self.pake_state.as_ref().unwrap().finalize()
    }

    /// The first step of the Fiore-Gennaro IBKE
    fn ibke_step_1<R: RngCore + CryptoRng>(&mut self, mut rng: R) -> Vec<u8> {
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
            MyHash512::new()
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
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::pake::kc_spake2::KcSpake2;

    use rand::Rng;

    #[test]
    fn chip_correctness() {
        type C = Chip<KcSpake2>;
        let mut rng = rand::thread_rng();

        // Create random user IDs
        let id1 = rng.gen();
        let id2 = rng.gen();

        // Create a random session ID
        let ssid = rng.gen();

        let password = b"torque (construction noise) lewith";

        let pwfile1 = C::gen_pwfile(&mut rng, password.to_vec(), id1);
        let pwfile2 = C::gen_pwfile(&mut rng, password.to_vec(), id2);

        let mut user1 = C::new_session(&mut rng, ssid, pwfile1, PartyRole::Initiator, id2);
        let mut user2 = C::new_session(&mut rng, ssid, pwfile2, PartyRole::Responder, id1);

        // Run through the whole protocol
        let mut cur_step = 0;
        let mut cur_msg = Some(Vec::new());
        while cur_msg.is_some() {
            cur_msg = if cur_step % 2 == 0 {
                user1.run(&mut rng, &cur_msg.unwrap()).unwrap()
            } else {
                user2.run(&mut rng, &cur_msg.unwrap()).unwrap()
            };

            cur_step += 1;
        }

        // Check that the final keys are the same
        assert_eq!(user1.finalize(), user2.finalize());
    }
}
