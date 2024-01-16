//! Implements the KC-SPAKE2 PAKE by [Shoup](https://eprint.iacr.org/2020/313)
use crate::{MyKdf, MyMac, Pake, PartyRole, SessKey, Ssid};

use blake2::digest::{MacError, OutputSizeUser};
use hkdf::hmac::digest::typenum::Unsigned;
use rand_core::{CryptoRng, RngCore};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use subtle::ConstantTimeEq;

pub const PROTO_ID: &[u8] = b"latke_kc_spake2";

/// The KC-SPAKE2 PAKE by [Shoup](https://eprint.iacr.org/2020/313)
pub struct KcSpake2 {
    /// The underlying SPAKE2 protocol. KC-SPAKE2 is basically this plus 2 MACs
    pake_state: Option<spake2::Spake2<Ed25519Group>>,
    // We need to store this because creating a SPAKE2 state immediately creates the first message
    first_outgoing_message: Vec<u8>,
    next_step: usize,
    done: bool,
    /// The output of this PAKE
    output_key: Option<SessKey>,
    /// The two MACs over the transcript
    macs: Option<([u8; 32], [u8; 32])>,
    password: Vec<u8>,
}

impl Pake for KcSpake2 {
    type Error = MacError;

    fn new<R: RngCore + CryptoRng>(
        mut rng: R,
        ssid: Ssid,
        password: &[u8],
        role: PartyRole,
    ) -> Self {
        let (pake_state, outgoing_msg) = Spake2::<Ed25519Group>::start_symmetric_with_rng(
            &Password::new(password),
            &Identity::new(&ssid),
            &mut rng,
        );

        // The initiator does even steps, the responder does odd steps
        let next_step = if role == PartyRole::Initiator { 0 } else { 1 };

        Self {
            pake_state: Some(pake_state),
            first_outgoing_message: outgoing_msg,
            next_step,
            done: false,
            output_key: None,
            macs: None,
            password: password.to_vec(),
        }
    }

    fn is_done(&self) -> bool {
        self.done
    }

    fn run(&mut self, incoming_msg: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        let out = match self.next_step {
            // Send the first message
            0 => {
                assert_eq!(incoming_msg.len(), 0);
                Some(self.first_outgoing_message.clone())
            }
            // Receive the first message, derive the session key, and send the second message (my first outgoing message)
            1 => {
                let pake_state: Spake2<Ed25519Group> =
                    core::mem::replace(&mut self.pake_state, None).unwrap();
                let pake_key = pake_state.finish(&incoming_msg).unwrap();

                // Out PAKE msg is the message computed in the constructor
                let out_msg = self.first_outgoing_message.clone();

                // From the PAKE key, derive the final session key and two MACs over the transcript
                let mut sess_hash = [0u8; 64 + core::mem::size_of::<SessKey>()];
                let hk = MyKdf::from_prk(&pake_key).unwrap();
                hk.expand_multi_info(
                    &[&self.password, PROTO_ID, incoming_msg, &out_msg, &pake_key],
                    &mut sess_hash,
                )
                .unwrap();

                // Unpack the big output and assign it properly
                let (macs, output_key) = sess_hash.split_at(64);
                let (mac0, mac1) = macs.split_at(32);
                self.macs = Some((mac0.try_into().unwrap(), mac1.try_into().unwrap()));
                self.output_key = Some(output_key.try_into().unwrap());

                // Send (pake_msg, mac1)
                Some([&out_msg, mac1].concat())
            }
            // Receive the second message and derive the session key
            2 => {
                // Deserialize the incoming message as (pake_msg, mac)
                let (incoming_pake_msg, incoming_mac1) = incoming_msg
                    .split_at(incoming_msg.len() - <MyMac as OutputSizeUser>::OutputSize::USIZE);

                // Finish the key negotiation of ht PAKE
                let pake_state: Spake2<Ed25519Group> =
                    core::mem::replace(&mut self.pake_state, None).unwrap();
                let pake_key = pake_state.finish(&incoming_pake_msg).unwrap();

                // From the PAKE key, derive the final session key and two MACs over the transcript
                let mut sess_hash = [0u8; 64 + core::mem::size_of::<SessKey>()];
                let hk = MyKdf::from_prk(&pake_key).unwrap();
                hk.expand_multi_info(
                    &[
                        &self.password,
                        PROTO_ID,
                        &self.first_outgoing_message,
                        &incoming_pake_msg,
                        &pake_key,
                    ],
                    &mut sess_hash,
                )
                .unwrap();

                // Unpack the big output and assign it properly
                let (macs, output_key) = sess_hash.split_at(64);
                let (mac0, mac1) = macs.split_at(32);
                self.macs = Some((mac0.try_into().unwrap(), mac1.try_into().unwrap()));
                self.output_key = Some(output_key.try_into().unwrap());

                // Verify the MAC
                if !bool::from(mac1.ct_eq(&incoming_mac1)) {
                    return Err(MacError);
                }

                // After sending this, we're done
                self.done = true;

                // Send the MAC
                Some(mac0.to_vec())
            }
            // Receive the MAC and verify it
            3 => {
                let incoming_mac0 = incoming_msg;
                if !bool::from(self.macs.unwrap().0.ct_eq(&incoming_mac0)) {
                    return Err(MacError);
                }

                self.done = true;

                None
            }
            _ => panic!("protocol already completed"),
        };

        // The initiator does even steps, the responder does odd steps
        self.next_step += 2;

        Ok(out)
    }

    fn finalize(&self) -> SessKey {
        self.output_key.unwrap()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use rand::{thread_rng, Rng};

    #[test]
    fn kc_spake2_correctness() {
        let mut rng = thread_rng();

        let ssid = rng.gen();

        let mut user1 = KcSpake2::new(&mut rng, ssid, b"password", PartyRole::Initiator);
        let mut user2 = KcSpake2::new(&mut rng, ssid, b"password", PartyRole::Responder);

        let msg1 = user1.run(&[]).unwrap().unwrap();
        let msg2 = user2.run(&msg1).unwrap().unwrap();
        let msg3 = user1.run(&msg2).unwrap().unwrap();
        let msg4 = user2.run(&msg3).unwrap();

        // Check that the protocol is over
        assert!(msg4.is_none());
        assert!(user1.is_done());
        assert!(user2.is_done());

        // Check that the session keys are the same
        assert_eq!(user1.finalize(), user2.finalize());
    }
}
