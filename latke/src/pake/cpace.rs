//! Implements the CPace PAKE by [Haase and Labrique](https://eprint.iacr.org/2018/286)

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use pake_cpace::{CPace, Step1Out};
use rand_core::{CryptoRng, RngCore};

use crate::{Pake, PartyRole, SessKey, Ssid};

pub const PROTO_ID_INIT: &str = "latke_cpace_initiator";
pub const PROTO_ID_RESP: &str = "latke_cpace_responder";

pub struct Cpace {
    step1_state: Option<Step1Out>,
    next_step: usize,
    done: bool,
    /// The output of this PAKE
    output_key: Option<SessKey>,
    ssid: Ssid,
    // Yes the CPace crate uses Strings for passwords. Whatever
    password: String,
}

impl Pake for Cpace {
    type Error = ();

    fn new<R: RngCore + CryptoRng>(_: R, ssid: Ssid, password: &[u8], role: PartyRole) -> Self {
        // The initiator does even steps, the responder does odd steps
        let next_step = if role == PartyRole::Initiator { 0 } else { 1 };

        // The password might not be a valid UTF-8 string, but CPace requires it to be
        // So encode it to b64
        let password = BASE64_STANDARD.encode(&password);

        Self {
            step1_state: None,
            next_step,
            done: false,
            output_key: None,
            ssid,
            password,
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
                // Make a new CPace initiator and generate the first message
                let client = CPace::step1(
                    &self.password,
                    PROTO_ID_INIT,
                    PROTO_ID_RESP,
                    Some(self.ssid),
                )
                .unwrap();
                let out_msg = client.packet();
                self.step1_state = Some(client);

                Some(out_msg.to_vec())
            }
            // Receive the first message, derive the session key, and send the second message (my first outgoing message)
            1 => {
                // Process the first message
                let packet = incoming_msg.try_into().unwrap();
                let st = CPace::step2(
                    &packet,
                    &self.password,
                    PROTO_ID_INIT,
                    PROTO_ID_RESP,
                    Some(self.ssid),
                )
                .unwrap();

                // Derive the second message and the session key
                self.output_key = Some(st.shared_keys().k1);
                let out_msg = st.packet();

                // After sending this, we're done
                self.done = true;

                Some(out_msg.to_vec())
            }
            // Receive the second message and derive the session key
            2 => {
                // Process the second
                let packet = incoming_msg.try_into().unwrap();
                let shared_keys = self.step1_state.as_ref().unwrap().step3(&packet).unwrap();

                // Derive the session key
                self.output_key = Some(shared_keys.k1);

                // All done
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
    fn cpace_correctness() {
        let mut rng = thread_rng();

        let ssid = rng.gen();

        let mut user1 = Cpace::new(&mut rng, ssid, b"password", PartyRole::Initiator);
        let mut user2 = Cpace::new(&mut rng, ssid, b"password", PartyRole::Responder);

        let msg1 = user1.run(&[]).unwrap().unwrap();
        let msg2 = user2.run(&msg1).unwrap().unwrap();
        let msg3 = user1.run(&msg2).unwrap();

        // Check that the protocol is over
        assert!(msg3.is_none());
        assert!(user1.is_done());
        assert!(user2.is_done());

        // Check that the session keys are the same
        assert_eq!(user1.finalize(), user2.finalize());
    }
}
