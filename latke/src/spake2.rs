use crate::{Pake, PartyRole, SessKey};

use rand_core::{CryptoRng, RngCore};
use spake2::{Ed25519Group, Identity, Password, Spake2};

pub struct MySpake2 {
    pake_state: Option<spake2::Spake2<Ed25519Group>>,
    outgoing_msg: Vec<u8>,
    next_step: usize,
    key: Option<SessKey>,
}

impl Pake for MySpake2 {
    type Error = spake2::Error;

    fn new<R: RngCore + CryptoRng>(mut rng: R, role: PartyRole, password: &[u8]) -> Self {
        let (pake_state, outgoing_msg) = Spake2::<Ed25519Group>::start_symmetric_with_rng(
            &Password::new(password),
            &Identity::new(b"shared id"),
            &mut rng,
        );

        // The initiator does even steps, the responder does odd steps
        let next_step = if role == PartyRole::Initiator { 0 } else { 1 };

        Self {
            pake_state: Some(pake_state),
            outgoing_msg,
            next_step,
            key: None,
        }
    }

    fn run(&mut self, incoming_msg: &[u8]) -> Option<Vec<u8>> {
        let out = match self.next_step {
            // Send the first message
            0 => {
                assert_eq!(incoming_msg.len(), 0);
                Some(self.outgoing_msg.clone())
            }
            // Receive the first message, derive the session key, and send the second message
            1 => {
                let pake_state: Spake2<Ed25519Group> =
                    core::mem::replace(&mut self.pake_state, None).unwrap();
                let key = pake_state
                    .finish(&incoming_msg)
                    .unwrap()
                    .try_into()
                    .unwrap();
                self.key = Some(key);
                Some(self.outgoing_msg.clone())
            }
            // Receive the second message and derive the session key
            2 => {
                let pake_state: Spake2<Ed25519Group> =
                    core::mem::replace(&mut self.pake_state, None).unwrap();
                let key = pake_state
                    .finish(&incoming_msg)
                    .unwrap()
                    .try_into()
                    .unwrap();
                self.key = Some(key);
                None
            }
            _ => panic!("protocol already completed"),
        };

        // The initiator does even steps, the responder does odd steps
        self.next_step += 2;

        out
    }

    fn finalize(&self) -> Option<SessKey> {
        self.key
    }
}
