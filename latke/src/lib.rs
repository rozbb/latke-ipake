use rand_core::{CryptoRng, RngCore};

pub mod cake;
pub mod chip;
pub mod id_hiding_ake;
pub mod spake2;

/// ID strings are any bytestring. We'll limit it to 32 bytes here.
pub type Id = [u8; 32];

/// Subsession ID is some unique identifier
pub type Ssid = [u8; 32];

/// The final key of a PAKE session
pub type SessKey = [u8; 32];

/// The role of a party in a 2-party protocol
#[derive(PartialEq, Eq)]
enum PartyRole {
    Initiator,
    Responder,
}

/// A trait representing a PAKE protocol
trait Pake {
    type Error;

    /// Makes a new PAKE session
    fn new<R: RngCore + CryptoRng>(rng: R, role: PartyRole, password: &[u8]) -> Self;

    /// Runs the next step of the algorithm, given the previous message. If this is the first step of the initiator, then `msg` MUST be `[]`.
    /// Returns the next message to send, or `None` if the protocol is finished.
    fn run(&mut self, msg: &[u8]) -> Option<Vec<u8>>;

    /// Returns the session key if the protocol completed, or `None` otherwise.
    fn finalize(&self) -> Option<SessKey>;
}
