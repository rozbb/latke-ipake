use blake2::{Blake2b, Blake2b512};
use hkdf::{
    hmac::{digest::consts::U32, SimpleHmac},
    SimpleHkdf, SimpleHkdfExtract,
};
use rand_core::{CryptoRng, RngCore};

mod auth_enc;
pub mod cake;
pub mod chip;
mod eue_transform;
pub mod id_hmqv_c;
pub mod id_sig_dh;
pub mod id_sigma_r;
pub mod kc_spake2;
pub mod latke;

pub(crate) type MyHash256 = Blake2b<U32>;
pub(crate) type MyHash512 = Blake2b512;
pub(crate) type MyKdf = SimpleHkdf<MyHash256>;
pub(crate) type MyKdfExtract = SimpleHkdfExtract<MyHash256>;
pub(crate) type MyMac = SimpleHmac<MyHash256>;

/// ID strings are any bytestring. We'll limit it to 32 bytes here.
pub type Id = [u8; 32];

/// Subsession ID is some unique identifier
pub type Ssid = [u8; 32];

/// A nonce for replay protection
pub type Nonce = [u8; 32];

/// The final key of a PAKE session
pub type SessKey = [u8; 32];

/// The role of a party in a 2-party protocol
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PartyRole {
    Initiator,
    Responder,
}

/// A trait representing a PAKE protocol
pub trait Pake {
    type Error: core::fmt::Debug;

    /// Makes a new PAKE session
    fn new<R: RngCore + CryptoRng>(rng: R, ssid: Ssid, password: &[u8], role: PartyRole) -> Self;

    /// Runs the next step of the algorithm, given the previous message. If this is the first step of the initiator, then `msg` MUST be `[]`.
    /// Returns the next message to send, or `Ok(None)` if the protocol successfully completed.
    fn run(&mut self, msg: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Returns whether the protocol has completed
    fn is_done(&self) -> bool;

    /// Returns the session key if the protocol successfully completed. Panics otherwise.
    fn finalize(&self) -> SessKey;
}

/// An identity based key exchange protocol in the style of the AKE-to-IBKE transform described in LATKE.
/// The only thing of note is that users generate their own user keypair, and `extract` takes the user public key as auxiliary data.
pub trait IdentityBasedKeyExchange {
    type MainPubkey: Clone + AsBytes;
    type MainPrivkey;
    type UserPubkey;
    type UserPrivkey: Clone;
    type Certificate: Clone;
    type Error: core::fmt::Debug;

    /// Generates the main keypair for the key generation center (KGC)
    fn gen_main_keypair<R: RngCore + CryptoRng>(rng: R) -> (Self::MainPubkey, Self::MainPrivkey);

    /// Generates a user keypair. The public part of this is given to the KGC for extraction
    fn gen_user_keypair<R: RngCore + CryptoRng>(rng: R) -> (Self::UserPubkey, Self::UserPrivkey);

    /// Extracts a certificate for the given identity and user public key
    fn extract(msk: &Self::MainPrivkey, id: &Id, upk: &Self::UserPubkey) -> Self::Certificate;

    /// Begins a new session with a given SSID
    fn new_session<R: RngCore + CryptoRng>(
        rng: R,
        ssid: Ssid,
        mpk: Self::MainPubkey,
        cert: Self::Certificate,
        usk: Self::UserPrivkey,
        role: PartyRole,
    ) -> Self;

    /// Runs the next step of the protocol. `incoming_msg` MUST be empty for the first step.
    fn run<R: RngCore + CryptoRng>(
        &mut self,
        rng: R,
        incoming_msg: &[u8],
    ) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Simulates running the next step of the protocol. This returns the size of the message that would be sent, and internally updates the state to the next step
    fn run_sim(&mut self) -> Option<usize>;

    /// Returns whether the protocol has completed. The protocol counts as completed if either the last `run` OR `run_sim` has executed
    fn is_done(&self) -> bool;

    /// Finalizes the protocol and returns the session key and the ID of the other party
    fn finalize(&self) -> (Id, SessKey);
}

pub trait AsBytes {
    fn as_bytes(&self) -> &[u8];
}
