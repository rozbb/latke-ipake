pub mod cake;
pub mod chip;
pub mod id_hiding_ake;

/// ID strings are any bytestring. We'll limit it to 32 bytes here.
pub type Id = [u8; 32];

/// Subsession ID is some unique identifier
pub type Ssid = [u8; 32];

/// The final key of a PAKE session
pub type SessKey = [u8; 32];
