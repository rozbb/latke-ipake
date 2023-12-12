use pqcrypto_dilithium::dilithium5::{
    keypair as gen_sig_keypair, PublicKey as SigPubkey, SecretKey as SigPrivkey,
};

struct AkeInitiator {
    upk: SigPubkey,
    usk: SigPrivkey,
}

impl Default for AkeInitiator {
    fn default() -> Self {
        let (upk, usk) = gen_sig_keypair();
        AkeInitiator { upk, usk }
    }
}

impl AkeInitiator {
    fn new(upk: SigPubkey, usk: SigPrivkey) -> Self {
        AkeInitiator { upk, usk }
    }
}
