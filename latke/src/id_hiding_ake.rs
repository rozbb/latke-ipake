use pqcrypto_dilithium::dilithium2::{
    keypair_det as gen_sig_keypair, KeygenCoins, PublicKey as SigPubkey, SecretKey as SigPrivkey,
};
use rand::Rng;

struct AkeInitiator {
    upk: SigPubkey,
    usk: SigPrivkey,
}

impl Default for AkeInitiator {
    fn default() -> Self {
        let mut rng = rand::thread_rng();
        let coins: KeygenCoins = rng.gen();
        let (upk, usk) = gen_sig_keypair(coins);
        AkeInitiator { upk, usk }
    }
}

impl AkeInitiator {
    fn new(upk: SigPubkey, usk: SigPrivkey) -> Self {
        AkeInitiator { upk, usk }
    }
}
