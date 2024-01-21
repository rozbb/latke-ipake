use rand_core::{CryptoRng, RngCore};

use crate::{
    auth_enc::{auth_decrypt, auth_encrypt, AuthEncKey, ZERO_AUTH_ENC_KEY},
    Id, IdentityBasedKeyExchange, MyKdf, PartyRole, SessKey, Ssid,
};

/// The Encrypt-and-Unconditionally-Execute (EUE) transform from LATKE. This takes an IBKE and an encryption key and produces a new IBKE whose messages are all encrypted.
pub(crate) struct Eue<I>
where
    I: IdentityBasedKeyExchange,
{
    /// The key used to encrypt/decrypt the next message in the protocol
    msg_key: AuthEncKey,
    /// The key used to derive the next message and chain keys
    chain_key: [u8; 32],
    sess: I,
    /// Indicates whether this user is the initiator and has not begun. Used to know when to ratchet
    next_step_is_first: bool,
    /// Whether we're in real mode or not. If not in real mode, we just encrypt the appropriate number of zeros in both directions
    real_mode: bool,
    _marker: core::marker::PhantomData<I>,
}

impl<I: IdentityBasedKeyExchange> Eue<I> {
    /// Ratchets forward the chain key to the next generation of chain and message keys
    fn ratchet_keys(&mut self) {
        let hk = MyKdf::from_prk(&self.chain_key).unwrap();
        hk.expand(b"chain key", &mut self.chain_key).unwrap();
        hk.expand(b"msg key", &mut self.msg_key).unwrap();
    }

    pub fn new_session<R: RngCore + CryptoRng>(
        rng: R,
        ssid: Ssid,
        mpk: I::MainPubkey,
        cert: I::Certificate,
        usk: I::UserPrivkey,
        role: PartyRole,
        initial_key: [u8; 32],
    ) -> Self {
        // Start the new underlying session
        let sess = I::new_session(rng, ssid, mpk, cert, usk, role);

        // Derive the initial chain key and message keys
        let mut chain_key = [0u8; 32];
        let mut msg_key = ZERO_AUTH_ENC_KEY;
        let hk = MyKdf::from_prk(&initial_key).unwrap();
        hk.expand_multi_info(&[&b"init chain key"[..], &ssid[..]], &mut chain_key)
            .unwrap();
        hk.expand_multi_info(&[&b"init msg key"[..], &ssid[..]], &mut msg_key)
            .unwrap();

        let next_step_is_first = role == PartyRole::Initiator;

        Self {
            msg_key,
            chain_key,
            sess,
            next_step_is_first,
            real_mode: true,
            _marker: core::marker::PhantomData,
        }
    }

    pub fn is_done(&self) -> bool {
        self.sess.is_done()
    }

    pub fn run<R: RngCore + CryptoRng>(
        &mut self,
        mut rng: R,
        incoming_ciphertext: &[u8],
    ) -> Result<Option<Vec<u8>>, I::Error> {
        // Decrypt the incoming ciphertext if there is any and we're in real mode
        let incoming_msg = if incoming_ciphertext.len() > 0 && self.real_mode {
            let pt = auth_decrypt(self.msg_key, incoming_ciphertext);
            assert!(pt.is_ok());
            // If a decryption error occurred, we exit real mode and will just start sending zeros
            if pt.is_err() {
                self.real_mode = false;
                None
            } else {
                Some(pt.unwrap())
            }
        } else {
            // If the ciphertext is empty or we're not in real mode, then the message is empty or it doesn't matter. Set it to empty
            Some(Vec::new())
        };

        // If this isn't the very first step of the protocol, ratchet the keys
        if !self.next_step_is_first {
            self.ratchet_keys();
        } else {
            // Otherwise, don't ratchet the keys, and mark the protocol begun.
            self.next_step_is_first = false;
        };

        // Either run the underlying IBKE or simulate it and make the appropriate number of zeros
        let outgoing_msg = if self.real_mode {
            self.sess.run(&mut rng, &incoming_msg.unwrap())?
        } else {
            let msg_size = self.sess.run_sim();
            msg_size.map(|s| vec![0u8; s])
        };

        // Encrypt the outgoing message if there is one
        let outgoing_ciphertext = outgoing_msg.map(|m| {
            if m.len() > 0 {
                auth_encrypt(&mut rng, self.msg_key, &m)
            } else {
                Vec::new()
            }
        });

        // Ratchet the keys
        self.ratchet_keys();

        Ok(outgoing_ciphertext)
    }

    pub fn finalize(&self) -> (Id, SessKey) {
        self.sess.finalize()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ibke::id_sigma_r::IdSigmaREd25519;

    use rand::Rng;

    // Test the EUE transform when applied to the ID-SIGMA-R protocol
    #[test]
    fn eue_sigma_r_correctness() {
        type EueSigmaR = Eue<IdSigmaREd25519>;

        let mut rng = rand::thread_rng();

        // Generate the KGC keypair
        let (mpk, msk) = IdSigmaREd25519::gen_main_keypair(&mut rng);

        // Pick the user IDs randomly
        let id1 = rng.gen();
        let id2 = rng.gen();

        // Have the users generate their keypairs
        let (upk1, usk1) = IdSigmaREd25519::gen_user_keypair(&mut rng);
        let (upk2, usk2) = IdSigmaREd25519::gen_user_keypair(&mut rng);

        // Have the KGC sign the user's pubkeys
        let cert1 = IdSigmaREd25519::extract(&mut rng, &msk, &id1, &upk1);
        let cert2 = IdSigmaREd25519::extract(&mut rng, &msk, &id2, &upk2);

        // Start a new session with a random initial key
        let initial_key = rng.gen();
        let ssid = rng.gen();
        let mut user1 = EueSigmaR::new_session(
            &mut rng,
            ssid,
            mpk.clone(),
            cert1,
            usk1,
            PartyRole::Initiator,
            initial_key,
        );
        let mut user2 = EueSigmaR::new_session(
            &mut rng,
            ssid,
            mpk.clone(),
            cert2,
            usk2,
            PartyRole::Responder,
            initial_key,
        );

        // Run the session until completion
        let msg1 = user1.run(&mut rng, &[]).unwrap().unwrap();
        let msg2 = user2.run(&mut rng, &msg1).unwrap().unwrap();
        let msg3 = user1.run(&mut rng, &msg2).unwrap().unwrap();
        let msg4 = user2.run(&mut rng, &msg3).unwrap().unwrap();
        let msg5 = user1.run(&mut rng, &msg4).unwrap();

        let (user1_interlocutor, user1_key) = user1.finalize();
        let (user2_interlocutor, user2_key) = user2.finalize();

        // Ensure that there are no more messages to be sent, that the parties believe they're talking to each other, and that they have the same key
        assert!(msg5.is_none());
        assert!(user1_interlocutor == id2);
        assert!(user2_interlocutor == id1);
        assert_eq!(user1_key, user2_key);
    }
}
