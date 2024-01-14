use crate::{
    eue_transform::Eue, AsBytes, Id, IdentityBasedKeyExchange, MyHash256, Pake, PartyRole, SessKey,
    Ssid,
};

use hkdf::hmac::digest::Digest;
use rand_chacha::ChaCha8Rng as MyRng;
use rand_core::{CryptoRng, RngCore, SeedableRng};

struct Latke<I: IdentityBasedKeyExchange, P: Pake> {
    ssid: Ssid,
    pwfile: Pwfile<I>,
    role: PartyRole,

    pake_state: P,
    ibke_state: Option<Eue<I>>,

    _marker: core::marker::PhantomData<(I, P)>,
}

struct Pwfile<I: IdentityBasedKeyExchange> {
    mpk: I::MainPubkey,
    cert: I::Certificate,
    usk: I::UserPrivkey,
}

impl<I: IdentityBasedKeyExchange, P: Pake> Latke<I, P> {
    pub fn gen_pwfile<R: RngCore + CryptoRng>(mut rng: R, password: &[u8], id: &Id) -> Pwfile<I> {
        // Use the password to generate the main keypair
        let seed = MyHash256::digest(password);
        let mut pw_based_rng = MyRng::from_seed(seed.into());
        let (mpk, msk) = I::gen_main_keypair(&mut pw_based_rng);

        // Generate a user keypair using a real RNG
        let (upk, usk) = I::gen_user_keypair(&mut rng);
        // Extract the certificate
        let cert = I::extract(&msk, id, &upk);

        Pwfile { mpk, cert, usk }
    }

    pub fn new_session<R: RngCore + CryptoRng>(
        mut rng: R,
        ssid: Ssid,
        pwfile: Pwfile<I>,
        role: PartyRole,
    ) -> Self {
        // Start the PAKE over self.mpk
        let pake_state = P::new(&mut rng, ssid, pwfile.mpk.as_bytes(), role);

        Self {
            ssid,
            pwfile,
            role,
            pake_state,
            ibke_state: None,
            _marker: core::marker::PhantomData,
        }
    }

    pub fn run<R: CryptoRng + RngCore>(
        &mut self,
        mut rng: R,
        incoming_msg: &[u8],
    ) -> Option<Vec<u8>> {
        // If the PAKE isn't done, run it
        if !self.pake_state.is_done() {
            self.pake_state.run(incoming_msg).unwrap()
        } else {
            // Initialize the encrypted IBKE if it hasn't been initialized yet
            if self.ibke_state.is_none() {
                let eue_key = self.pake_state.finalize();
                self.ibke_state = Some(Eue::<I>::new_session(
                    &mut rng,
                    self.ssid,
                    self.pwfile.mpk.clone(),
                    self.pwfile.cert.clone(),
                    self.pwfile.usk.clone(),
                    self.role,
                    eue_key,
                ));
            }

            // Run the encrypted IBKE
            self.ibke_state
                .as_mut()
                .unwrap()
                .run(&mut rng, incoming_msg)
                .unwrap()
        }
    }

    pub fn is_done(&self) -> bool {
        // We are done once the IBKE is done
        self.ibke_state
            .as_ref()
            .map(|ibke| ibke.is_done())
            .unwrap_or(false)
    }

    pub fn finalize(&self) -> (Id, SessKey) {
        self.ibke_state.as_ref().unwrap().finalize()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cake::Cake;
    use crate::id_sigma_r::IdSigmaR;
    use crate::kc_spake2::KcSpake2;
    use crate::sig_dh::IdSigDh;

    use rand::Rng;

    #[test]
    fn latke_correctness() {
        type L = Latke<IdSigDh, KcSpake2>;
        //type L = Latke<IdSigmaR, Cake>;
        let mut rng = rand::thread_rng();

        let id1 = rng.gen();
        let id2 = rng.gen();
        let ssid = rng.gen();

        let pwfile1 = L::gen_pwfile(&mut rng, b"password", &id1);
        let pwfile2 = L::gen_pwfile(&mut rng, b"password", &id2);

        let mut user1 = L::new_session(&mut rng, ssid, pwfile1, PartyRole::Initiator);
        let mut user2 = L::new_session(&mut rng, ssid, pwfile2, PartyRole::Responder);

        // Run through the whole protocol
        let mut cur_step = 0;
        let mut cur_msg = Vec::new();
        loop {
            let user = if cur_step % 2 == 0 {
                &mut user1
            } else {
                &mut user2
            };

            if user.is_done() {
                // If it's this user's turn to talk, and it's done, then the whole protocol is done
                break;
            } else {
                cur_msg = user.run(&mut rng, &cur_msg).unwrap_or(Vec::new());
            }

            cur_step += 1;
        }

        let (user1_interlocutor, user1_key) = user1.finalize();
        let (user2_interlocutor, user2_key) = user2.finalize();

        // Check that the users agree on the interlocutor and the session key
        assert!(user1_interlocutor == id2);
        assert!(user2_interlocutor == id1);
        assert_eq!(user1_key, user2_key);
    }
}
