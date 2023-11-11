use rand_core::RngCore;
use saber::firesaber::{
    decapsulate_ind_cpa as kem_decap, encapsulate_ind_cpa as kem_encap,
    keygen_ind_cpa as kem_keygen,
};
