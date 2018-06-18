#include <amcl/src/ecdh_NIST.h>
#include <xtt.h>
#include <xtt/crypto_wrapper.h>


int xtt_crypto_create_ecdsap256(csprng *rng, octet* priv_key, octet* pub_key) {
    int out = ECP_NIST256_KEY_PAIR_GENERATE(rng, priv_key, pub_key);
    return out;
}

int xtt_crypto_sign_ecdsap256(int hashtype, csprng *rng, octet *ephem_key, octet *priv_sign_key_in, octet *msg_in, octet *c_comp, octet *d_comp){
    int out = ECP_NIST256_SP_DSA(hashtype, rng, ephem_key, priv_sign_key_in, msg_in, c_comp, d_comp);
    return out;
}

int xtt_crypto_verify_ecdsap256(int hashtype, octet *pub_key_in, octet *msg_in, octet *c_comp, octet *d_comp){
    int out = -1;
    if(0 == ECP_NIST256_PUBLIC_KEY_VALIDATE(pub_key_in)){
        out = ECP_NIST256_VP_DSA(hashtype, pub_key_in, msg_in, c_comp, d_comp);
    }
    return out;
}
