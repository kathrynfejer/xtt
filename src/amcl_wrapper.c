#include <amcl/include/amcl.h>
#include <xtt.h>
#include <xtt/crypto_wrapper.h>


int xtt_crypto_create_ecdsap256(xtt_x25519_pub_key *pub_key, xtt_x25519_priv_key *priv_key) {
    //passing NULL pointer instead of csprng and use randombytes_buf
    unsigned char* nullptr = NULL;
    xtt_crypto_get_random(buffer, sizeof(buffer));
    struct octet pub;
    pub.val = pub_key->data;
    pub.len = sizeof(pub_key->data);
    struct octet priv;
    randombytes_buf(priv->data, sizeof(xtt_x25519_priv_key));
    priv.val = priv_key->data;
    priv.len = sizeof(priv_key->data);

    int out = ECP_NIST256_KEY_PAIR_GENERATE(nullptr, priv, pub);

    return out;

}

int xtt_crypto_sign_ecdsap256(unsigned char* signature_out,
                            const unsigned char* msg,
                            uint16_t msg_len,
                            const xtt_ed25519_priv_key* priv_key){
    unsigned char* nullptr = NULL;
    struct octet msg_in = {.val = {msg}};
    struct octet priv_sign_key_in = {.val = {priv_key->add_data}};
    struct octet ephem_key;
    int out = ECP_NIST256_SP_DSA(SHA512, nullptr, ephem_key, priv_sign_key_in, msg_in, c_comp, d_comp);
    return out;
}

int xtt_crypto_verify_ecdsap256(const unsigned char* signature,
                              const unsigned char* msg,
                              uint16_t msg_len,
                              const xtt_ed25519_pub_key* pub_key){
    struct octet pub
    int out = -1;
    if(0 == ECP_NIST256_PUBLIC_KEY_VALIDATE(pub_key_in)){
        out = ECP_NIST256_VP_DSA(SHA512, pub_key_in, msg_in, c_comp, d_comp);
    }
    return out;
}
