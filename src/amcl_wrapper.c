#include <../../amcl/include/ecdh_NIST256.h>
#include <sodium.h>
#include <xtt.h>
#include <xtt/crypto_wrapper.h>
#include <assert.h>

int xtt_crypto_create_ecdsap256(xtt_ed25519_pub_key *pub_key, xtt_ed25519_priv_key *priv_key) {
    assert(sizeof(xtt_ed25519_pub_key) == 1+2*EFS_NIST256);
    xtt_crypto_get_random(priv_key->data, sizeof(xtt_ed25519_priv_key));
    octet pub = {0, sizeof(xtt_ed25519_pub_key), (char*)pub_key->data};
    octet priv = {sizeof(xtt_ed25519_priv_key), sizeof(xtt_ed25519_priv_key), (char*)priv_key->data};
    int out = ECP_NIST256_KEY_PAIR_GENERATE(NULL, &priv, &pub);
    return out;
}

int xtt_crypto_sign_ecdsap256(unsigned char* signature_out,
                            const unsigned char* msg,
                            uint16_t msg_len,
                            const xtt_ed25519_priv_key* priv_key){
    assert(sizeof(xtt_ed25519_signature) == 2*EGS_NIST256);
    octet msg_in = {.val = (char*)msg, .len = msg_len};
    octet priv_sign_key_in = {.val = (char*)priv_key->data};
    char ephem_key_buffer[sizeof(xtt_ed25519_priv_key)];
    octet ephem_key = {.val = ephem_key_buffer};

    xtt_crypto_get_random((unsigned char*)ephem_key.val, sizeof(xtt_ed25519_priv_key));
    octet c_comp = {.val = (char *)&signature_out[0]};
    octet d_comp = {.val = (char *)&signature_out[EGS_NIST256]};
    int out = ECP_NIST256_SP_DSA(SHA256, NULL, &ephem_key, &priv_sign_key_in, &msg_in, &c_comp, &d_comp);
    return out;
}

int xtt_crypto_verify_ecdsap256(const unsigned char* signature,
                              const unsigned char* msg,
                              uint16_t msg_len,
                              const xtt_ed25519_pub_key* pub_key){
    octet pub = {0, sizeof(xtt_ed25519_pub_key), (char*)pub_key->data};
    octet msg_in = {.val = (char*)msg, .len = msg_len};
    octet c_comp = {.val = (char *)&signature[0]};
    octet d_comp = {.val = (char *)&signature[EGS_NIST256]};
    int out = ECP_NIST256_PUBLIC_KEY_VALIDATE(&pub);
    assert(0 == out);//makes sure that key_validate passes
    if (0 == out) {
        out = ECP_NIST256_VP_DSA(SHA256, &pub, &msg_in, &c_comp, &d_comp);
    }

    return out;
}
