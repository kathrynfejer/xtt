#include <xtt.h>

#include "test-utils.h"

#include <string.h>
#include <stdint.h>
#include <stdio.h>

void ecdsa_regression_test();
void ecdsa_hard_code_keypair();
void ecdsa_hard_code_signature();
void ecdsa_check_k_vals();

void initialize() {
    int init_ret = xtt_crypto_initialize_crypto();
    TEST_ASSERT(0 == init_ret);
}

int main() {
    initialize();

    ecdsa_regression_test();
    ecdsa_hard_code_keypair();
    //ecdsa_hard_code_signature();
    ecdsa_check_k_vals();
}


void ecdsa_regression_test()
{
    printf("starting wrapper_sanity-test::ecdsa_regression_test...\n");

    const unsigned char msg_sign[] = "this is a test msg to be signed";
    size_t msg_sign_len;
    xtt_ed25519_signature signature;
    xtt_ed25519_pub_key pub_key;
    xtt_ed25519_priv_key priv_key;

    msg_sign_len = sizeof(msg_sign);

    EXPECT_EQ(xtt_crypto_create_ecdsap256(&pub_key, &priv_key), 0);
    EXPECT_EQ(xtt_crypto_sign_ecdsap256(signature.data, msg_sign, msg_sign_len, &priv_key), 0);
    EXPECT_EQ(xtt_crypto_verify_ecdsap256(signature.data, msg_sign, msg_sign_len, &pub_key), 0);
    printf("ecdsa_regression_test passed\n");
}

void ecdsa_hard_code_keypair(){
    //sign and verify
    printf("starting wrapper_sanity-test::ecdsa_hard_code_keypair...\n");

    const unsigned char msg_sign[] = "this is a test msg to be signed";
    size_t msg_sign_len = sizeof(msg_sign);
    xtt_ed25519_signature signature;
    xtt_ed25519_pub_key pub_key = {.data = {0x04, 0xca, 0x97, 0x84, 0xc6, 0x07, 0xc2, 0x04, 0x98, 0x63, 0xd0, 0xd4, 0x15, 0xdb, 0x63,
    0x67, 0x90, 0x77, 0x60, 0xc8, 0x95, 0x2b, 0x42, 0x99, 0xd3, 0xed, 0x3e, 0x5f, 0x6f, 0x3e,
    0x82, 0xd7, 0xaa, 0xf1, 0xde, 0x99, 0xa9, 0x83, 0xfe, 0xbe, 0x4f, 0xfd, 0x56, 0x03, 0x84,
    0x85, 0x59, 0xf4, 0x99, 0x4d, 0x86, 0xfe, 0xe3, 0x5a, 0xa5, 0x25, 0x1c, 0x59, 0xc5, 0x02,
    0xa5, 0x49, 0x16, 0xd7, 0xa6}};
    xtt_ed25519_priv_key priv_key = {.data ={0x5d, 0x74, 0xd1, 0x19, 0x1a, 0x12, 0xdc, 0x6b, 0x58, 0x8e, 0x98, 0xdb, 0xab, 0xac, 0xeb,
    0xa7, 0x3f, 0xba, 0x9b, 0x39, 0x3a, 0xab, 0x33, 0x1b, 0xc0, 0xbc, 0xf6, 0xd6, 0xcf, 0x26,
    0x8b, 0x3e}};

    EXPECT_EQ(xtt_crypto_sign_ecdsap256(signature.data, msg_sign, msg_sign_len, &priv_key), 0);
    EXPECT_EQ(xtt_crypto_verify_ecdsap256(signature.data, msg_sign, msg_sign_len, &pub_key), 0);
    printf("ecdsa_hard_code_keypair passed\n");
}

void ecdsa_hard_code_signature(){
    printf("starting wrapper_sanity-test::ecdsa_hard_code_signature...\n");

    const unsigned char msg_sign[] = "this is a test msg to be signed";
    size_t msg_sign_len = sizeof(msg_sign);
    xtt_ed25519_signature signature = {.data = {0x30, 0x45, 0x02, 0x20, 0x43, 0x21, 0x6d, 0x29, 0xb5, 0x8a, 0x59, 0xc8,
  0xff, 0xff, 0x71, 0x6b, 0x19, 0xcf, 0xc6, 0x07, 0x3b, 0xc4, 0x10, 0x8f,
  0x56, 0x31, 0xeb, 0x87, 0xbf, 0xb6, 0x0a, 0x48, 0x02, 0x06, 0xc7, 0x60,
  0x02, 0x21, 0x00, 0xb5, 0x12, 0x38, 0x76, 0x44, 0x92, 0xdc, 0xd5, 0x4c,
  0xb8, 0x51, 0x89, 0x53, 0x65, 0x1c, 0x09, 0x1f, 0xdd, 0x80, 0xe1, 0xb1,
  0xb0, 0x2e, 0x3f, 0x02, /*0x7b, 0x55, 0xfd, 0xbe, 0x6a, 0xcb, 0x70*/
}};
    xtt_ed25519_pub_key pub_key = {.data = {0x04, 0xca, 0x97, 0x84, 0xc6, 0x07, 0xc2, 0x04, 0x98, 0x63, 0xd0, 0xd4, 0x15, 0xdb, 0x63,
    0x67, 0x90, 0x77, 0x60, 0xc8, 0x95, 0x2b, 0x42, 0x99, 0xd3, 0xed, 0x3e, 0x5f, 0x6f, 0x3e,
    0x82, 0xd7, 0xaa, 0xf1, 0xde, 0x99, 0xa9, 0x83, 0xfe, 0xbe, 0x4f, 0xfd, 0x56, 0x03, 0x84,
    0x85, 0x59, 0xf4, 0x99, 0x4d, 0x86, 0xfe, 0xe3, 0x5a, 0xa5, 0x25, 0x1c, 0x59, 0xc5, 0x02,
    0xa5, 0x49, 0x16, 0xd7, 0xa6}};


    int verifyout = xtt_crypto_verify_ecdsap256(signature.data, msg_sign, sizeof(msg_sign), &pub_key);
    printf("output of crypto_verify: %d\n", verifyout);
    EXPECT_EQ(xtt_crypto_verify_ecdsap256(signature.data,
                                        msg_sign,
                                        msg_sign_len,
                                        &pub_key),
              0);
    printf("ecdsa_hard_code_signature passed\n");
}

void ecdsa_check_k_vals(){
    //sign 2x with same keypair and check that it changes the output signatures
    printf("starting wrapper_sanity-test::ecdsa_check_k_vals...\n");

    const unsigned char msg_sign[] = "this is a test msg to be signed";
    size_t msg_sign_len;
    xtt_ed25519_signature signature1;
    xtt_ed25519_signature signature2;
    xtt_ed25519_pub_key pub_key;
    xtt_ed25519_priv_key priv_key;

    msg_sign_len = sizeof(msg_sign);

    EXPECT_EQ(xtt_crypto_create_ecdsap256(&pub_key, &priv_key), 0);

    EXPECT_EQ(xtt_crypto_sign_ecdsap256(signature1.data,
                                      msg_sign,
                                      msg_sign_len,
                                      &priv_key),
              0);
    EXPECT_EQ(xtt_crypto_sign_ecdsap256(signature2.data,
                                      msg_sign,
                                      msg_sign_len,
                                      &priv_key),
              0);

    EXPECT_NE(memcmp(signature1.data, signature2.data, sizeof(xtt_ed25519_signature)), 0);    //memcmp because this is not enough
    printf("ecdsa_check_k_vals passed\n");

}
