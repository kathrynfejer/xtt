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
    ecdsa_hard_code_signature();
    ecdsa_check_k_vals();
}


void ecdsa_regression_test()
{
    printf("starting wrapper_sanity-test::ecdsa_regression_test...\n");

    const unsigned char msg_sign[] = "this is a test msg to be signed";
    size_t msg_sign_len;
    xtt_ecdsap256_signature signature;
    xtt_ecdsap256_pub_key pub_key;
    xtt_ecdsap256_priv_key priv_key;

    msg_sign_len = sizeof(msg_sign);

    EXPECT_EQ(xtt_crypto_create_ecdsap256_key_pair(&pub_key, &priv_key), 0);
    EXPECT_EQ(xtt_crypto_sign_ecdsap256(signature.data, msg_sign, msg_sign_len, &priv_key), 0);
    EXPECT_EQ(xtt_crypto_verify_ecdsap256(signature.data, msg_sign, msg_sign_len, &pub_key), 0);
    printf("ecdsa_regression_test passed\n");
}

void ecdsa_hard_code_keypair(){
    //sign and verify
    printf("starting wrapper_sanity-test::ecdsa_hard_code_keypair...\n");

    const unsigned char msg_sign[] = "this is a test msg to be signed";
    size_t msg_sign_len = sizeof(msg_sign);
    xtt_ecdsap256_signature signature;
    xtt_ecdsap256_pub_key pub_key = {.data = {0x04, 0xc6, 0x33, 0x28, 0x1d, 0x25, 0x3c, 0xe4, 0xc5, 0x61, 0xbd, 0xf4, 0x7f, 0xa3, 0x30,
    0x01, 0x9f, 0x85, 0x80, 0x12, 0x03, 0xd3, 0xe8, 0x84, 0x3b, 0x8d, 0xde, 0xd0, 0xd3, 0x12,
    0xc6, 0x14, 0x15, 0xf2, 0x72, 0xd4, 0x83, 0x44, 0xc2, 0x59, 0x01, 0x38, 0x72, 0x0c, 0x07,
    0xeb, 0x0f, 0x92, 0xce, 0xd8, 0xd6, 0x40, 0xca, 0xe4, 0x08, 0x9d, 0xa4, 0x89, 0x8b, 0xf3,
    0x36, 0xeb, 0x04, 0x82, 0x30}};
    xtt_ecdsap256_priv_key priv_key = {.data ={0x5a, 0xba, 0x8a, 0x98, 0x5e, 0xfc, 0xee, 0xd5, 0x08, 0x1d, 0x1c, 0x45, 0x84, 0xd5, 0x34,
    0x73, 0x8b, 0x1d, 0x1d, 0xb5, 0x65, 0xb9, 0xe3, 0x19, 0x8d, 0x08, 0x86, 0x12, 0x7d, 0x2d,
    0x88, 0x23}};

    EXPECT_EQ(xtt_crypto_sign_ecdsap256(signature.data, msg_sign, msg_sign_len, &priv_key), 0);

    EXPECT_EQ(xtt_crypto_verify_ecdsap256(signature.data, msg_sign, msg_sign_len, &pub_key), 0);
    printf("ecdsa_hard_code_keypair passed\n");
}

void ecdsa_hard_code_signature(){
    printf("starting wrapper_sanity-test::ecdsa_hard_code_signature...\n");

    const unsigned char msg_sign[] = "this is a test msg to be signed";
    size_t msg_sign_len = sizeof(msg_sign);
    xtt_ecdsap256_signature signature = {.data = {0x31, 0xfe, 0xff, 0x82, 0xa4, 0x0f, 0x93, 0x9c,
  0xd4, 0x08, 0x1c, 0x1b, 0x65, 0x84, 0xa7, 0x9f, 0x12, 0x98, 0x8a, 0x3e,
  0xaa, 0xf4, 0x00, 0xb1, 0x1d, 0xa7, 0xa4, 0x0a, 0x3a, 0xe1, 0x02, 0x28,
  0x27, 0x85, 0xfd, 0x89, 0x92, 0x6b, 0xb9, 0xa7, 0xdc, 0x84,
  0x01, 0x56, 0x0a, 0x00, 0x7c, 0x9a, 0xcc, 0x4a, 0x53, 0x85, 0x31, 0xab,
  0x11, 0xf7, 0x84, 0x5c, 0x09, 0xf8, 0xa2, 0x0f, 0xe4, 0x72
}};
    xtt_ecdsap256_pub_key pub_key = {.data = {0x04, 0xc6, 0x33, 0x28, 0x1d, 0x25, 0x3c, 0xe4, 0xc5, 0x61, 0xbd, 0xf4, 0x7f, 0xa3, 0x30,
    0x01, 0x9f, 0x85, 0x80, 0x12, 0x03, 0xd3, 0xe8, 0x84, 0x3b, 0x8d, 0xde, 0xd0, 0xd3, 0x12,
    0xc6, 0x14, 0x15, 0xf2, 0x72, 0xd4, 0x83, 0x44, 0xc2, 0x59, 0x01, 0x38, 0x72, 0x0c, 0x07,
    0xeb, 0x0f, 0x92, 0xce, 0xd8, 0xd6, 0x40, 0xca, 0xe4, 0x08, 0x9d, 0xa4, 0x89, 0x8b, 0xf3,
    0x36, 0xeb, 0x04, 0x82, 0x30}};


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
    xtt_ecdsap256_signature signature1;
    xtt_ecdsap256_signature signature2;
    xtt_ecdsap256_pub_key pub_key;
    xtt_ecdsap256_priv_key priv_key;

    msg_sign_len = sizeof(msg_sign);

    EXPECT_EQ(xtt_crypto_create_ecdsap256_key_pair(&pub_key, &priv_key), 0);

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

    EXPECT_NE(memcmp(signature1.data, signature2.data, sizeof(xtt_ecdsap256_signature)), 0);    //memcmp because this is not enough
    printf("ecdsa_check_k_vals passed\n");

}
