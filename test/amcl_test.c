#include "xtt/crypto_wrapper.h"
#include <../../amcl/include/ecdh_NIST256.h>


int main(){
    xtt_ed25519_pub_key public_key = {.data = {"M3veFqo+56O03s3XGmPWEkLX6j0gTfL4OOamQ/GBncDOsBTwkyS4ioVTch4VTYgg
                                                TixTiAdRSA08SBr52YGF2ki8yafhmHLIBAJ3z0OSHpxCQuTEt8zpE2DpHIL4imoD
                                                zmbDuuCRZGXvKzgbdmTr9YeRQW8nNyDA6NZFJ1BwXrCzDQhaoML3K9eMmkLTce/Q
                                                dYzvaGuEWohAuijPLzjofYySMJ9OsJ+IHLMCppdiCBA="}};
    xtt_ed25519_priv_key private_key = {.data = {"MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhALcoNT7jQuB2nism8z6EM0SVY7rQwCuO90Z95oOd/H67AgMBAAE="}};
    printf("output of crypto_create: %d\n", xtt_crypto_create_ecdsap256(&public_key, &private_key));

    unsigned char sign_out_buffer[64];
    unsigned char msg[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
    int signatureout = xtt_crypto_sign_ecdsap256(sign_out_buffer, msg, sizeof(msg), &private_key);
    printf("output of crypto_sign: %d\n", signatureout);

    int verifyout = xtt_crypto_verify_ecdsap256(sign_out_buffer, msg, sizeof(msg), &public_key);
    printf("output of crypto_verify: %d\n", verifyout);

    return 0;
}
