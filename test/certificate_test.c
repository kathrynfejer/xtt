#include <xtt.h>
#include <../../amcl/include/x509.h>


int main(){
    xtt_ecdsap256_pub_key public_key;
    xtt_ecdsap256_priv_key private_key;
    xtt_ecdsap256_signature signature;
    unsigned char message[] = "test123";

    xtt_crypto_create_ecdsap256_key_pair(&public_key, &private_key);
    printf("Public Key: ");
    for (size_t i = 0; i < sizeof(public_key.data); i++) {
        printf("%x ", public_key.data[i]);
    }
    printf("\n");
    printf("\nPrivate Key: ");
    for (size_t i = 0; i < sizeof(private_key.data); i++) {
        printf("%x ", private_key.data[i]);
    }
    printf("\n");
    xtt_crypto_sign_ecdsap256(signature.data, message, sizeof(message), &private_key);

    printf("\nSignature: ");
    for (size_t i = 0; i < sizeof(signature.data); i++) {
        printf("%x ", signature.data[i]);
    }
    printf("\n");

    unsigned char certificate[XTT_X509_CERTIFICATE_LENGTH];

    xtt_x509_from_ecdsap256_keypair(&public_key, &private_key, &xtt_null_identity, certificate, XTT_X509_CERTIFICATE_LENGTH);

    printf("\nCertifcate: ");
    for (size_t i = 0; i < sizeof(certificate); i++) {
        printf("%c", certificate[i]);
    }
    printf("\n");

    int p = extract_sig_type(certificate);

    printf("\n type: %d \n", p);



}
