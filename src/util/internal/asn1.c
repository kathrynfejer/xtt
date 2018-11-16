/******************************************************************************
 *
 * Copyright 2017 Xaptum, Inc.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License
 *
 *****************************************************************************/

#include "asn1.h"

#include <xtt/crypto_wrapper.h>

#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

const unsigned char SEQUENCE_TAG = 0x30;
const unsigned char SET_TAG = 0x31;
const unsigned char INTEGER_TAG = 0x02;
const unsigned char OBJECTIDENTIFIER_TAG = 0x06;
const unsigned char UTCTIME_TAG = 0x17;
const unsigned char BITSTRING_TAG = 0x03;
const unsigned char OCTETSTRING_TAG = 0x04;
const unsigned char CONSTRUCTED_TAG0 = 0xA0;
const unsigned char CONSTRUCTED_TAG1 = 0xA1;

const unsigned char COMMONNAME_OID[] = {0x55, 0x04, 0x03};
const unsigned char ECDSA_W_SHA256_OID[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02};     //1.2.840.10045.4.3.2
const unsigned char PRIME256V1_OID[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};     //1.2.840.10045.3.1.7

const unsigned char ECPUBLICKEY_OID[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};

const unsigned char ONEASYMMETRICKEY_VERSION = 0x01;

const unsigned char UTF8STRING_ATTRTYPE = 0x0C;

const int VALIDITY_YEARS = 1;

size_t
get_certificate_length()
{
    return certificate_length;
}

size_t
get_asn1privatekey_length()
{
    return asn1_privatekey_length;
}

void
build_x509_skeleton(unsigned char *certificate_out,
                    unsigned char **pubkey_location,
                    unsigned char **signature_location,
                    unsigned char **signature_input_location,
                    size_t *signature_input_length,
                    const char *common_name_issuer,
                    const char *common_name_subject)
{
    unsigned char *current_loc = certificate_out;

    set_as_sequence(&current_loc);
    set_length(&current_loc, get_certificate_length() - 3 - 1);

    *signature_input_location = current_loc;
    *signature_input_length = tbs_certificate_length;

    build_tbs_certificate(&current_loc, pubkey_location, common_name_issuer, common_name_subject);

    build_signature_algorithm(&current_loc);

    *current_loc = BITSTRING_TAG;
    current_loc += 1;
    set_length(&current_loc, signature_value_length - 1 - 1);

    // Add a 0x00, to indicate we didn't need to pad (signature is always a multiple of 8bits)
    *current_loc = 0x00;
    current_loc += 1;

    *signature_location = current_loc;
}

void
build_privkey_version(unsigned char **current_loc)
{
    **current_loc = INTEGER_TAG;
    *current_loc += 1;
    set_length(current_loc, 1);

    **current_loc = ONEASYMMETRICKEY_VERSION;

    *current_loc += 1;
}

void
build_privatekey(unsigned char **current_loc,
                 unsigned char **privatekey_location)
{
    **current_loc = OCTETSTRING_TAG;
    *current_loc += 1;
    set_length(current_loc, asn1_privatekeyfield_length - 1 - 1);

    *privatekey_location = *current_loc;
    *current_loc += RAW_PRIVATE_KEY_LENGTH;
}

void
build_asn1_key_skeleton(unsigned char *asn1_out,
                        unsigned char **privkey_location,
                        unsigned char **pubkey_location)
{
    unsigned char *current_loc = asn1_out;

    set_as_sequence(&current_loc);
    set_length(&current_loc, asn1_privatekey_length - 2);

    build_privkey_version(&current_loc);

    build_privatekey(&current_loc, privkey_location);

    build_privatekey_algorithm(&current_loc);

    build_privatekey_publickeycopy(&current_loc, pubkey_location);
}

void
build_privatekey_publickeycopy(unsigned char **current_loc,
                               unsigned char **pubkey_location)
{
    **current_loc = CONSTRUCTED_TAG1;
    *current_loc += 1;
    set_length(current_loc, asn1_privatekey_pubkeycopy_length - 1 - 1);

    build_publickey(current_loc, pubkey_location);
}

void
set_as_sequence(unsigned char **current_loc)
{
    **current_loc = SEQUENCE_TAG;
    *current_loc += 1;
}

void
set_as_set(unsigned char **current_loc)
{
    **current_loc = SET_TAG;
    *current_loc += 1;
}

void
build_tbs_certificate(unsigned char **current_loc,
                      unsigned char **pubkey_location,
                      const char *common_name_issuer,
                      const char *common_name_subject)
{
    set_as_sequence(current_loc);
    set_length(current_loc, tbs_certificate_length - 1 - 3);

    build_serial_number(current_loc);

    build_signature_algorithm(current_loc);

    build_name(current_loc, common_name_issuer);    // issuer name

    build_validity(current_loc);

    build_name(current_loc, common_name_subject);    // subject name

    build_subjectpublickeyinfo(current_loc, pubkey_location);

}

void
set_length(unsigned char **current_loc,
           size_t length)
{
    if (length < 127) {
        **current_loc = length;
        *current_loc += 1;
    } else if (length < UINT8_MAX) {
        (*current_loc)[0] = 0x80 + 1;   // Set msb to 1, to indicate a long format, and add one for the one next block
        (*current_loc)[1] = length;
        *current_loc += 2;
    } else if (length < UINT16_MAX) {
        (*current_loc)[0] = 0x80 + 2;   // Set msb to 1, to indicate a long format, and add two for the two next blocks
        (*current_loc)[1] = length >> 8;
        (*current_loc)[2] = length & 0xFF;
        *current_loc += 3;
    } else {
        // None of our lengths should require more than 2 bytes to represent
        exit(1);
    }
}

void
build_signature_algorithm(unsigned char **current_loc)
{
    set_as_sequence(current_loc);
    set_length(current_loc, ecdsap256_algid_length - 1 - 1);

    **current_loc = OBJECTIDENTIFIER_TAG;
    *current_loc += 1;
    set_length(current_loc, ecdsa_w_sha256_oid_length - 1 - 1);

    memcpy(*current_loc, ECDSA_W_SHA256_OID, 8);
    *current_loc += 8;
}

void
build_privatekey_algorithm(unsigned char **current_loc)
{
    **current_loc = CONSTRUCTED_TAG0;
    *current_loc += 1;
    set_length(current_loc, p256_keyid_length - 1 - 1);

    **current_loc = OBJECTIDENTIFIER_TAG;
    *current_loc += 1;
    set_length(current_loc, prime256v1_oid_length - 1 - 1);

    memcpy(*current_loc, PRIME256V1_OID, 8);
    *current_loc += 8;
}

void
build_curve(unsigned char **current_loc)
{
    set_as_sequence(current_loc);
    set_length(current_loc, curve_def_length - 1 - 1);

    **current_loc = OBJECTIDENTIFIER_TAG;
    *current_loc += 1;
    set_length(current_loc, ecpublickey_oid_length - 1 - 1);

    memcpy(*current_loc, ECPUBLICKEY_OID, 7);
    *current_loc += 7;

    **current_loc = OBJECTIDENTIFIER_TAG;
    *current_loc += 1;
    set_length(current_loc, prime256v1_oid_length - 1 - 1);

    memcpy(*current_loc, PRIME256V1_OID, 8);
    *current_loc += 8;
}

void
build_serial_number(unsigned char **current_loc)
{
    const size_t len = serial_num_length - 1 - 1;

    **current_loc = INTEGER_TAG;
    *current_loc += 1;
    set_length(current_loc, len);

    assert(len == 20);
    // Nb. We're only generating 19 bytes of randomness
    xtt_crypto_get_random(*current_loc, len-1);
    (*current_loc)[0] &= 0x7F;   // clear msb, to ensure it's positive

    *current_loc += len;
}

void
build_name(unsigned char **current_loc,
           const char *common_name)
{
    set_as_sequence(current_loc);
    set_length(current_loc, name_length - 1 - 1);

    set_as_set(current_loc);
    set_length(current_loc, rdn_length - 1 - 1);

    set_as_sequence(current_loc);
    set_length(current_loc, name_attr_tandv_length - 1 - 1);

    **current_loc = OBJECTIDENTIFIER_TAG;
    *current_loc += 1;
    set_length(current_loc, name_oid_length - 1 - 1);
    memcpy(*current_loc, COMMONNAME_OID, 3);
    *current_loc += 3;

    **current_loc = UTF8STRING_ATTRTYPE;
    *current_loc += 1;
    set_length(current_loc, NAME_LENGTH);
    memcpy(*current_loc, common_name, NAME_LENGTH);
    *current_loc += NAME_LENGTH;
}

void
build_validity(unsigned char **current_loc)
{
    set_as_sequence(current_loc);
    set_length(current_loc, validity_length - 1 - 1);

    char not_before_time[14];
    assert(sizeof(not_before_time) == UTC_LENGTH + 1);      // for the null-terminator
    char not_after_time[14];
    assert(sizeof(not_after_time) == UTC_LENGTH + 1);      // for the null-terminator
    get_validity_times(not_before_time, not_after_time);

    **current_loc = UTCTIME_TAG;
    *current_loc += 1;
    set_length(current_loc, utctime_length - 1 - 1);
    memcpy(*current_loc, not_before_time, UTC_LENGTH);
    *current_loc += UTC_LENGTH;

    **current_loc = UTCTIME_TAG;
    *current_loc += 1;
    set_length(current_loc, utctime_length - 1 - 1);
    memcpy(*current_loc, not_after_time, UTC_LENGTH);
    *current_loc += UTC_LENGTH;
}

void
build_publickey(unsigned char **current_loc, unsigned char **pubkey_location)
{
    **current_loc = BITSTRING_TAG;
    *current_loc += 1;
    set_length(current_loc, pubkey_bitstring_length - 1 - 1);

    // Add a 0x00, to indicate we didn't need to pad (pub key is always a multiple of 8bits)
    **current_loc = 0x00;
    *current_loc += 1;

    *pubkey_location = *current_loc;

    // Increment, to make space for pub key (caller will copy it in)
    *current_loc += sizeof(xtt_ecdsap256_pub_key);
}

void
build_subjectpublickeyinfo(unsigned char **current_loc, unsigned char **pubkey_location)
{
    set_as_sequence(current_loc);
    set_length(current_loc, subjectpublickeyinfo_length - 1 - 1);

    build_curve(current_loc);

    build_publickey(current_loc, pubkey_location);
}

void
get_validity_times(char *not_before_time, char *not_after_time)
{
    time_t now_timet = time(NULL);
    struct tm *now = gmtime(&now_timet);

    snprintf(not_before_time,
             UTC_LENGTH + 1,
             "%02d%02d%02d000000Z",
             now->tm_year - 100,
             now->tm_mon + 1,
             now->tm_mday);

    snprintf(not_after_time,
             UTC_LENGTH + 1,
             "%02d%02d%02d000000Z",
             now->tm_year - 100 + VALIDITY_YEARS,
             now->tm_mon + 1,
             now->tm_mday);
}
