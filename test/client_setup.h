#include <xtt.h>
#include <sodium.h>

#include <ecdaa.h>

#include "test-utils.h"

#include "../src/internal/message_utils.h"
#include "../src/internal/byte_utils.h"

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#include <xtt/context.h>
#include <xtt/crypto_types.h>
#include <xtt/return_codes.h>

struct xtt_client_ctxhelper{
  unsigned char in[MAX_HANDSHAKE_SERVER_MESSAGE_LENGTH];
  unsigned char out[MAX_HANDSHAKE_CLIENT_MESSAGE_LENGTH];
  struct xtt_client_handshake_context ctx;
  unsigned char *io_ptr;
  uint16_t bytes_requested;
  xtt_return_code_type rc;
};

void setup_client_input(struct xtt_client_ctxhelper* client, struct xtt_client_group_context* group_ctx, const xtt_daa_group_pub_key_lrsw* gpk){
  xtt_group_id gid;
  xtt_daa_priv_key_lrsw daa_priv_key = { .data = {0xca, 0x6b, 0x40, 0x60, 0x76, 0xde, 0x8e, 0xba, 0x4b, 0x16, 0xb8, 0x8b,
  0xb8, 0xef, 0xf4, 0xa6, 0xd7, 0xac, 0x8d, 0x70, 0x2e, 0x4a, 0x64, 0xf4,
  0x55, 0xd5, 0x1a, 0xe8, 0xf0, 0xd1, 0x33, 0xdb}};
  xtt_daa_credential_lrsw daa_cred = { .data = {0x04, 0x78, 0x40, 0x9d, 0x96, 0x00, 0x00, 0x23, 0xcd, 0xb2, 0x5f, 0x6c,
  0x9b, 0x6c, 0x47, 0xa6, 0x74, 0xd9, 0x61, 0xe6, 0x6f, 0x6b, 0x8d, 0xa2,
  0xa4, 0xf9, 0xf9, 0xc6, 0x93, 0xdc, 0x45, 0x3e, 0xdc, 0xc7, 0x70, 0x45,
  0xff, 0xae, 0xfa, 0xf4, 0x2f, 0xac, 0x7d, 0x75, 0x6d, 0x2c, 0x13, 0x5f,
  0xa8, 0x55, 0x8d, 0x53, 0xe4, 0x62, 0x6f, 0x8b, 0xa9, 0x8b, 0xef, 0x56,
  0x07, 0x9a, 0x65, 0x02, 0x62, 0x04, 0x29, 0xb1, 0xbf, 0x70, 0x28, 0x37,
  0x27, 0x9d, 0xf3, 0x95, 0xfa, 0x13, 0xda, 0x4d, 0xf0, 0x8a, 0x3a, 0x3f,
  0xd7, 0xab, 0x9f, 0x1e, 0xee, 0x2f, 0xfc, 0xa9, 0x94, 0x5b, 0x75, 0xdd,
  0x58, 0x2d, 0x28, 0x5c, 0xd1, 0x7e, 0x70, 0x5b, 0xb6, 0x83, 0xef, 0xa3,
  0x09, 0x07, 0x3b, 0x44, 0x11, 0xec, 0x73, 0x2d, 0x33, 0xf7, 0x8f, 0x4d,
  0xb6, 0x37, 0xbc, 0x75, 0xb3, 0xde, 0xc6, 0x8f, 0xfe, 0x68, 0x04, 0x85,
  0xbe, 0x19, 0x73, 0xf5, 0x2f, 0x44, 0xcc, 0x74, 0x89, 0x9b, 0xa2, 0x8a,
  0x55, 0x08, 0x24, 0x2b, 0xeb, 0x0f, 0xef, 0xcd, 0x85, 0xe0, 0x8b, 0x2b,
  0x28, 0x90, 0x7a, 0xf7, 0xed, 0xba, 0x72, 0x02, 0x07, 0x85, 0x1b, 0x5c,
  0x0c, 0x87, 0xc5, 0x22, 0xed, 0x24, 0x5d, 0xf5, 0xa0, 0x5b, 0x49, 0xb2,
  0x4c, 0x56, 0x37, 0x99, 0x6b, 0x47, 0xac, 0x76, 0x54, 0x40, 0xd1, 0x5b,
  0x76, 0x90, 0xb5, 0x04, 0xec, 0x16, 0xd3, 0xe7, 0x37, 0x88, 0xd2, 0x2c,
  0xc2, 0x38, 0x18, 0xf0, 0xf7, 0x69, 0x8c, 0xb2, 0x19, 0x5b, 0xb5, 0xb7,
  0x4a, 0xf2, 0xdd, 0x6f, 0x91, 0x94, 0xf5, 0xa0, 0xa7, 0x64, 0xc5, 0x9e,
  0xf0, 0xdb, 0xdd, 0xc0, 0xa9, 0xbc, 0x39, 0xa2, 0xfb, 0x2d, 0x60, 0xb4,
  0x50, 0x7a, 0xa9, 0xb7, 0x98, 0xce, 0x11, 0x15, 0x35, 0x64, 0xbc, 0x8d,
  0xae, 0xb7, 0x82, 0x5c, 0xdc, 0x62, 0xc7, 0x70}};

  const unsigned char basename[]={0x42, 0x41, 0x53, 0x45, 0x4e, 0x41, 0x4d, 0x45};
  uint16_t basename_length = 8;



  int hash_ret = crypto_hash_sha256(gid.data, gpk->data, sizeof(gpk));
  assert(0 == hash_ret);


  client->rc = xtt_initialize_client_group_context_lrsw(group_ctx, &gid, &daa_priv_key, &daa_cred, basename, basename_length);
  printf("initialize client group context: %s\n", xtt_strerror(client->rc));
  assert(client->rc==XTT_RETURN_SUCCESS);
}
