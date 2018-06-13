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
#include "networkArray.h"
#include "server_setup.h"

#include <xtt/context.h>
#include <xtt/crypto_types.h>
#include <xtt/return_codes.h>



//Helper functions and structs
struct xtt_client_ctxhelper{
  unsigned char in[MAX_HANDSHAKE_SERVER_MESSAGE_LENGTH];
  unsigned char out[MAX_HANDSHAKE_CLIENT_MESSAGE_LENGTH];
  struct xtt_client_handshake_context ctx;
  unsigned char *io_ptr;
  uint16_t bytes_requested;
  xtt_return_code_type rc;
};




void client_write_to_network(struct xtt_client_ctxhelper* client, struct network_helper* network);
void client_read_from_network(struct xtt_client_ctxhelper* client, struct network_helper* network);
void server_write_to_network(struct xtt_server_ctxhelper* server, struct network_helper* network);
void server_read_from_network(struct xtt_server_ctxhelper* server, struct network_helper* network);


//global variables

int main()
{
  //initialize structs and important pointers
  struct xtt_client_ctxhelper client;
  struct xtt_server_ctxhelper server;

  //setup and assign network HERE
    struct network_helper network;
    setupNetwork(&network);

  client.bytes_requested=0;
  server.bytes_requested=0;
  uint16_t msglen;

  xtt_certificate_root_id claimed_root_out;
  const struct xtt_server_root_certificate_context root_server_cert;
  const xtt_identity_type client_id;
  const xtt_identity_type intended_server_id;
  xtt_identity_type requested_client_id_out;
  xtt_group_id claimed_group_id_out;
  const struct xtt_server_certificate_context certificate_ctx;
  struct xtt_server_certificate_context cert_ctx_s;
  struct xtt_group_public_key_context group_pub_key_ctx;
  struct xtt_client_group_context group_ctx;

  xtt_version version = XTT_VERSION_ONE;
  // xtt_suite_spec suite_spec = XTT_X25519_LRSW_ED25519_CHACHA20POLY1305_SHA512;
  // xtt_suite_spec suite_spec = XTT_X25519_LRSW_ED25519_CHACHA20POLY1305_BLAKE2B;
  xtt_suite_spec suite_spec = XTT_X25519_LRSW_ED25519_AES256GCM_SHA512;
  // xtt_suite_spec suite_spec = XTT_X25519_LRSW_ED25519_AES256GCM_BLAKE2B;


  setup_server_stuff(&server, &cert_ctx_s, &group_pub_key_ctx, &group_ctx);

  uint16_t client_init_send_length = xtt_get_message_length(client.out);
  msglen =xtt_get_message_length(client.out);
  printf("%d\n", msglen);
  EXPECT_EQ(msglen, client_init_send_length);

//TODO: take out access and replace
  *xtt_access_msg_type(client.out)=XTT_CLIENTINIT_MSG;
  assert(xtt_get_message_type(client.out)==XTT_CLIENTINIT_MSG);



//*************************************************************************
  //Initializing client and server handshake contexts
  client.rc= xtt_initialize_client_handshake_context(&client.ctx, client.in , sizeof(client.in), client.out, sizeof(client.out), version, suite_spec);
  printf("initialize client handshaek ctx: %s\n", xtt_strerror(client.rc));
  assert(client.rc==XTT_RETURN_SUCCESS);
  assert(xtt_get_message_type(client.out)==XTT_CLIENTINIT_MSG);
  server.rc = xtt_initialize_server_handshake_context(&server.ctx, server.in, sizeof(server.in), server.out, sizeof(server.out));
  assert(server.rc==XTT_RETURN_SUCCESS);

//START CLIENT STEP 1
//***********************************************************************
  client.rc = xtt_handshake_client_start(&client.bytes_requested, &client.io_ptr, &client.ctx);
  printf("handshake client start: %s\n", xtt_strerror(client.rc));
  assert(client.rc==XTT_RETURN_WANT_WRITE);
  printf("bytes requested client: %hu\n", client.bytes_requested);
  client_write_to_network(&client, &network);
  printf("handshake client handle I/O: %s\n", xtt_strerror(client.rc));
  assert(client.rc==XTT_RETURN_WANT_READ);
  printf("%hu client\n", client.bytes_requested);

//START SERVER STEP 1
//**************************************************************
  printf("initial bytes requested server: %hu server\n", server.bytes_requested);
  server.rc=xtt_handshake_server_handle_connect(&server.bytes_requested, &server.io_ptr, &server.ctx);
  printf("handshake server handle connect: %s\n", xtt_strerror(server.rc));
  printf("bytes req after handle connect:%hu \n", server.bytes_requested);
  assert(server.rc==XTT_RETURN_WANT_READ);
  server_read_from_network(&server, &network);
  printf("1 handshake server after read from network: %s\n", xtt_strerror(server.rc));
  printf("bytes requested after 1st read from net: %hu \n", server.bytes_requested);
  server_read_from_network(&server, &network);
  printf("2 handshake server after read from network: %s\n", xtt_strerror(server.rc));
  printf("bytes req after 2nd read from net: %hu \n", server.bytes_requested);
  assert(server.rc==XTT_RETURN_WANT_BUILDSERVERATTEST);
  server.rc= xtt_handshake_server_build_serverattest(&server.bytes_requested, &server.io_ptr, &server.ctx, &cert_ctx_s, &server.cookie_ctx);
  printf("handshake server build server attest: %s\n", xtt_strerror(server.rc));
  assert(server.rc==XTT_RETURN_WANT_WRITE);
  server_write_to_network(&server, &network);
  printf("after write to network's I/0: %s\n", xtt_strerror(server.rc));
  assert(server.rc==XTT_RETURN_WANT_READ);

//START CLIENT STEP 2
//****************************************************************
  client_read_from_network(&client, &network);
  printf("client read from network read I/O: %s\n", xtt_strerror(client.rc));
  client_read_from_network(&client, &network);
  printf("client read from network read I/O: %s\n", xtt_strerror(client.rc));
  assert(client.rc==XTT_RETURN_WANT_PREPARSESERVERATTEST);
  client.rc=xtt_handshake_client_preparse_serverattest(&claimed_root_out, &client.bytes_requested, &client.io_ptr, &client.ctx);
  printf("client preparse server attest: %s\n", xtt_strerror(client.rc));
  assert(client.rc==XTT_RETURN_WANT_BUILDIDCLIENTATTEST);
  client.rc=xtt_handshake_client_build_idclientattest(&client.bytes_requested, &client.io_ptr, &root_server_cert, &xtt_null_identity, &intended_server_id, &group_ctx, &client.ctx);
  printf("client build idclientattest: %s\n", xtt_strerror(client.rc));
  assert(client.rc==XTT_RETURN_WANT_WRITE);
  client_write_to_network(&client, &network);
  printf("client write to network I/O: %s\n", xtt_strerror(client.rc));
  assert(client.rc==XTT_RETURN_WANT_READ);

//START CLIENT STEP 2
//********************************************************************
  server_read_from_network(&server, &network);
  printf("server read from network read I/O: %s\n", xtt_strerror(server.rc));
  assert(server.rc==XTT_RETURN_WANT_PREPARSEIDCLIENTATTEST);
  server.rc=xtt_handshake_server_preparse_idclientattest(&client.bytes_requested, &client.io_ptr, &requested_client_id_out, &claimed_group_id_out, &server.cookie_ctx, &cert_ctx_s, &server.ctx);
  printf("server preparse idclientattest: %s\n", xtt_strerror(server.rc));
  //assert(server.rc==XTT_RETURN_WANT_VERIFYGROUPSIGNATURE);
  server.rc= xtt_handshake_server_verify_groupsignature(&server.bytes_requested, &server.io_ptr, &group_pub_key_ctx, &certificate_ctx, &server.ctx);
  //assert(server.rc==XTT_RETURN_WANT_BUILDIDSERVERFINISHED);
  server.rc= xtt_handshake_server_build_idserverfinished(&server.bytes_requested, &server.io_ptr, &client_id, &server.ctx);
  //assert(server.rc==XTT_RETURN_WANT_WRITE);
  server_write_to_network(&server, &network);
  //assert(server.rc==XTT_RETURN_HANDSHAKE_FINISHED);

//START CLIENT STEP 3
//******************************************************************
  client_read_from_network(&client, &network);
  //assert(client.rc== XTT_RETURN_WANT_PARSEIDSERVERFINISHED);
  client.rc=xtt_handshake_client_parse_idserverfinished(&client.bytes_requested, &client.io_ptr, &client.ctx);
  //assert(client.rc==XTT_RETURN_HANDSHAKE_FINISHED);
}






void client_write_to_network(struct xtt_client_ctxhelper* client, struct network_helper* network){
  clear_bytes(network);
  uint16_t bytes_to_write = client->bytes_requested;
  write_bytes(network, bytes_to_write, client->io_ptr);
  client->rc= xtt_handshake_client_handle_io(bytes_to_write, 0, &client->bytes_requested, &client->io_ptr, &client->ctx);
}

void client_read_from_network(struct xtt_client_ctxhelper* client, struct network_helper* network){
  uint16_t bytes_to_read = client->bytes_requested;
  read_bytes(network, bytes_to_read, client->io_ptr);
  client->rc= xtt_handshake_client_handle_io(0, bytes_to_read, &client->bytes_requested, &client->io_ptr, &client->ctx);
}

void server_write_to_network(struct xtt_server_ctxhelper* server, struct network_helper* network){
  clear_bytes(network);
  uint16_t bytes_to_write = server->bytes_requested;
  write_bytes(network, bytes_to_write, server->io_ptr);
  server->rc= xtt_handshake_server_handle_io(bytes_to_write, 0, &server->bytes_requested, &server->io_ptr, &server->ctx);
}

void server_read_from_network(struct xtt_server_ctxhelper* server, struct network_helper* network){
  uint16_t bytes_to_read = server->bytes_requested;
  read_bytes(network, bytes_to_read, server->io_ptr);
  server->rc= xtt_handshake_server_handle_io(0, bytes_to_read, &server->bytes_requested, &server->io_ptr, &server->ctx);
}

// void printArray(unsigned char* arr){
//   printf("here is the array:");
//   for(unsigned int i = 0; i<=(sizeof(arr)/sizeof(unsigned char)); i++){
//     printf("%c", arr[i]);
//   }
//   printf("\n");
// }


// void printServerData(struct xtt_server_handshake_context* ctx){
//   uint16_t message_length = xtt_serverinitandattest_total_length(ctx->base.version, ctx->base.suite_spec);
//   uint16_t bytes_io_performed_for_this_message = ctx->base.out_end - ctx->base.out_message_start;
//   unsigned char* outend = ctx->base.out_end;
//   unsigned char* msgstart = ctx->base.out_message_start;
//   printf("out end: %s\n", outend);
//   printf("message start: %s\n", msgstart);
//   printf("io_performed: %d\n", bytes_io_performed_for_this_message);
//   printf("message length: %d\n", message_length);
// }
