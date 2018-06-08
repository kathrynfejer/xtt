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

//Helper functions and structs
struct xtt_client_ctxhelper{
  unsigned char in[MAX_HANDSHAKE_SERVER_MESSAGE_LENGTH];
  unsigned char out[MAX_HANDSHAKE_CLIENT_MESSAGE_LENGTH];
  struct xtt_client_handshake_context ctx;
  unsigned char *io_ptr;
  uint16_t bytes_requested;
  xtt_return_code_type rc;
};

struct xtt_server_ctxhelper{
  unsigned char in[MAX_HANDSHAKE_CLIENT_MESSAGE_LENGTH];
  unsigned char out[MAX_HANDSHAKE_SERVER_MESSAGE_LENGTH];
  struct xtt_server_handshake_context ctx;
  unsigned char *io_ptr;
  uint16_t bytes_requested;
  xtt_return_code_type rc;
  struct xtt_server_cookie_context cookie_ctx;
};


void client_write_to_network(struct xtt_client_ctxhelper* client);
void client_read_from_network(struct xtt_client_ctxhelper* client);
void server_write_to_network(struct xtt_server_ctxhelper* server);
void server_read_from_network(struct xtt_server_ctxhelper* server);

void printArray(unsigned char* arr);
void printState(struct xtt_client_handshake_context ctx);
void printServerData(struct xtt_server_handshake_context* ctx);
void makeAssortedBuffers(void);

//global variables
unsigned char network[1024];


int main()
{
  //initialize structs and important pointers
  struct xtt_client_ctxhelper client;
  struct xtt_server_ctxhelper server;

  client.bytes_requested=0;
  server.bytes_requested=0;
  uint16_t msglen;

  xtt_certificate_root_id claimed_root_out;
  const struct xtt_server_root_certificate_context root_server_cert;
  const xtt_identity_type requested_client_id;
  const xtt_identity_type client_id;
  const xtt_identity_type intended_server_id;
  struct xtt_client_group_context group_ctx;
  struct xtt_server_certificate_context cert_ctx_s;
  const unsigned char serialized_certificate;
  const xtt_ed25519_priv_key private_key_s;
  xtt_identity_type requested_client_id_out;
  xtt_group_id claimed_group_id_out;
  struct xtt_group_public_key_context group_pub_key_ctx;
  const struct xtt_server_certificate_context certificate_ctx;

  xtt_version version = XTT_VERSION_ONE;
  // xtt_suite_spec suite_spec = XTT_X25519_LRSW_ED25519_CHACHA20POLY1305_SHA512;
  // xtt_suite_spec suite_spec = XTT_X25519_LRSW_ED25519_CHACHA20POLY1305_BLAKE2B;
  xtt_suite_spec suite_spec = XTT_X25519_LRSW_ED25519_AES256GCM_SHA512;
  // xtt_suite_spec suite_spec = XTT_X25519_LRSW_ED25519_AES256GCM_BLAKE2B;


  server.rc = xtt_initialize_server_certificate_context_ed25519(&cert_ctx_s, &serialized_certificate, &private_key_s);
  assert(server.rc==XTT_RETURN_SUCCESS);
  server.rc= xtt_initialize_server_cookie_context(&server.cookie_ctx);
  assert(server.rc==XTT_RETURN_SUCCESS);

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
  client_write_to_network(&client);
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
  server_read_from_network(&server);
  printf("1 handshake server after read from network: %s\n", xtt_strerror(server.rc));
  printf("bytes requested after 1st read from net: %hu \n", server.bytes_requested);
  server_read_from_network(&server);
  printf("2 handshake server after read from network: %s\n", xtt_strerror(server.rc));
  printf("bytes req after 2nd read from net: %hu \n", server.bytes_requested);
  assert(server.rc==XTT_RETURN_WANT_BUILDSERVERATTEST);
  server.rc= xtt_handshake_server_build_serverattest(&server.bytes_requested, &server.io_ptr, &server.ctx, &cert_ctx_s, &server.cookie_ctx);
  printf("handshake server build server attest: %s\n", xtt_strerror(server.rc));
  //assert(server.rc==XTT_RETURN_WANT_WRITE);
  server_write_to_network(&server);
  printf("after write to network's I/0: %s\n", xtt_strerror(server.rc));
  assert(server.rc==XTT_RETURN_WANT_READ);

//START CLIENT STEP 2
//****************************************************************
  client_read_from_network(&client);
  printf("client read from network read I/O: %s\n", xtt_strerror(client.rc));
  //assert(client.rc==XTT_CLIENT_HANDSHAKE_STATE_PREPARSING_SERVERATTEST);
  client.rc=xtt_handshake_client_preparse_serverattest(&claimed_root_out, &client.bytes_requested, &client.io_ptr, &client.ctx);
  printf("client preparse server attest: %s\n", xtt_strerror(client.rc));
  //assert(client.rc==XTT_CLIENT_HANDSHAKE_STATE_BUILDING_IDCLIENTATTEST);
  client.rc=xtt_handshake_client_build_idclientattest(&client.bytes_requested, &client.io_ptr, &root_server_cert, &requested_client_id, &intended_server_id, &group_ctx, &client.ctx);
  printf("client build idclientattest: %s\n", xtt_strerror(client.rc));
  //assert(client.rc==XTT_RETURN_WANT_WRITE);
  client_write_to_network(&client);
  printf("client write to network I/O: %s\n", xtt_strerror(client.rc));
  //assert(client.rc==XTT_RETURN_WANT_READ);

//START CLIENT STEP 2
//********************************************************************
  server_read_from_network(&server);
  printf("server read from network read I/O: %s\n", xtt_strerror(server.rc));
  //assert(server.rc==XTT_RETURN_WANT_PREPARSEIDCLIENTATTEST);
  server.rc=xtt_handshake_server_preparse_idclientattest(&client.bytes_requested, &client.io_ptr, &requested_client_id_out, &claimed_group_id_out, &server.cookie_ctx, &cert_ctx_s, &server.ctx);
  printf("server preparse idclientattest: %s\n", xtt_strerror(server.rc));
  //assert(server.rc==XTT_RETURN_WANT_VERIFYGROUPSIGNATURE);
  server.rc= xtt_handshake_server_verify_groupsignature(&server.bytes_requested, &server.io_ptr, &group_pub_key_ctx, &certificate_ctx, &server.ctx);
  //assert(server.rc==XTT_RETURN_WANT_BUILDIDSERVERFINISHED);
  server.rc= xtt_handshake_server_build_idserverfinished(&server.bytes_requested, &server.io_ptr, &client_id, &server.ctx);
  //assert(server.rc==XTT_RETURN_WANT_WRITE);
  server_write_to_network(&server);
  //assert(server.rc==XTT_RETURN_HANDSHAKE_FINISHED);

//START CLIENT STEP 3
//******************************************************************
  client_read_from_network(&client);
  //assert(client.rc== XTT_RETURN_WANT_PARSEIDSERVERFINISHED);
  client.rc=xtt_handshake_client_parse_idserverfinished(&client.bytes_requested, &client.io_ptr, &client.ctx);
  //assert(client.rc==XTT_RETURN_HANDSHAKE_FINISHED);
}

void client_write_to_network(struct xtt_client_ctxhelper* client){
  uint16_t bytes_to_write = client->bytes_requested;
  memcpy(network, client->io_ptr, bytes_to_write);
  client->rc= xtt_handshake_client_handle_io(bytes_to_write, 0, &client->bytes_requested, &client->io_ptr, &client->ctx);
}

void client_read_from_network(struct xtt_client_ctxhelper* client){
  uint16_t bytes_to_read = client->bytes_requested;
  memcpy(client->io_ptr, network, bytes_to_read);
  client->rc= xtt_handshake_client_handle_io(0, bytes_to_read, &client->bytes_requested, &client->io_ptr, &client->ctx);
}

void server_write_to_network(struct xtt_server_ctxhelper* server){
  uint16_t bytes_to_write = server->bytes_requested;
  memcpy(network, server->io_ptr, bytes_to_write);
  server->rc= xtt_handshake_server_handle_io(bytes_to_write, 0, &server->bytes_requested, &server->io_ptr, &server->ctx);
}

void server_read_from_network(struct xtt_server_ctxhelper* server){
  uint16_t bytes_to_read = server->bytes_requested;
  printf("bytes to read:%hu \n", server->bytes_requested);
  memcpy(server->io_ptr, network, bytes_to_read);
  server->rc= xtt_handshake_server_handle_io(0, bytes_to_read, &server->bytes_requested, &server->io_ptr, &server->ctx);
}

void printArray(unsigned char* arr){
  printf("here is the array:");
  for(unsigned int i = 0; i<=(sizeof(arr)/sizeof(unsigned char)); i++){
    printf("%c", arr[i]);
  }
  printf("\n");
}

void printState(struct xtt_client_handshake_context ctx){
  xtt_client_handshake_state state = ctx.state;
  printf("%d\n", state);
}

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

// void makeAssortedBuffers(void){
//   //read in from files for data
//   unsigned char priv_key_buff[64];
//   read_file_into_buffer(priv_key_buff, 64, "../examples/data/server/server_privatekey.bin");
//   unsigned char server_cert_buff[XTT_SERVER_CERTIFICATE_ED25519_LENGTH];
//   read_file_into_buffer(server_cert_buff, XTT_SERVER_CERTIFICATE_ED25519_LENGTH, "../examples/data/server/server_certificate.txt");
//   unsigned char requID[8];
//   read_file_into_buffer(requID, 8, "../examples/data/client/requested_client_id.bin");
//   unsigned char rootID_buff[64];
//   read_file_into_buffer(rootID_buff, 64, "../examples/data/client/root_id.bin");
//   unsigned char rootPub_buff[64];
//   read_file_into_buffer(rootPub_buff, 64, "../examples/data/client/root_pub.bin");
//   unsigned char serverID[64];
//   read_file_into_buffer(serverID, 64, "../examples/data/client/server_id.bin");
//   unsigned char client_secretkey[64];
//   read_file_into_buffer(client_secretkey, 64, "../examples/data/client/daa_secretkey.bin");
//   printArray(client_secretkey);
// }
