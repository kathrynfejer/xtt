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
#include "network_array.h"
#include "server_setup.h"
#include "client_setup.h"

#include <xtt/context.h>
#include <xtt/crypto_types.h>
#include <xtt/return_codes.h>



void client_write_to_network(struct xtt_client_ctxhelper* client, struct network_helper* network);
void client_read_from_network(struct xtt_client_ctxhelper* client, struct network_helper* network);
void server_write_to_network(struct xtt_server_ctxhelper* server, struct network_helper* network);
void server_read_from_network(struct xtt_server_ctxhelper* server, struct network_helper* network);


int main()
{
    struct xtt_client_ctxhelper client;
    struct xtt_server_ctxhelper server;

    struct network_helper network;
    setupNetwork(&network);

    client.bytes_requested=0;
    server.bytes_requested=0;

    xtt_certificate_root_id claimed_root_out;
    struct xtt_server_root_certificate_context server_root_cert;
    const xtt_identity_type client_id;
    const xtt_identity_type intended_server_id = {.data = {0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x31}};
    xtt_identity_type requested_client_id_out;
    xtt_group_id claimed_group_id_out;
    struct xtt_server_certificate_context cert_ctx_s;
    struct xtt_group_public_key_context group_pub_key_ctx;
    struct xtt_client_group_context group_ctx;

    const xtt_daa_group_pub_key_lrsw gpk={.data={
        0x04, 0x73, 0x64, 0xff, 0x42, 0xe1, 0x07, 0x6a, 0xa2, 0x92, 0xe9, 0x56,
        0x1f, 0xe9, 0x6e, 0x08, 0xca, 0x0f, 0x52, 0x56, 0xa7, 0xf6, 0x14, 0xbc,
        0xed, 0x24, 0x6e, 0x1b, 0x5f, 0x02, 0xcc, 0x29, 0x32, 0x4c, 0x54, 0x63,
        0xaf, 0x7d, 0xda, 0xd9, 0x50, 0xf9, 0x73, 0xe5, 0x25, 0x0a, 0x04, 0x1d,
        0x2a, 0x2f, 0xdc, 0x5f, 0xcb, 0x46, 0x69, 0x6a, 0xe8, 0x90, 0x76, 0x74,
        0xdd, 0xd2, 0x76, 0xf0, 0xa6, 0xef, 0xab, 0x22, 0x2b, 0x6a, 0x34, 0x37,
        0x3b, 0xf6, 0x22, 0xf0, 0x87, 0xf2, 0x9b, 0x6f, 0x2e, 0xa7, 0x57, 0x65,
        0x7b, 0xd6, 0xc9, 0x04, 0x9a, 0x15, 0xff, 0x50, 0x5a, 0x61, 0xa3, 0x97,
        0xe0, 0x43, 0x1b, 0x15, 0xb6, 0xf0, 0x5e, 0xba, 0x4a, 0xf2, 0x9b, 0xca,
        0xd7, 0xd9, 0x6c, 0xbd, 0x15, 0x90, 0x79, 0x25, 0x3b, 0x44, 0x4e, 0xe8,
        0xd4, 0xff, 0x57, 0x52, 0x93, 0xe3, 0xe4, 0x84, 0x04, 0x04, 0x70, 0xe2,
        0x7d, 0x8a, 0x09, 0x34, 0x24, 0x58, 0x3c, 0xaa, 0x6a, 0xb8, 0x64, 0x57,
        0xce, 0x7d, 0x54, 0xd1, 0x4f, 0x04, 0xba, 0xd0, 0xf6, 0x17, 0xd5, 0xe9,
        0xce, 0x45, 0x30, 0xdf, 0xae, 0x81, 0xd2, 0xf4, 0x8f, 0x32, 0xa9, 0xbe,
        0xd3, 0x52, 0x31, 0x49, 0x04, 0x5a, 0x36, 0x33, 0x1d, 0xf5, 0xed, 0xe6,
        0x00, 0xe8, 0x60, 0x16, 0xba, 0x48, 0x29, 0x61, 0x52, 0x97, 0x94, 0xf3,
        0x7f, 0x5e, 0x60, 0x20, 0x0f, 0x9c, 0x77, 0x65, 0xc1, 0x31, 0xdb, 0x74,
        0xdc, 0xa0, 0xf1, 0xd0, 0xe2, 0x04, 0x2b, 0x76, 0xba, 0xaa, 0x88, 0x06,
        0x1c, 0xc1, 0x3a, 0xd3, 0x29, 0x5d, 0xa2, 0xcc, 0xbd, 0xd3, 0x8d, 0xab,
        0x99, 0xd2, 0x8f, 0x29, 0x0e, 0xd5, 0x16, 0x4b, 0x4b, 0x22, 0x39, 0x43,
        0xc1, 0x38, 0x6e, 0x5a, 0x40, 0xa1, 0x37, 0xd3, 0xf7, 0xb4, 0x4a, 0xe7,
        0xb1, 0x48, 0x77, 0xba, 0x97, 0x65}};

    setup_server_input(&server, &cert_ctx_s, &group_pub_key_ctx, &gpk);
    setup_client_input(&server_root_cert, &client, &group_ctx);

    xtt_version version = XTT_VERSION_ONE;
    // xtt_suite_spec suite_spec = XTT_X25519_LRSW_ED25519_CHACHA20POLY1305_SHA512;
    // xtt_suite_spec suite_spec = XTT_X25519_LRSW_ED25519_CHACHA20POLY1305_BLAKE2B;
    xtt_suite_spec suite_spec = XTT_X25519_LRSW_ED25519_AES256GCM_SHA512;
    // xtt_suite_spec suite_spec = XTT_X25519_LRSW_ED25519_AES256GCM_BLAKE2B;

    //*************************************************************************
    //Initializing client and server handshake contexts
    client.rc = xtt_initialize_client_handshake_context(&client.ctx, client.in , sizeof(client.in), client.out, sizeof(client.out), version, suite_spec);
    assert(client.rc == XTT_RETURN_SUCCESS);
    server.rc = xtt_initialize_server_handshake_context(&server.ctx, server.in, sizeof(server.in), server.out, sizeof(server.out));
    assert(server.rc == XTT_RETURN_SUCCESS);


    //START CLIENT STEP 1
    //***********************************************************************
    client.rc = xtt_handshake_client_start(&client.bytes_requested, &client.io_ptr, &client.ctx);
    assert(client.rc == XTT_RETURN_WANT_WRITE);
    client_write_to_network(&client, &network);
    assert(client.rc == XTT_RETURN_WANT_READ);
    printf("Passes all of client step 1\n");

    //START SERVER STEP 1
    //**************************************************************
    server.rc=xtt_handshake_server_handle_connect(&server.bytes_requested, &server.io_ptr, &server.ctx);
    assert(server.rc == XTT_RETURN_WANT_READ);
    server_read_from_network(&server, &network);
    assert(server.rc == XTT_RETURN_WANT_READ);
    server_read_from_network(&server, &network);
    assert(server.rc == XTT_RETURN_WANT_BUILDSERVERATTEST);
    server.rc = xtt_handshake_server_build_serverattest(&server.bytes_requested, &server.io_ptr, &server.ctx, &cert_ctx_s, &server.cookie_ctx);
    assert(server.rc == XTT_RETURN_WANT_WRITE);
    server_write_to_network(&server, &network);
    assert(server.rc == XTT_RETURN_WANT_READ);
    printf("Passes all of server step 1\n");
    //START CLIENT STEP 2
    //****************************************************************
    client_read_from_network(&client, &network);
    client_read_from_network(&client, &network);
    assert(client.rc == XTT_RETURN_WANT_PREPARSESERVERATTEST);
    client.rc=xtt_handshake_client_preparse_serverattest(&claimed_root_out,
                                                    &client.bytes_requested,
                                                    &client.io_ptr,
                                                    &client.ctx);
    assert(client.rc == XTT_RETURN_WANT_BUILDIDCLIENTATTEST);
    client.rc=xtt_handshake_client_build_idclientattest(&client.bytes_requested,
                                                    &client.io_ptr,
                                                    &server_root_cert,
                                                    &xtt_null_identity,
                                                    &intended_server_id,
                                                    &group_ctx,
                                                    &client.ctx);
    assert(client.rc == XTT_RETURN_WANT_WRITE);
    client_write_to_network(&client, &network);
    assert(client.rc == XTT_RETURN_WANT_READ);
    printf("Passes all of client step 2\n");

    //START SERVER STEP 2
    //********************************************************************
    server_read_from_network(&server, &network);
    assert(server.rc == XTT_RETURN_WANT_READ);
    server_read_from_network(&server, &network);
    assert(server.rc == XTT_RETURN_WANT_PREPARSEIDCLIENTATTEST);
    server.rc=xtt_handshake_server_preparse_idclientattest(&client.bytes_requested, &client.io_ptr, &requested_client_id_out, &claimed_group_id_out, &server.cookie_ctx, &cert_ctx_s, &server.ctx);
    assert(server.rc == XTT_RETURN_WANT_VERIFYGROUPSIGNATURE);
    server.rc = xtt_handshake_server_verify_groupsignature(&server.bytes_requested,
                                                        &server.io_ptr,
                                                        &group_pub_key_ctx,
                                                        &cert_ctx_s,
                                                        &server.ctx);
    assert(server.rc == XTT_RETURN_WANT_BUILDIDSERVERFINISHED);
    server.rc = xtt_handshake_server_build_idserverfinished(&server.bytes_requested,
                                                        &server.io_ptr,
                                                        &client_id,
                                                        &server.ctx);
    assert(server.rc == XTT_RETURN_WANT_WRITE);
    server_write_to_network(&server, &network);
    assert(server.rc == XTT_RETURN_HANDSHAKE_FINISHED);
    printf("Passes all of server step 2\n");

    //START CLIENT STEP 3
    //******************************************************************
    client_read_from_network(&client, &network);
    assert(client.rc == XTT_RETURN_WANT_READ);
    client_read_from_network(&client, &network);
    assert(client.rc == XTT_RETURN_WANT_PARSEIDSERVERFINISHED);
    client.rc=xtt_handshake_client_parse_idserverfinished(&client.bytes_requested, &client.io_ptr, &client.ctx);
    assert(client.rc == XTT_RETURN_HANDSHAKE_FINISHED);
    printf("Passes all of client step 3- Handshake Completed\n");
}


void client_write_to_network(struct xtt_client_ctxhelper* client, struct network_helper* network){
    clear_bytes(network);
    uint16_t bytes_to_write = client->bytes_requested;
    write_bytes(network, bytes_to_write, client->io_ptr);
    client->rc = xtt_handshake_client_handle_io(bytes_to_write, 0, &client->bytes_requested, &client->io_ptr, &client->ctx);
}

void client_read_from_network(struct xtt_client_ctxhelper* client, struct network_helper* network){
    uint16_t bytes_to_read = client->bytes_requested;
    read_bytes(network, bytes_to_read, client->io_ptr);
    client->rc = xtt_handshake_client_handle_io(0, bytes_to_read, &client->bytes_requested, &client->io_ptr, &client->ctx);
}

void server_write_to_network(struct xtt_server_ctxhelper* server, struct network_helper* network){
    clear_bytes(network);
    uint16_t bytes_to_write = server->bytes_requested;
    write_bytes(network, bytes_to_write, server->io_ptr);
    server->rc = xtt_handshake_server_handle_io(bytes_to_write, 0, &server->bytes_requested, &server->io_ptr, &server->ctx);
}

void server_read_from_network(struct xtt_server_ctxhelper* server, struct network_helper* network){
    uint16_t bytes_to_read = server->bytes_requested;
    read_bytes(network, bytes_to_read, server->io_ptr);
    server->rc = xtt_handshake_server_handle_io(0, bytes_to_read, &server->bytes_requested, &server->io_ptr, &server->ctx);
}

// void printArray(unsigned char* arr){
//   printf("here is the array:");
//   for(unsigned int i = 0; i<=(sizeof(arr)/sizeof(unsigned char)); i++){
//     printf("%c", arr[i]);
//   }
//   printf("\n");
// }
