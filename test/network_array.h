#ifndef NETWORKARRAY_H
#define NETWORKARRAY_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

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
#include <stdbool.h>

#include <xtt/context.h>
#include <xtt/crypto_types.h>
#include <xtt/return_codes.h>


struct network_helper{
    unsigned char array[MAX_HANDSHAKE_CLIENT_MESSAGE_LENGTH];
  unsigned char* head;
  size_t filled;
};

// bool isFull(struct network_helper* network);
 void printArray(unsigned char* arr, unsigned int length);


void setupNetwork(struct network_helper* network){
    network->head= network->array;
    network->filled= 0;
}

void read_bytes(struct network_helper* network, size_t numbytes, unsigned char* io_ptr) {
    if (network->filled < numbytes) {
        exit(1);
    }
    memcpy(io_ptr, network->head, numbytes);
    network->head+=numbytes;//&network->array[network->filled+numbytes-1];
    network->filled-=numbytes;
    //network->remainingempty-=network->remainingempty;
}

void write_bytes(struct network_helper* network, size_t numbytes, unsigned char* io_ptr) {
    if (network->filled+numbytes> MAX_HANDSHAKE_CLIENT_MESSAGE_LENGTH){
        exit(1);
    }

    memcpy(network->head, io_ptr, numbytes);
    //printf("zero: %c\n", network->array[0]);
    network->filled += numbytes;
    //network->remainingempty-=numbytes;
}

void clear_bytes(struct network_helper* network){
    if(network->filled!=0){
        exit(1);
    }
    network->head = network->array;
    network->filled = 0;
}

void printArray (unsigned char* arr, unsigned int length) {
    printf("here is the array: ");
  for(unsigned int i = 0; i<length; i++){
    printf("%x", arr[i]);
  }

  printf("\n");
}

#ifdef __cplusplus
}
#endif

#endif
