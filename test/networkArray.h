#ifndef NETWORKARRAY_H
#define NETWORKARRAY_H
#pragma once

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
// void printArrayc(const char* arr);
// void add_bytes(struct network_helper* network, int numbytes, unsigned char* io_ptr);
// void setLength(struct network_helper* network, uint16_t s);
// void delete_bytes(struct network_helper* network, int numbytes);

void setupNetwork(struct network_helper* network){
  network->head= network->array;
	network->filled= 0;
}

void read_bytes(struct network_helper* network, size_t numbytes, unsigned char* io_ptr){
	if(network->filled<numbytes){
		printf("the number of filled is less than the numbytes we want to read");
		exit(1);
	}
	memcpy(io_ptr, network->head, numbytes);
	network->head+=numbytes;//&network->array[network->filled+numbytes-1];
	network->filled-=numbytes;
	//network->remainingempty-=network->remainingempty;
}

void write_bytes(struct network_helper* network, size_t numbytes, unsigned char* io_ptr){
	if(network->filled+numbytes> MAX_HANDSHAKE_CLIENT_MESSAGE_LENGTH){
		printf("writes over the edge");
		exit(1);
	}

	memcpy(network->head, io_ptr, numbytes);
	//printf("zero: %c\n", network->array[0]);
	network->filled+= numbytes;
	//network->remainingempty-=numbytes;
}

void clear_bytes(struct network_helper* network){
	if(network->filled!=0){
		printf("head and filled do not match up--cannot clear");
	}
	network->head = network->array;
	network->filled=0;
}

void printArray(unsigned char* arr, unsigned int length){
  printf("here is the array: ");
  for(unsigned int i = 0; i<length; i++){
    printf("%x", arr[i]);
  }

  printf("\n");
}

#endif
