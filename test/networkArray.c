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
  unsigned char* arrptr;
  int head;
  int tail;
  int length;

};

bool isFull(struct network_helper* network){
  int i;
  int c = -1;
  for(i=0; i<network->length; i++){
    if(c==network->arrptr[i]){
      return false;
    }
  }
  return true;
}

void printArray(unsigned char* arr){
  printf("here is the array:");
  for(unsigned int i = 0; i<=(sizeof(arr)/sizeof(unsigned char)); i++){
    printf("%c", arr[i]);
  }
  printf("\n");
}

void setupNetwork(struct network_helper* network, unsigned char* netarr){
  network->arrptr= netarr;
  network->head= 0;
  network->tail = network->head;
  network->length= sizeof(netarr);
}

void add_bytes(struct network_helper* network, int numbytes, unsigned char* io_ptr){
  if(isFull(network)){
    printf("DOES NOT WORK\n");
    return;
  }
  int i;
  for(i=0; i<numbytes; i++){
    network->arrptr[network->tail] = *(io_ptr)++; //this does not increment on the original data yet
    network->tail = (network->tail+1)%(network->length);
  }
}

void delete_bytes(struct network_helper* network, int numbytes){
  int i;
  //unsigned char x = 0;
  for(i=0; i<numbytes; i++){
    network->arrptr[network->head]= -1;
    network->head = (network->head+1)%(network->length);
  }
}

int main(){
  printf("Hello, world\n");

  unsigned char array2[]= {'k', 't'};
  unsigned char io_ptr = array2[0];
  unsigned char myArray[]={'a', '2', '5', 'd', '9', 'x', 'y'};
  unsigned char* netarr = myArray;
  printArray(netarr);
  //unsigned char* io_ptr = &myArray[0];
  struct network_helper N;
  setupNetwork(&N, netarr);
  printf("%c\n", N.arrptr[N.head]);
  add_bytes(&N, 1, &io_ptr);
  printArray(N.arrptr);
}
