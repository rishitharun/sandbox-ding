#ifndef BOOLEAN_H
#define BOOLEAN_H
typedef enum boolean{True=1,False=0} boolean;
#endif

#ifndef NODE_H
#define NODE_H
#include "datastructures/node.h"
#endif

//--------------------------------------------------------------------//

////* VARIABLES *////

typedef struct
{
  unsigned char datatype;
  unsigned char *identifier;
  unsigned char *value;
  unsigned char length;
  Node* members;
}UserVariable;

////* VARIABLES *////

//--------------------------------------------------------------------//

////* PACKETS *////

typedef enum
{
  EMPTY_CONTAINER,
  HARDWARE,
  HOST,
  PROCESS,
  PROCESS_TYPE,
  PAYLOAD
}Layer;

#define PMTU 576

typedef struct packt
{
  
  unsigned char protocol;
  unsigned char * packet_buff;
  unsigned short offset;
  unsigned short len;
  unsigned short * len_ptr;
  Layer layer;
  struct packt * above, * below;
}Packet;


////* PACKETS *////

//--------------------------------------------------------------------//

