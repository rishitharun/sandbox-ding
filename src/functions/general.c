#include "functions/print.h"
#include "functions/general.h"

#include "net/sockets.h"
#include "net/interface.h"
#include "net/members/all.h"
#include "net/createpacket.h"

#include "datastructures/bst.h"
#include "datastructures/stack.h"

#include "utils/base.h"
#include "utils/string.h"

#include "codes/packet.h"
#include "codes/datatype.h"

#include "logger.h"


extern int sock_desc;
extern int interface;
extern BinarySearchTree* packet_tree;
extern short jump_offset;
extern boolean condition, in_loop, if_block;
extern Stack* condition_stack;

static short nullifyChecksum(Packet* packet)
{
  unsigned char packet_type = packet->protocol;

  switch(packet_type)
  {
    case __IP4:
      ((struct ip4_head*) (packet->packet_buff + packet->offset))->header_chksum = 0;
      return packet->len;

    case __ICMP:
      ((struct icmp_head*)(packet->packet_buff + packet->offset))->checksum = 0;
      return *(packet->len_ptr) - packet->offset;

    default:
      return 0;
  }
}

UserVariable* ifcond(Node* args)
{
  if(args == NULL)
  {
    fprintf(stderr, ERROR"Please specify a condition for the loop statement !\n"RESET);
    return NULL;
  }
  else {;}

  UserVariable* condition_val = (UserVariable*)(((Node*)(args->data))->data);

  if(!condition_val->length)
  {
    fprintf(stderr, ERROR"Invalid Condition !\nCondition variable <%s> not defined !\n"RESET, condition_val->identifier);
    return NULL;
  }
  else {;}

  if(condition_val->datatype != NUMBER_TYPE_CODE)
  {
    fprintf(stderr, ERROR"Condition must be or return number type !\n"RESET);
    return NULL;
  }
  else {;}

  if_block = True;

  if(*(condition_val->value) == 0) condition = False;
  else condition = True;

  return condition_val;
}

UserVariable* loop(Node* args)
{
  if(args == NULL)
  {
    fprintf(stderr, ERROR"Please specify a condition for the loop statement !\n"RESET);
    return NULL;
  }
  else {;}

  UserVariable* condition_val = (UserVariable*)(((Node*)(args->data))->data);

  if(!condition_val->length)
  {
    fprintf(stderr, ERROR"Invalid Condition !\nCondition variable <%s> not defined !\n"RESET, condition_val->identifier);
    return NULL;
  }
  else {;}

  if(condition_val->datatype != NUMBER_TYPE_CODE)
  {
    fprintf(stderr, ERROR"Condition must be or return number type !\n"RESET);
    return NULL;
  }
  else {;}

  #if LOGGING_ENABLED(LOG_CONTROL_STRUCTURES)
    CS_LOGGING_UTIL0("loop","Checking looping condition");
  #endif

  in_loop = True;

  #if LOGGING_ENABLED(LOG_CONTROL_STRUCTURES)
    CS_LOGGING_UTIL0("loop","in_loop set to True");
  #endif

  if(*(condition_val->value) == 0) condition = False;
  else condition = True;

  #if LOGGING_ENABLED(LOG_CONTROL_STRUCTURES)
    CS_LOGGING_UTIL1("loop","condition evaluated to %s",(condition)?"True":"False");
  #endif

  unsigned short* pushData = (short*) malloc(3*sizeof(short));
  *(pushData+0) = jump_offset;
  *(pushData+1) = in_loop;
  *(pushData+2) = condition;

  #if LOGGING_ENABLED(LOG_CONTROL_STRUCTURES)
    CS_LOGGING_UTIL0("loop","loop control data before pushing to stack");
    CS_LOGGING_UTIL0("loop","-----------------------------------------");
    CS_LOGGING_UTIL1("loop","jump_offset %d",jump_offset);
    CS_LOGGING_UTIL1("loop","in_loop %d", in_loop);
    CS_LOGGING_UTIL1("loop","condition %d", condition);
    CS_LOGGING_UTIL0("loop","-----------------------------------------");
  #endif

  pushStack(condition_stack, (char*) pushData);

  #if LOGGING_ENABLED(LOG_CONTROL_STRUCTURES)
    CS_LOGGING_UTIL0("loop","loop control data pushed to stack\n");
  #endif
  return condition_val;
}

UserVariable* interfacefunc(Node* args)
{
  if(args == NULL)
  {
    fprintf(stderr, ERROR"interface() requires an argument !\nPlease specify an interface name !\n"RESET);
    return NULL;
  }
  else {;}

  UserVariable* value = (UserVariable*)(((Node*)(args->data))->data);
  if(value->datatype != STRING_TYPE_CODE)
  {
    fprintf(stderr, ERROR"interface() requires a <string> argument !\nPlease specify the interface name as string !\n"RESET);
    return NULL;
  }
  else {;}
  if (getInterface(value->value,value->length)) {;}  
  else return NULL;
  return value;
  
}

#include <errno.h>

UserVariable* sendfunc(Node* args)
{
  UserVariable* return_var = (UserVariable*) malloc(1*sizeof(UserVariable));
  return_var->identifier = NULL;
  return_var->datatype = NUMBER_TYPE_CODE;
  return_var->value = (char*) malloc(1*sizeof(char));
  return_var->length = 1;

  while(args != NULL)
  {
    UserVariable* packet_variable = (UserVariable*)(((Node*)(args->data))->data);

    if(!packet_variable->length)
    {
      fprintf(stderr, ERROR"Variable <%s> not defined !\n"RESET, packet_variable->identifier);
      free(return_var->value);
      free(return_var);
      return NULL;
    }

    else {;}
    if(packet_variable->datatype != PACKET_TYPE_CODE || ((Packet * )(packet_variable->value))->layer != EMPTY_CONTAINER)
    {
      fprintf(stderr, ERROR"Invalid argument !\nsend() takes only base packet arguments !\n"RESET);
      free(return_var->value);
      free(return_var);
      return NULL;
    }
    else {;}

    Packet* packet = (Packet*) packet_variable->value;

    short status;
    char* bytedata = packet->packet_buff;
    unsigned short len = packet->len;
    short i=0;
    char buff[len];
    struct sockaddr_ll inface = { .sll_ifindex = interface };

    for(;i<len;i++) buff[i]=*(bytedata+i);

    status = sendto(sock_desc, buff, len, 0, (struct sockaddr*)&inface, sizeof(inface));

    if(status<0)
    {
      fprintf(stderr, ERROR"Packet was not sent !\nCheck whether you have forgot to set the interface...\n"RESET);
//     HAVE IN LOGS: fprintf(stderr, ERROR"errno <%d>\n",errno);
      free(return_var->value);
      free(return_var);
      return NULL;
    }
    else *(return_var->value) = 1;
    args = (Node*)args->right;
  }

  return return_var;
}

UserVariable* recvfunc(Node* args)
{
  boolean found = False;
  short cstr_buff_ind, len;
  unsigned char* cstr = NULL;
  char cstr_len = 0;
  if(args != NULL)
  {
    UserVariable* value = (UserVariable*)(((Node*)(args->data))->data);
    cstr = value->value;
    cstr_len = value->length;

    #if LOGGING_ENABLED(LOG_NETWORK) > 0
      NETWORK_LOGGING_UTIL0("Condition String Passed to receive()");
      logHexDump(cstr, cstr_len);
    #endif
  }
  else {;}

  unsigned char* buff = (char*) malloc(1024);

  if(cstr !=  NULL)
  {
    while(True)
    {
      cstr_buff_ind = 0;
      len = recvfrom(sock_desc, buff, 1024, 0, NULL, NULL);
      if (buff == NULL) continue;
      else {;}

      #if LOGGING_ENABLED(LOG_NETWORK) > 0
        NETWORK_LOGGING_UTIL0("Packet Received");
        logHexDump(buff, len);
        NETWORK_LOGGING_UTIL0("Scanning Packet");
      #endif

      while((cstr_buff_ind < len) && (cstr_buff_ind < cstr_len))
      {
        #if LOGGING_ENABLED(LOG_NETWORK) > 0
        NETWORK_LOGGING_UTIL2("CString Buffer Index %d and Value 0x%02x before getting offsets",cstr_buff_ind,*(cstr+cstr_buff_ind));
        #endif

        short start = *((short*)(cstr+cstr_buff_ind++));
        short end = *((short*)(cstr+(++cstr_buff_ind)));
        cstr_buff_ind++; cstr_buff_ind++;

        #if LOGGING_ENABLED(LOG_NETWORK) > 0
        NETWORK_LOGGING_UTIL1("Start Offset from CStr is %d",start);
        NETWORK_LOGGING_UTIL1("End Offset from CStr is %d",end);
        NETWORK_LOGGING_UTIL2("CString Buffer Index %d and Value 0x%02x after getting offsets",cstr_buff_ind, *(cstr+cstr_buff_ind));
        #endif

        short ind = 0;
        for(;ind < end-start; ind++)
        {
          if( *(((unsigned char*)cstr)+cstr_buff_ind++) == *(buff+start+ind)) found = True;
          else
          {
            #if LOGGING_ENABLED(LOG_NETWORK) > 0
            NETWORK_LOGGING_UTIL0("Packet Not desired");
            NETWORK_LOGGING_UTIL0("--------------");
            NETWORK_LOGGING_UTIL0("Mismatch Stats");
            NETWORK_LOGGING_UTIL0("--------------");
            NETWORK_LOGGING_UTIL2("Packet index is %d, Value at packet index is 0x%02x",start+ind, *(buff+start+ind));
            NETWORK_LOGGING_UTIL2("CStr buff index is %d, Value at CStr buff index is 0x%02x",cstr_buff_ind-1, *(cstr+cstr_buff_ind-1));
            NETWORK_LOGGING_UTIL0("Looking for next packet\n");
            #endif

          found = False;
          break;
          }
        }
        if(!found) break;
        else
        { ;
          #if LOGGING_ENABLED(LOG_NETWORK) > 0
          NETWORK_LOGGING_UTIL0("Block in CStr found in received packet");
          NETWORK_LOGGING_UTIL0("Checking next Block\n");
          #endif
        }
      }
      if(found)
      {
        #if LOGGING_ENABLED(LOG_NETWORK) > 0
        NETWORK_LOGGING_UTIL0("Desired packet found");
        NETWORK_LOGGING_UTIL0("Breaking out from receive()\n");
        #endif
        break;
      }
      else {;}
    }
  }
  else
  {
    do
    {
      len = recvfrom(sock_desc, buff, 1024, 0, NULL, NULL);
    }while(buff == NULL);

    #if LOGGING_ENABLED(LOG_NETWORK) > 0
      NETWORK_LOGGING_UTIL0("Condition String NOT Passed to receive()");
      NETWORK_LOGGING_UTIL0("Packet Received");
      logHexDump(buff, len);
    #endif
  }

  Packet* receivedPacket = (Packet*) malloc(sizeof(Packet));

  receivedPacket->packet_buff = buff;
  receivedPacket->len = len;
  receivedPacket->layer = EMPTY_CONTAINER;

  UserVariable* return_var = (UserVariable*) malloc(1*sizeof(UserVariable));
  return_var->identifier = NULL;
  return_var->datatype = PACKET_TYPE_CODE;
  return_var->value = (char*) receivedPacket;
  return_var->length = 2;

  return return_var;
}

UserVariable* cat(Node* args)
{
  UserVariable* return_var = (UserVariable*) malloc(1*sizeof(UserVariable));
  return_var->identifier = NULL;
  return_var->datatype = STRING_TYPE_CODE;
  return_var->value = (char*) malloc(1*sizeof(char));
  return_var->length = 0;

  short index = 0;

  while(args != NULL)
  {
    UserVariable* value = (UserVariable*)(((Node*)(args->data))->data);

    if(!value->length)
    {
      fprintf(stderr, ERROR"Variable <%s> not defined !\n"RESET, value->identifier);
      free(return_var->value);
      free(return_var);
      return NULL;
    }
    else {;}

    if(value->datatype != STRING_TYPE_CODE) return_var->datatype = STREAM_TYPE_CODE;
    else {;}

    short i=0, arg_len = value->length;
    (return_var->length) += arg_len;

    return_var->value = (char*) realloc(return_var->value, return_var->length);
    while(i<arg_len) *(return_var->value+index++) = *(((char*)(value->value))+i++);

    args = (Node*)args->right;
  }
  return return_var;
}

UserVariable* container(Node* args)
{
  Packet * packet;
  if(args == NULL)
  {
    UserVariable* return_var = (UserVariable*) malloc(1*sizeof(UserVariable));
    return_var->identifier = NULL;
    return_var->datatype = PACKET_TYPE_CODE;
    return_var->value = (unsigned char* ) createPacket(__EMPTY, NULL);
    return_var->length = 1;
    return_var->members = NULL;

    return return_var;
   }
  else if (args != NULL && args->right == NULL) {fprintf(stderr, ERROR"Need two args (protocol and base container) !"RESET); return NULL;}
  else {;}

  UserVariable * proto = (UserVariable*)(((Node*)(args->data))->data);
  UserVariable * base = (UserVariable*)(((Node*)(args->right->data))->data);

  if(base->value == NULL) {fprintf(stderr, DEBUG"[DEBUG INFO]: "RESET"look at this in container() in src/functions/general.c\n"); return NULL;}
  else {;}

  if(proto->datatype == STRING_TYPE_CODE) {;}
  else { fprintf(stderr, ERROR"Please pass packet name string as first argument ! \n"RESET); return NULL; }

  if(base->datatype == PACKET_TYPE_CODE && ((Packet *) (base->value))->layer == EMPTY_CONTAINER) {;}
  else { fprintf(stderr, ERROR"Please pass a base packet as second argument ! \n"RESET); return NULL; }

  char* packet_name = proto->value;
  short* index = (short*) malloc(sizeof(short));

  BinarySearchTree* current = packet_tree;

  UserVariable* return_var = (UserVariable*) malloc(1*sizeof(UserVariable));
  return_var->identifier = NULL;
  return_var->datatype = PACKET_TYPE_CODE;
  return_var->value = NULL;
  return_var->length = 1;
  return_var->members = NULL;

  while(*(packet_name))
  {
    current = getNode(current, *(packet_name++), index);

    if (current == NULL) { free(index); free(return_var); return NULL; }
    else {;}
  }

  if(!*((current->key)+(*index)))
  {
    return_var->value = (unsigned char *) createPacket(current->type, (Packet *) (base->value));
    return_var->members = (Node*) current->data;
  }
  else { free(index); free(return_var); return NULL; }

  if(return_var->value == NULL)  { free(index); free(return_var); return NULL; }
  else {;}

  free(index);
  return return_var;
}

UserVariable* print(Node* args)
{
  UserVariable* return_var = (UserVariable*) malloc(1*sizeof(UserVariable));
  return_var->identifier = NULL;
  return_var->datatype = NUMBER_TYPE_CODE;
  return_var->value = (char*) malloc(1*sizeof(char));
  return_var->length = 1;

  *(return_var->value) = 0;

  while(args != NULL)
  {
    UserVariable* value = (UserVariable*)(((Node*)(args->data))->data);

    if(!value->length)
    {
      fprintf(stderr, ERROR"Variable <%s> not defined !\n"RESET, value->identifier);
      free(return_var->value);
      free(return_var);
      return NULL;
    }
    else {;}
    *(return_var->value) += 1;

    switch(value->datatype)
    {
      case STRING_TYPE_CODE:
        printStr(value->value);
        break;
      case STREAM_TYPE_CODE:
        printHexDump(value->value, value->length);
        break;
      case IP4_TYPE_CODE:
        printIp4(value->value);
        break;
      case IP6_TYPE_CODE:
        printIp6(value->value);
        break;
      case MAC_TYPE_CODE:
        printMac(value->value);
        break;
      case PACKET_TYPE_CODE:;
        Packet* temp = (Packet*) value->value;
        printHexDump((char*) temp->packet_buff, temp->len);
        break;
      case BIT_TYPE_CODE:
        printBit(numberTolong(value->value, value->length));
        break;
      case NUMBER_TYPE_CODE:
        printNum(numberTolong(value->value, value->length));
        break;
      default:
        fprintf(stderr, ERROR"Can't print data of type <%s> !\nPrint Not Yet Defined for this type.\n"RESET,value->identifier);
        free(return_var->value);
        free(return_var);
        return NULL;
      
    }
    args = (Node*)args->right;
  }
  fprintf(stdout, USR "\n" RESET);
  return return_var;
}

UserVariable* Log(Node* args)
{
/*  
  //DO LOGGING//
*/
  return print(args);
}

UserVariable* type(Node* args)
{
  if(args == NULL)
  {
    fprintf(stderr, ERROR"type() requires an argument !\n");
    return NULL;
  }
  else {;}

  UserVariable* value = (UserVariable*)(((Node*)(args->data))->data);

  UserVariable* return_var = (UserVariable*) malloc(1*sizeof(UserVariable));
  return_var->identifier = NULL;
  return_var->datatype = STRING_TYPE_CODE;
  return_var->value = NULL;
  return_var->length = 1;

  switch(value->datatype)
  {
    case BIT_TYPE_CODE:
      return_var->value = "bit\0";
      return_var->length = 3;
      break;
    case IP4_TYPE_CODE:
      return_var->value = "ip4\0";
      return_var->length = 3;
      break;
    case MAC_TYPE_CODE:
      return_var->value = "mac\0";
      return_var->length = 3;
      break;
    case NUMBER_TYPE_CODE:
      return_var->value = "number\0";
      return_var->length = 6;
      break;
    case STRING_TYPE_CODE:
      return_var->value = "string\0";
      return_var->length = 6;
      break;
    case STREAM_TYPE_CODE:
      return_var->value = "stream\0";
      return_var->length = 6;
      break;
    case PACKET_TYPE_CODE:
      return_var->value = "packet\0";
      return_var->length = 6;
      break;
  }
  return return_var;
}

UserVariable* checksum(Node* args)
{
  if(args == NULL)
  {
    fprintf(stderr, ERROR"checksum() requires an argument !\n");
    return NULL;
  }
  else {;}

  UserVariable* value = (UserVariable*)(((Node*)(args->data))->data);

  if(value->datatype != PACKET_TYPE_CODE)
  {
    fprintf(stderr, ERROR"checksum() requires a packet argument !\n");
    return NULL;
  }
  else {;}

  Packet* packet = (Packet*) (value->value);
  unsigned char* assmbld_packet = packet->packet_buff + packet->offset;

  UserVariable* return_var = (UserVariable*) malloc(1*sizeof(UserVariable));

  return_var->identifier = NULL;
  return_var->datatype = NUMBER_TYPE_CODE;
  return_var->value = (unsigned char*) malloc(sizeof(char));
  return_var->length = 2;
  
  *(return_var->value+0) = 0;
  *(return_var->value+1) = 0;

  short range = nullifyChecksum(packet);

  #define maximum(a,b) ((a>b)?a:b)

  short i=0;
  for(;i<range;i+=2)
  {
    unsigned char byte2[2];
    byte2[0] = *(assmbld_packet+i);
    byte2[1] = *(assmbld_packet+i+1);

    char j = 1, carry = 0;
    for(; j>=0; j--)
    {
      unsigned char greater = maximum(*(return_var->value+j), byte2[j]);
      *(return_var->value+j) += byte2[j] + carry;
      carry = (greater <= *(return_var->value+j)) ? 0 : 1;
    }
  }

  *(return_var->value) = ~*(return_var->value);
  *(return_var->value+1) = ~*(return_var->value+1);

  return return_var;
}

