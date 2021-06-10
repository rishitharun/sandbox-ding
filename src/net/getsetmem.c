#include "codes/packet.h"
#include "codes/datatype.h"

#include "net/getsetmem.h"
#include "net/members/all.h"

extern short allocd;
extern char** extracted_bit_values;
extern char* bit_specific;

UserVariable* get_set_member(Packet* packet, unsigned short packet_member, char choice)
{
  UserVariable* member_variable = (UserVariable*) malloc(sizeof(UserVariable));

  member_variable->identifier = NULL;
  member_variable->datatype = 0;
  member_variable->value = NULL;
  member_variable->length = 0;

  static union
  {
    struct arp_head * arphdr;
    struct ether_head * ethhdr;
    struct ip4_head * ip4hdr;
    struct icmp_head * icmphdr;
  } proto;

  *(bit_specific+0) = 0;
  *(bit_specific+1) = 0;

  switch(packet_member)
  {
    case __ARP_HW_TYPE:
      member_variable->datatype = NUMBER_TYPE_CODE;
      proto.arphdr = (struct arp_head *) ((packet->packet_buff) + (packet->offset));
      member_variable->value = (unsigned char *) &(proto.arphdr->hw_type);
      member_variable->length = 2;
      break;

    case __ARP_PROTO_TYPE:
      member_variable->datatype = NUMBER_TYPE_CODE;
      proto.arphdr = (struct arp_head *) ((packet->packet_buff) + (packet->offset));
      member_variable->value = (unsigned char *) &(proto.arphdr->protocol_type);
      member_variable->length = 2;
      break;

    case __ARP_HW_ADDRESS_LEN:
      member_variable->datatype = NUMBER_TYPE_CODE;
      proto.arphdr = (struct arp_head *) ((packet->packet_buff) + (packet->offset));
      member_variable->value = (unsigned char *) &(proto.arphdr->hw_addr_len);
      member_variable->length = 1;
      break;

    case __ARP_PROTO_ADDRESS_LEN:
      member_variable->datatype = NUMBER_TYPE_CODE;
      proto.arphdr = (struct arp_head *) ((packet->packet_buff) + (packet->offset));
      member_variable->value = (unsigned char *) &(proto.arphdr->protocol_addr_len);
      member_variable->length = 1;
      break;

    case __ARP_OPERATION:
      member_variable->datatype = NUMBER_TYPE_CODE;
      proto.arphdr = (struct arp_head *) ((packet->packet_buff) + (packet->offset));
      member_variable->value = (unsigned char *) &(proto.arphdr->operation);
      member_variable->length = 2;
      break;

    case __ARP_SRC_MAC:
      member_variable->datatype = MAC_TYPE_CODE;
      proto.arphdr = (struct arp_head *) ((packet->packet_buff) + (packet->offset));
      member_variable->value = (unsigned char *) &(proto.arphdr->src_mac);
      member_variable->length = 6;
      break;

    case __ARP_SRC_IP:
      member_variable->datatype = IP4_TYPE_CODE;
      proto.arphdr = (struct arp_head *) ((packet->packet_buff) + (packet->offset));
      member_variable->value = (unsigned char *) &(proto.arphdr->src_ip);
      member_variable->length = 4;
      break;

    case __ARP_DEST_MAC:
      member_variable->datatype = MAC_TYPE_CODE;
      proto.arphdr = (struct arp_head *) ((packet->packet_buff) + (packet->offset));
      member_variable->value = (unsigned char *) &(proto.arphdr->dest_mac);
      member_variable->length = 6;
      break;

    case __ARP_DEST_IP:
      member_variable->datatype = IP4_TYPE_CODE;
      proto.arphdr = (struct arp_head *) ((packet->packet_buff) + (packet->offset));
      member_variable->value = (unsigned char *) &(proto.arphdr->dest_ip);
      member_variable->length = 4;
      break;

    case __ETHER_DEST_MAC:
      member_variable->datatype = MAC_TYPE_CODE;
      proto.ethhdr = (struct ether_head *) ((packet->packet_buff) + (packet->offset));
      member_variable->value = (unsigned char *) &(proto.ethhdr->dest_mac);
      member_variable->length = 6;
      break;

    case __ETHER_SRC_MAC:
      member_variable->datatype = MAC_TYPE_CODE;
      proto.ethhdr = (struct ether_head *) ((packet->packet_buff) + (packet->offset));
      member_variable->value = (unsigned char *) &(proto.ethhdr->src_mac);
      member_variable->length = 6;
      break;

    case __ETHER_TYPE:
      member_variable->datatype = NUMBER_TYPE_CODE;
      proto.ethhdr = (struct ether_head *) ((packet->packet_buff) + (packet->offset));
      member_variable->value = (unsigned char *) &(proto.ethhdr->type);
      member_variable->length = 2;
      break;

    /* NEED TO TAKE A LOOK AT THIS LATER
    case __ETHER_CRC:
      member_variable->datatype = NUMBER_TYPE_CODE;
      member_variable->value = ?
      member_variable->length = 4;
      break;
     NEED TO TAKE A LOOK AT THIS LATER */

    case __IP4_VERSION:
      member_variable->datatype = BIT_TYPE_CODE;
      proto.ip4hdr = (struct ip4_head *) ((packet->packet_buff) + (packet->offset));
      member_variable->length = 1;
      if(choice == SET)
      {
        member_variable->value = (unsigned char *) &(proto.ip4hdr->version_headerlen);
        *(bit_specific+0) = 0;    //  offset
        *(bit_specific+1) = 4;    //  lshift
      }
      else if (choice == GET)
      {
        extracted_bit_values = (char**) realloc(extracted_bit_values, allocd+1);
        member_variable->value = (char*) malloc(sizeof(char));
        *(member_variable->value) = (0xf0 & proto.ip4hdr->version_headerlen)>>4;
        *(extracted_bit_values+allocd++) = member_variable->value;
      }
      else
      {
        fprintf(stderr, DEBUG"[DEBUG INFO]: "RESET"Impossible Branch in \"case __IP4_VERSION\" @ /src/net/getsetmem.c !\n"RESET);
        free(member_variable);
        return NULL;
      }
      break;

    case __IP4_HEADER_LEN:
      member_variable->datatype = BIT_TYPE_CODE;
      member_variable->length = 1;
      proto.ip4hdr = (struct ip4_head *) ((packet->packet_buff) + (packet->offset));
      if(choice == SET)
      {
        member_variable->value = (unsigned char *) &(proto.ip4hdr->version_headerlen);
        *(bit_specific+0) = 0;    //  offset
        *(bit_specific+1) = 0;    //  lshift
      }
      else if (choice == GET)
      {
        extracted_bit_values = (char**) realloc(extracted_bit_values, allocd+1);
        member_variable->value = (char*) malloc(sizeof(char));
        *(member_variable->value) = 0x0f & proto.ip4hdr->version_headerlen;
        *(extracted_bit_values+allocd++) = member_variable->value;
      }
      else
      {
        fprintf(stderr, DEBUG"[DEBUG INFO]: "RESET"Impossible Branch in \"case __IP4_HEADER_LEN\" @ /src/net/getsetmem.c !\n"RESET);
        free(member_variable);
        return NULL;
      }
      break;

    case __IP4_TYPE_OF_SERVICE:
      member_variable->datatype = NUMBER_TYPE_CODE;
      proto.ip4hdr = (struct ip4_head *) ((packet->packet_buff) + (packet->offset));
      member_variable->value = (unsigned char *) &(proto.ip4hdr->type_of_service);
      member_variable->length = 1;
      break;

    case __IP4_TOTAL_LEN:
      member_variable->datatype = NUMBER_TYPE_CODE;
      proto.ip4hdr = (struct ip4_head *) ((packet->packet_buff) + (packet->offset));
      member_variable->value = (unsigned char *) &(proto.ip4hdr->total_length);
      member_variable->length = 2;
      break;

    case __IP4_IDENTIFICATION:
      member_variable->datatype = NUMBER_TYPE_CODE;
      proto.ip4hdr = (struct ip4_head *) ((packet->packet_buff) + (packet->offset));
      member_variable->value = (unsigned char *) &(proto.ip4hdr->identification);
      member_variable->length = 2;
      break;

    case __IP4_FLAGS:
      member_variable->datatype = BIT_TYPE_CODE;
      proto.ip4hdr = (struct ip4_head *) ((packet->packet_buff) + (packet->offset));
      member_variable->length = 1;
      if(choice == SET)
      {
        member_variable->value = (unsigned char *) &(proto.ip4hdr->flags_fragoff);
        *(bit_specific+0) = 0;    //  offset
        *(bit_specific+1) = 5;    //  lshift
      }
      else if (choice == GET)
      {
        extracted_bit_values = (char**) realloc(extracted_bit_values, allocd+1);
        member_variable->value = (char*) malloc(sizeof(char));
        *(member_variable->value) = (0xe0 & proto.ip4hdr->flags_fragoff) >> 5;
        *(extracted_bit_values+allocd++) = member_variable->value;
      }
      else
      {
        fprintf(stderr, DEBUG"[DEBUG INFO]: "RESET"Impossible Branch in \"case __IP4_FLAGS\" @ /src/net/getsetmem.c !\n"RESET);
        free(member_variable);
        return NULL;
      }
      break;

    case __IP4_FRAG_OFFSET:
      member_variable->datatype = BIT_TYPE_CODE;
      proto.ip4hdr = (struct ip4_head *) ((packet->packet_buff) + (packet->offset));
      member_variable->length = 2;
      if(choice == SET)
      {
        member_variable->value = (unsigned char *) &(proto.ip4hdr->flags_fragoff);
        *(bit_specific+0) = 0;    //  offset
        *(bit_specific+1) = 0;    //  lshift
      }
      else if (choice == GET)
      {
        extracted_bit_values = (char**) realloc(extracted_bit_values, allocd+1);
        member_variable->value = (unsigned char*) malloc(sizeof(short));
        *((unsigned short *) member_variable->value) = (0xff1f) & proto.ip4hdr->flags_fragoff;
        *(extracted_bit_values+allocd++) = member_variable->value;
      }
      else
      {
        fprintf(stderr, DEBUG"[DEBUG INFO]: "RESET"Impossible Branch in \"case __IP4_FRAG_OFFSET\" @ /src/net/getsetmem.c !\n"RESET);
        free(member_variable);
        return NULL;
      }
      break;

    case __IP4_TTL:
      member_variable->datatype = NUMBER_TYPE_CODE;
      proto.ip4hdr = (struct ip4_head *) ((packet->packet_buff) + (packet->offset));
      member_variable->value = (unsigned char *) &(proto.ip4hdr->time_to_live);
      member_variable->length = 1;
      break;

    case __IP4_PROTOCOL:
      member_variable->datatype = NUMBER_TYPE_CODE;
      proto.ip4hdr = (struct ip4_head *) ((packet->packet_buff) + (packet->offset));
      member_variable->value = (unsigned char *) &(proto.ip4hdr->protocol);
      member_variable->length = 1;
      break;

    case __IP4_CHECKSUM:
      member_variable->datatype = NUMBER_TYPE_CODE;
      proto.ip4hdr = (struct ip4_head *) ((packet->packet_buff) + (packet->offset));
      member_variable->value = (unsigned char *) &(proto.ip4hdr->header_chksum);
      member_variable->length = 2;
      break;

    case __IP4_SRC_IP:
      member_variable->datatype = IP4_TYPE_CODE;
      proto.ip4hdr = (struct ip4_head *) ((packet->packet_buff) + (packet->offset));
      member_variable->value = (unsigned char *) &(proto.ip4hdr->src_ip);
      member_variable->length = 4;
      break;

    case __IP4_DEST_IP:
      member_variable->datatype = IP4_TYPE_CODE;
      proto.ip4hdr = (struct ip4_head *) ((packet->packet_buff) + (packet->offset));
      member_variable->value = (unsigned char *) &(proto.ip4hdr->dest_ip);
      member_variable->length = 4;
      break;

    case __ICMP_TYPE:
      member_variable->datatype = NUMBER_TYPE_CODE;
      proto.icmphdr = (struct icmp_head *) ((packet->packet_buff) + (packet->offset));
      member_variable->value = (unsigned char *) &(proto.icmphdr->type);
      member_variable->length = 1;
      break;

    case __ICMP_CODE:
      member_variable->datatype = NUMBER_TYPE_CODE;
      proto.icmphdr = (struct icmp_head *) ((packet->packet_buff) + (packet->offset));
      member_variable->value = (unsigned char *) &(proto.icmphdr->code);
      member_variable->length = 1;
      break;

    case __ICMP_CHECKSUM:
      member_variable->datatype = NUMBER_TYPE_CODE;
      proto.icmphdr = (struct icmp_head *) ((packet->packet_buff) + (packet->offset));
      member_variable->value = (unsigned char *) &(proto.icmphdr->checksum);
      member_variable->length = 2;
      break;

    case __ICMP_DATA:
      member_variable->datatype = NUMBER_TYPE_CODE;
      proto.icmphdr = (struct icmp_head *) ((packet->packet_buff) + (packet->offset));
      member_variable->value = (unsigned char *) &(proto.icmphdr->data);
      member_variable->length = 4;
      break;

    case __PAYLOAD_LEN:
      member_variable->datatype = NUMBER_TYPE_CODE;
      member_variable->value = (unsigned char *) &packet->len;
      if(choice == SET) member_variable->length = 0;
      else if(choice == GET) member_variable->length = 1; // can't be one foreva
      else
      {
        fprintf(stderr, DEBUG"[DEBUG INFO]: "RESET"Impossible Branch in \"case __PAYLOAD_LEN\" @ /src/net/getsetmem.c !\n"RESET);
        free(member_variable);
        return NULL;
      }
      break;

    case __PAYLOAD_DATA:
      member_variable->datatype = STREAM_TYPE_CODE;
      member_variable->value = (packet->packet_buff) + (packet->offset);
      member_variable->length = packet->len;
      if (choice == SET) * (packet->len_ptr) = packet->offset + packet->len;
      else {;}
      break;

    default:
      fprintf(stderr, ERROR"Invalid Member\n"RESET);
      free(member_variable);
      return NULL;
  }
  return member_variable;
}
