///* CODES FOR PACKETS AND PACKET MEMBERS *///

#define __EMPTY 0x00

#define __ETHER 0x01
#define __ARP 0x02
#define __IP4 0x03
#define __ICMP 0x04

#define __PAYLOAD 0xff

#define __ETHER_DEST_MAC 0x0000              //mac
#define __ETHER_SRC_MAC 0x0001               //mac
#define __ETHER_TYPE 0x0002                  //number (2 bytes)
#define __ETHER_CRC 0x0003                   //number (4 bytes)

#define __IP4_VERSION 0x0004                 //bit (4 bits)
#define __IP4_HEADER_LEN 0x0005              //bit (4 bits)
#define __IP4_TYPE_OF_SERVICE 0x0006         //number (1 byte)
#define __IP4_TOTAL_LEN 0x0007               //number (2 bytes)
#define __IP4_IDENTIFICATION 0x0008          //number (2 bytes)
#define __IP4_FLAGS 0x0009                   //bit (3 bits)
#define __IP4_FRAG_OFFSET 0x000a             //bit (13 bits)
#define __IP4_TTL 0x000b                     //number (1 byte)
#define __IP4_PROTOCOL 0x000c                //number (1 byte)
#define __IP4_CHECKSUM 0x000d                //number (2 bytes)
#define __IP4_SRC_IP 0x000e                  //ip4
#define __IP4_DEST_IP 0x00f                 //ip4

#define __ARP_HW_TYPE 0x0010                 //number (2 bytes)
#define __ARP_PROTO_TYPE 0x0011              //number (2 bytes)
#define __ARP_HW_ADDRESS_LEN 0x0012          //number (1 byte)
#define __ARP_PROTO_ADDRESS_LEN 0x0013       //number (1 byte)
#define __ARP_OPERATION 0x0014               //number (2 bytes)
#define __ARP_SRC_MAC 0x0015                 //mac
#define __ARP_SRC_IP 0x0016                  //ip4
#define __ARP_DEST_MAC 0x0017                //mac
#define __ARP_DEST_IP 0x0018                 //ip4

#define __ICMP_TYPE 0x0019                   //number (1 byte)
#define __ICMP_CODE 0x001a                   //number (1 byte)
#define __ICMP_CHECKSUM 0x001b               //number (2 bytes)
#define __ICMP_DATA 0x001c                   //number (4 bytes)

#define __PAYLOAD_LEN 0xfffe                //number (4 bytes)
#define __PAYLOAD_DATA 0xffff                //number (4 bytes)


