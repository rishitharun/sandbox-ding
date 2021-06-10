
#define IP4_HEAD_LEN 20
#define IP4_TAIL_LEN 0
#define IP4_OPTN_LEN 2


struct ip4_head
{
  // BITS 4 & 4
  unsigned char version_headerlen;

  unsigned char type_of_service;
  unsigned short total_length;
  unsigned short identification;

  // BITS 3 & 13
  unsigned short flags_fragoff;

  unsigned char time_to_live;
  unsigned char protocol;
  unsigned short header_chksum;
  unsigned char src_ip[4];
  unsigned char dest_ip[4];
};

// SUPPORT FOR OPTIONS NOT YET IMPLEMENTED

struct ip4_options
{
  struct
  {
    unsigned char copied:1;
    unsigned char option_class:2;
    unsigned char option_number:5;
  } option_params;
  
  unsigned char option_length[1];
  unsigned char* option_data;
};

