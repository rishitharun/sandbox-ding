
#define ARP_HEAD_LEN 28
#define ARP_TAIL_LEN 0


struct arp_head
{
  unsigned short hw_type;
  unsigned short protocol_type;
  unsigned char hw_addr_len;
  unsigned char protocol_addr_len;
  unsigned short operation;
  unsigned char src_mac[6];
  unsigned char src_ip[4];
  unsigned char dest_mac[6];
  unsigned char dest_ip[4];
};

