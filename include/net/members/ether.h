#define ETH_HEAD_LEN 14
#define ETH_TAIL_LEN 0


struct ether_head
{
  unsigned char dest_mac[6];
  unsigned char src_mac[6];
  unsigned short type;
};

// SUPPORT FOR TAIL NOT YET IMPLEMENTED

struct ether_tail
{
  unsigned char crc[4];
};

