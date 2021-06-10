#define ICMP_HEAD_LEN 8
#define ICMP_TAIL_LEN 0


struct icmp_head
{
  unsigned char type;
  unsigned char code;
  unsigned short checksum;
  unsigned char data[4];
};

