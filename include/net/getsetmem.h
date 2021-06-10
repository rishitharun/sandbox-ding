#ifndef STDIO_H
#define STDIO_H
#include<stdio.h>
#endif

#ifndef STDLIB_H
#define STDLIB_H
#include<stdlib.h>
#endif

#ifndef COLOR
#define COLOR
#include "codes/color.h"
#endif

#ifndef STORAGE
#define STORAGE
#include "storage.h"
#endif

#define SET 0x01
#define GET 0x00

UserVariable* get_set_member(Packet* packet, unsigned short packet_member, char choice);

