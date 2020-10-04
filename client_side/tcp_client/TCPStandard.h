#ifndef TCP_STANDARD_H
#define TCP_STANDARD_H

// Common include
#include <iostream>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Common define
# define MAXPACKETSIZE 40960
# define SIZEOFPACKAGEFORNAME 100	// This is for target packet size of receiving frame name
# define SIZEOFPACKAGEFORSIZE 8	// This is for target packet size of receiving frame size
# define SIZEOFPACKAGE 40000	// This is for target packet size of receiving frame

// Server specific define
# define MAX_CLIENT 1000

// Client specific define

#endif