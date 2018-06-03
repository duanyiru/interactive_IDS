#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "sniffer.h"

#define STRING_SIZE 1024

#define READ_END 0
#define WRITE_END 1

#define MAX_ARGU_SIZE 512

/*
	require: 
	iptables packet
	pacp packet
*/