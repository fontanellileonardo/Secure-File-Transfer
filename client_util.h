#include <iostream>
#include <string.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <unistd.h> 

#include <netinet/in.h>
#include <arpa/inet.h> //conversione little-big endian 

#include "messageDef.h"

int identifyCommand(char* command);
void print_available_commands();
void print_prompt();
void quitClient(int socket);
