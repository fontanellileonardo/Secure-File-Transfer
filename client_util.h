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

using namespace std;

void command_available();
int identifyCommand(char* command);
void quitClient(int socket);
void print_prompt();



