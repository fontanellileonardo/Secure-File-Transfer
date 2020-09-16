#include <iostream>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <string.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <unistd.h> 

#include <netinet/in.h>
#include <arpa/inet.h> //conversione little-big endian 

#include "common_util.h"
#include "utils.h"

uint8_t identifyCommand(std::string command);
void print_prompt();
int send_command(uint8_t command, Session &session);
void quitClient(int socket);