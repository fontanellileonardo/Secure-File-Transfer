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

#include "messageDef.h"

int identifyCommand(char* command);
int load_cert(std::string filename, X509** cert);
void print_available_commands();
void print_prompt();
void quitClient(int socket);
int send_data(unsigned int fd, const char* buffer, size_t buflen);
