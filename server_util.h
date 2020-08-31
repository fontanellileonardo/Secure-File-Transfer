#include <iostream>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <unistd.h> 

//openssl libraries
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <netinet/in.h>
#include <arpa/inet.h> //conversione little-big endian 

#include <string.h>

#include "messageDef.h"

//void load_crl(string filename, X509_CRL * crl);
int load_crl(std::string filename, X509_CRL** crl);
void quitClient(int socket, fd_set* master);
int receive_data(unsigned int fd, char** input_buffer, size_t* buflen);
