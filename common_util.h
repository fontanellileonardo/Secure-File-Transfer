#include <arpa/inet.h>
#include <iostream>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>


class Session{
	private:
		int fd;
		uint32_t counterpart_nonce;
		uint32_t my_nonce;
		EVP_PKEY* counterpart_pubkey;

	public:
		Session(unsigned int fd);
		
		// Restituisce il numero di sequenza della controparte
		uint32_t get_counterpart_nonce();
		// Restituisce il numero del file descriptor
		unsigned int get_fd();
		// Restituisce il mio numero di sequenza
		uint32_t get_my_nonce();
		// Salva il numero di sequenza della controparte
		void set_counterpart_nonce(uint32_t nonce);
		// Salva la chiave pubblica del server
		void set_counterpart_pubkey(EVP_PKEY *pubkey);
};

int create_store(X509_STORE **store, X509 *CA_cert, X509_CRL *crl);
int load_cert(std::string filename, X509 **cert);
int load_crl(std::string filename, X509_CRL** crl);
int load_private_key(std::string filename, std::string password, EVP_PKEY** prvkey);
int receive_data(unsigned int fd, char** input_buffer, size_t* buflen);
int send_data(unsigned int fd, const char* buffer, size_t buflen);
int verify_cert(X509_STORE *store, X509 *cert);
