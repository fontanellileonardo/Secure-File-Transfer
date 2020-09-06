#include <arpa/inet.h>
#include <iostream>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>


class Session{
	private:
		int fd;
		uint32_t counterpart_nonce;
		EVP_PKEY* counterpart_pubkey;
		char* iv;
		char* key_encr;
		char* key_auth;
		uint32_t my_nonce;

	public:
		Session(unsigned int fd);
		~Session();
		
		// Restituisce il numero di sequenza della controparte
		uint32_t get_counterpart_nonce();
		// Restituisce la chiave pubblica della controparte
		EVP_PKEY* get_counterpart_pubkey();
		// Restituisce il numero del file descriptor
		unsigned int get_fd();
		// Restituisce IV
		int get_iv(char* buffer);
		// Restituisce il mio numero di sequenza
		uint32_t get_my_nonce();
		// Restituisce la chiave simmetrica di autenticazione
		int get_key_auth(char *buffer);
		// Restituisce la chiave simmetrica di cifratura
		int get_key_encr(char *buffer);
		// Inizializza iv, key_encr e key_auth con byte pseudocasuali
		int initialize(const EVP_CIPHER *type);
		// Salva il numero di sequenza della controparte
		void set_counterpart_nonce(uint32_t nonce);
		// Salva la chiave pubblica del server
		void set_counterpart_pubkey(EVP_PKEY *pubkey);
		// Salva la chiave simmetrica di autenticazione
		int set_key_auth(const EVP_CIPHER *type, char* key);
		// Salva la chiave simmetrica di cifratura
		int set_key_encr(const EVP_CIPHER *type, char* key);
};

int create_store(X509_STORE **store, X509 *CA_cert, X509_CRL *crl);
int decrypt_asym(unsigned char* ciphertext, size_t ciphertextlen, unsigned char* encrypted_key, size_t encrypted_key_len, unsigned char* iv, EVP_PKEY* prvkey, unsigned char** plaintext, size_t* plaintextlen);
int encrypt_asym(char* plaintext, size_t plaintextlen, EVP_PKEY* pubkey, const EVP_CIPHER *type, unsigned char** ciphertext, size_t* ciphertextlen, unsigned char** encrypted_key, size_t* encrypted_key_len, unsigned char** iv);
int get_random(char* buffer, size_t buflen);
int load_cert(std::string filename, X509 **cert);
int load_crl(std::string filename, X509_CRL** crl);
int load_private_key(std::string filename, std::string password, EVP_PKEY** prvkey);
int receive_data(unsigned int fd, char** input_buffer, size_t* buflen);
int sign_asym(char* plaintext, size_t plaintextlen, EVP_PKEY* prvkey, unsigned char** signature, size_t* signaturelen);
int send_data(unsigned int fd, const char* buffer, size_t buflen);
int verify_cert(X509_STORE *store, X509 *cert);
