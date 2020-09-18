#pragma once

#include <arpa/inet.h>
#include <fstream>
#include <iostream>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <fstream>
#include <regex>

#include "utils.h"

class CustomBN{
	private:
		uint64_t counter_0;
		uint64_t counter_1;

	public:
		CustomBN(){};
		bool initialize(char* buffer, size_t size);
		bool get_next(char* buffer, size_t size);
};


class Session{
	private:
		int fd;
		uint32_t counterpart_nonce;
		EVP_PKEY* counterpart_pubkey;
		CustomBN iv;
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
		// Scrive in buffer il valore di IV
		bool get_iv(char* buffer, size_t size);
		// Restituisce il mio numero di sequenza
		uint32_t get_my_nonce();
		// Restituisce la chiave simmetrica di autenticazione
		int get_key_auth(char *buffer);
		// Restituisce la chiave simmetrica di cifratura
		int get_key_encr(char *buffer);
		// Inizializza iv, key_encr e key_auth con byte pseudocasuali
		int initialize(const EVP_CIPHER *type_encr, const EVP_MD *type_auth);
		// Salva il numero di sequenza della controparte
		void set_counterpart_nonce(uint32_t nonce);
		// Salva la chiave pubblica del server
		void set_counterpart_pubkey(EVP_PKEY *pubkey);
		// Salva il valore IV
		int set_iv(const EVP_CIPHER *type, char* iv_buffer);
		// Salva la chiave simmetrica di autenticazione
		int set_key_auth(const EVP_MD *type, char* key);
		// Salva la chiave simmetrica di cifratura
		int set_key_encr(const EVP_CIPHER *type, char* key);
};

bool verify_input_command(std::string buf);
bool checkFile(std::string filePath);
int create_store(X509_STORE **store, X509 *CA_cert, X509_CRL *crl);
int decrypt_asym(unsigned char* ciphertext, size_t ciphertextlen, unsigned char* encrypted_key, size_t encrypted_key_len, unsigned char* iv, EVP_PKEY* prvkey, unsigned char** plaintext, size_t* plaintextlen);
int decrypt_symm(unsigned char* ciphertext, size_t cipherlen, unsigned char** plaintext, size_t* plaintextlen, const EVP_CIPHER *type, const unsigned char* key, const unsigned char* iv);
int encrypt_asym(char* plaintext, size_t plaintextlen, EVP_PKEY* pubkey, const EVP_CIPHER *type, unsigned char** ciphertext, size_t* ciphertextlen, unsigned char** encrypted_key, size_t* encrypted_key_len, unsigned char** iv);
int encrypt_symm(const unsigned char* plaintext, size_t plaintextlen, unsigned char** ciphertext, size_t* ciphertextlen, const EVP_CIPHER *type, const unsigned char* key, const unsigned char* iv);
size_t get_file_size(std::string filename);
std::string get_file_size_string(std::string filename);
int get_random(char* buffer, size_t buflen);
int hash_bytes(unsigned char* msg, size_t msg_len, unsigned char** digest, size_t* digest_len, Session* session);
int hash_verify(unsigned char* msg, size_t msg_len, unsigned char* received_digest, Session* session);
int load_cert(std::string filename, X509 **cert);
int load_crl(std::string filename, X509_CRL** crl);
int load_private_key(std::string filename, std::string password, EVP_PKEY** prvkey);
int receive_data(unsigned int fd, char** input_buffer, size_t* buflen);
int receive_data_encr(char** plaintext, size_t* plaintext_len, Session* session);
int receive_size_hmac(Session* session, size_t* size);
int send_data(unsigned int fd, const char* buffer, size_t buflen);
int send_data_encr(const char* buffer, size_t buflen, Session* session);
int send_ack(Session*);
void send_error(unsigned int fd);
int send_nack(Session*);
int send_size_hmac(uint32_t seqnum, uint32_t size, Session* session);
int sign_asym(char* plaintext, size_t plaintextlen, EVP_PKEY* prvkey, unsigned char** signature, size_t* signaturelen);
int sign_asym_verify(unsigned char* msg, int msg_len, unsigned char* signature, int signature_len, EVP_PKEY* pubkey);
int verify_cert(X509_STORE *store, X509 *cert);
unsigned int fsize();
int send_file_name(std::string, Session*);
int receive_file_name(char** fileName, Session* session);
void print_progress_bar(int total, unsigned int fragment);
int encryptAndSendFile(std::string path, Session* session);
int decryptAndWriteFile(std::string path,  Session* session);