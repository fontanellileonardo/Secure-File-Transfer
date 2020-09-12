#include "common_util.h"

Session::Session(unsigned int fd){//TODO: passare il tipo di algoritmo (es: EVP_aes_128_cbc()) al costruttore
	this->fd = fd;
	key_auth = NULL;
	key_encr = NULL;
	//char buffer[sizeof(my_nonce)];
	if(get_random((char*)&my_nonce, sizeof(my_nonce)) < 0)
		my_nonce = 1;
	if(my_nonce > (UINT32_MAX / 2))
		my_nonce = my_nonce - (UINT32_MAX / 2);
	
	counterpart_nonce = 0;
}

Session::~Session(){
	if(key_encr != NULL)
		delete[] key_encr;
	if(key_auth != NULL)
		delete[] key_auth;
	if(counterpart_pubkey != NULL)
		EVP_PKEY_free(counterpart_pubkey);
}

bool CustomBN::initialize(char* buffer, size_t size){
	if(size != 16)
		return false;
	memcpy(&counter_1, buffer, sizeof(counter_1));
	memcpy(&counter_0,  buffer + sizeof(counter_1), sizeof(counter_0));
	return true;
}

bool CustomBN::get_next(char* buffer, size_t size){
	if(size < 16)
		return false;
	
	if(counter_0 == UINT64_MAX){
		if(counter_1 == UINT64_MAX)
			counter_1 = 0;
		else
			counter_1++;
		counter_0 = 0;
	}
	else
		counter_0++;
	
	memcpy(buffer, &counter_1, sizeof(counter_1));
	memcpy(buffer + sizeof(counter_1), &counter_0, sizeof(counter_0));
	return true;
}

uint32_t Session::get_counterpart_nonce(){
	return ++counterpart_nonce;
}

EVP_PKEY* Session::get_counterpart_pubkey(){
	return counterpart_pubkey;
}

unsigned int Session::get_fd(){
	return fd;
}

bool Session::get_iv(char* buffer, size_t size){
	return iv.get_next(buffer, size);
}

int Session::get_key_auth(char* buffer){
	if(key_auth == NULL)
		return -1;

	memcpy(buffer, key_auth, EVP_CIPHER_key_length(EVP_aes_128_cbc()));
	return 0;
}

int Session::get_key_encr(char* buffer){
	if(key_encr == NULL)
		return -1;

	memcpy(buffer, key_encr, EVP_CIPHER_key_length(EVP_aes_128_cbc()));
	return 0;
}

uint32_t Session::get_my_nonce(){
	return ++my_nonce;
}

int Session::initialize(const EVP_CIPHER *type){
	key_encr = new char[EVP_CIPHER_key_length(type)];
	if(get_random(key_encr, EVP_CIPHER_key_length(type)) < 0)
		return -1;
	
	key_auth = new char[EVP_CIPHER_key_length(type)];
	if(get_random(key_auth, EVP_CIPHER_key_length(type)) < 0)
		return -1;
	
	return 0;
}

void Session::set_counterpart_nonce(uint32_t nonce){
	counterpart_nonce = nonce;
}

void Session::set_counterpart_pubkey(EVP_PKEY *pubkey){
	counterpart_pubkey = pubkey;
}

int Session::set_iv(const EVP_CIPHER *type, char* iv_buffer){
	if(iv_buffer == NULL)
		return -1;
	
	if(!iv.initialize(iv_buffer, EVP_CIPHER_iv_length(type)))
		return -1;
	return 0;
}

int Session::set_key_auth(const EVP_CIPHER *type, char* key){
	if(key == NULL)
		return -1;
	
	if(key_auth != NULL)
		delete[] key_auth;
	
	key_auth = new char[EVP_CIPHER_key_length(type)];
	memcpy(key_auth, key, EVP_CIPHER_key_length(type));
	return 0;
}

int Session::set_key_encr(const EVP_CIPHER *type, char* key){
	if(key == NULL)
		return -1;
	
	if(key_encr != NULL)
		delete[] key_encr;
	
	key_encr = new char[EVP_CIPHER_key_length(type)];
	memcpy(key_encr, key, EVP_CIPHER_key_length(type));
	return 0;
}

int create_store(X509_STORE **store, X509 *CA_cert, X509_CRL *crl){
	*store = X509_STORE_new();
	if(store == NULL){
		std::cerr << "Errore durante la creazione dello store" << std::endl;
		return -1;
	}

	if(X509_STORE_add_cert(*store, CA_cert) != 1){
		std::cerr << "Errore durante l'aggiunta del certificato allo store" << std::endl;
		return -1;
	}

	if(X509_STORE_add_crl(*store, crl) != 1){
		std::cerr << "Errore durante di CRL allo store" << std::endl;
		return -1;
	}

	if(X509_STORE_set_flags(*store, X509_V_FLAG_CRL_CHECK) != 1){
		std::cerr << "Errore durante l'impostazione dei flag allo store" << std::endl;
		return -1;
	}
	return 0;
}

int decrypt_asym(unsigned char* ciphertext, size_t ciphertextlen, unsigned char* encrypted_key, size_t encrypted_key_len, unsigned char* iv, EVP_PKEY* prvkey, unsigned char** plaintext, size_t* plaintextlen){
	int outlen, plainlen;
	*plaintext = new unsigned char[ciphertextlen];
	
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if(ctx == NULL)
		return -1;
	if(EVP_OpenInit(ctx, EVP_aes_128_cbc(), encrypted_key, encrypted_key_len, iv, prvkey) != 1){
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	if(EVP_OpenUpdate(ctx, *plaintext, &outlen, ciphertext, ciphertextlen) != 1){
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	plainlen = outlen;
	if(EVP_OpenFinal(ctx, *plaintext + plainlen, &outlen) != 1){
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	plainlen += outlen;
	*plaintextlen = (size_t)plainlen;
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}

int decrypt_symm(unsigned char* ciphertext, size_t cipherlen, unsigned char** plaintext, size_t* plaintextlen, const EVP_CIPHER *type, const unsigned char* key, const unsigned char* iv){
	int plainlen;
	int outlen;
	
	*plaintext = new unsigned char[cipherlen + 16];
	
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if(ctx == NULL)
		return -1;
	if(EVP_DecryptInit(ctx, type, key, iv) !=1){
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	
	if(EVP_DecryptUpdate(ctx, *plaintext, &outlen, ciphertext, cipherlen) != 1){
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	plainlen = outlen;
	
	if(EVP_DecryptFinal(ctx, *plaintext + plainlen, &outlen) != 1){
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	plainlen += outlen;
	
	*plaintextlen = (size_t)plainlen;
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}

int encrypt_asym(char* plaintext, size_t plaintextlen, EVP_PKEY* pubkey, const EVP_CIPHER *type, unsigned char** ciphertext, size_t* ciphertextlen, unsigned char** encrypted_key, size_t *encrypted_key_len, unsigned char** iv){
	*encrypted_key_len = EVP_PKEY_size(pubkey);
	*encrypted_key = new unsigned char[EVP_PKEY_size(pubkey)];
	*ciphertext = new unsigned char[plaintextlen + EVP_CIPHER_block_size(type)];
	int outlen, cipherlen;
	*iv = new unsigned char[EVP_CIPHER_iv_length(type)];
	
	if(RAND_poll() != 1){
		return -1;
	}
	
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if(ctx == NULL)
		return -1;
	if(EVP_SealInit(ctx, type, encrypted_key, (int*)encrypted_key_len, *iv, &pubkey, 1) != 1){
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	if(EVP_SealUpdate(ctx, *ciphertext, &outlen, (unsigned char*)plaintext, plaintextlen) != 1){
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	cipherlen = outlen;
	if(EVP_SealFinal(ctx, *ciphertext + cipherlen, &outlen) != 1){
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	*ciphertextlen = (size_t)(cipherlen + outlen);
	
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}

int encrypt_symm(const unsigned char* plaintext, size_t plaintextlen, unsigned char** ciphertext, size_t* ciphertextlen, const EVP_CIPHER *type, const unsigned char* key, const unsigned char* iv){
	*ciphertext = new unsigned char[plaintextlen + 1 + EVP_CIPHER_block_size(type)];
	int cipherlen;
	int outlen;
	
	EVP_CIPHER_CTX* ctx;
	ctx = EVP_CIPHER_CTX_new();
	if(ctx == NULL)
		return -1;
	if(EVP_EncryptInit(ctx, type, key, iv) != 1){
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	if(EVP_EncryptUpdate(ctx, *ciphertext, &outlen, plaintext, plaintextlen) != 1){
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	cipherlen = outlen;
	if(EVP_EncryptFinal(ctx, *ciphertext + cipherlen, &outlen) != 1){
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	*ciphertextlen = (size_t)(cipherlen + outlen);
	
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}

size_t get_file_size(std::string filename){
	size_t file_size = 0;
	std::ifstream file(filename, std::ios::binary);
	if(file){
		file.seekg(0, std::ios::end);
		file_size = file.tellg();
		file.close();
	}
	std::cout << "file_size: " << file_size << std::endl;
	return file_size;
}

std::string get_file_size_string(std::string filename){
	size_t size = get_file_size(filename);
	size_t divider = 1;
	std::string unit;
	
	if(size > (1024 * 1024 * 1024)){
		divider = (1024 * 1024 * 1024);
		unit = " Gb";
	}
	else if(size > (1024 * 1024)){
		divider = (1024 * 1024);
		unit = " Mb";
	}
	else if(size > 1024){
		divider = 1024;
		unit = " Kb";
	}
	else{
		return std::to_string(size) + " Byte";
	}
	
	std::string integer_part = std::to_string(size / divider);
	
	if((size % divider) > 9){
		std::string decimal_part = std::to_string(size % divider);
		return integer_part + "." + decimal_part.substr(0, 2) + unit;
	}
	else if((size % divider) > 0){
		std::string decimal_part = std::to_string(size % divider);
		return integer_part + "." + decimal_part.substr(0, 1) + unit;
	}
	else{
		return integer_part + unit;
	}
}

// Scrive buflen byte pseudocasuali in buffer
int get_random(char* buffer, size_t buflen){
	if(RAND_poll() != 1){
		return -1;
	}
	if(RAND_bytes((unsigned char*)buffer, buflen) != 1){
		return -1;
	}
	return 0;
}

int hash_bytes(unsigned char* msg, size_t msg_len, unsigned char** digest, size_t* digest_len){
	unsigned int digestlen;
	*digest = new unsigned char[EVP_MD_size(EVP_sha256())];
	
	EVP_MD_CTX* ctx;
	ctx = EVP_MD_CTX_new();
	if(ctx == NULL)
		return -1;
	if(EVP_DigestInit(ctx, EVP_sha256()) != 1){
		EVP_MD_CTX_free(ctx);
		return -1;
	}
	if(EVP_DigestUpdate(ctx, msg, msg_len) != 1){
		EVP_MD_CTX_free(ctx);
		return -1;
	}
	if(EVP_DigestFinal(ctx, *digest, &digestlen) != 1){
		EVP_MD_CTX_free(ctx);
		return -1;
	}
	*digest_len = (size_t)digestlen;
	
	EVP_MD_CTX_free(ctx);
	return 0;
}

int hash_verify(unsigned char* msg, size_t msg_len, unsigned char* received_digest){
	unsigned char* digest;
	size_t digest_len;
	
	if(hash_bytes(msg, msg_len, &digest, &digest_len) < 0)
		return -1;
	
	if(CRYPTO_memcmp(digest, received_digest, digest_len) == 0){
		delete[] digest;
		return 1;
	}
	else{
		delete[] digest;
		return 0;
	}
}

//Carica il certificato come file .pem
int load_cert(std::string filename, X509 **cert){
	FILE* file = fopen(filename.c_str(), "r");
	if(!file){
		return -1;
	}
	*cert = PEM_read_X509(file, NULL, NULL, NULL);
	if(!cert){
		return -1;
	}
	fclose(file);
	return 0;
}

//Carica il file CRL
int load_crl(std::string filename, X509_CRL** crl){
	FILE* file = fopen(filename.c_str(), "r");
	if(!file){
		return -1;
	}
	*crl = PEM_read_X509_CRL(file, NULL, NULL, NULL);
	if(!crl){
		return -1;
	}
	fclose(file);
	return 0;
}

int load_private_key(std::string filename, std::string password, EVP_PKEY** prvkey){
	FILE* file = fopen(filename.c_str(), "r");
	if(!file){
		return -1;
	}
	*prvkey = PEM_read_PrivateKey(file, NULL, NULL, (void*)password.c_str());
	fclose(file);
	if(!(*prvkey)){
		return -2;
	}
	return 0;
}

// Alloca un nuovo buffer e vi inserisce i dati ricevuti.
// Deallocare sempre il buffer non appena i dati in esso contenuti non servono più
int receive_data(unsigned int fd, char** input_buffer, size_t* buflen){
	size_t buflen_n, received = 0;
	ssize_t ret = 0;
	
	// Ricevo dimensione dei dati in ingresso
	if(recv(fd, &buflen_n, sizeof(buflen_n), 0) <= 0){
		return -1;
	}
	*buflen = ntohl(buflen_n);
	if(*buflen < 0)
		return -1;
	
	if(*buflen == 0)
		return 0;
	
	// Alloco il buffer per i dati in ingresso
	*input_buffer = new char[*buflen];
	if(*input_buffer == NULL)
		return -1;
	
	// Ricevo i dati in ingresso
	while(received < *buflen){
		ret = recv(fd, *input_buffer + received, (*buflen) - received, 0);
		if(ret < 0){
			return -1;
		}
		if(ret == 0){
			return -1;
		}
		received += ret;
	}
	return 0;
}

int send_data(unsigned int fd, const char* buffer, size_t buflen){
	size_t sent = 0;
	ssize_t ret;
	
	size_t buflen_n = htonl(buflen);
	send(fd, &buflen_n, sizeof(buflen_n), 0);
	
	while(sent < buflen){
		ret = send(fd, buffer + sent, buflen - sent, 0);
		//std::cout << "Inviati: " << ret << " byte" << std::endl;
		if(ret < 0){
			return -1;
		} 
		sent += ret;
	}
	return (sent == buflen)?0:(-1);
}

void send_error(unsigned int fd){
	size_t buflen_n = htonl(0);
	send(fd, &buflen_n, sizeof(buflen_n), 0);
}

int sign_asym(char* plaintext, size_t plaintextlen, EVP_PKEY* prvkey, unsigned char** signature, size_t* signaturelen){
	*signature = new unsigned char[EVP_PKEY_size(prvkey)];
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if(ctx == NULL)
		return -1;
	if(EVP_SignInit(ctx, EVP_sha256()) != 1){
		EVP_MD_CTX_free(ctx);
		return -1;
	}
	if(EVP_SignUpdate(ctx, (unsigned char*)plaintext, plaintextlen) != 1){
		EVP_MD_CTX_free(ctx);
		return -1;
	}
	if(EVP_SignFinal(ctx, *signature, (unsigned int*)signaturelen, prvkey) != 1){
		EVP_MD_CTX_free(ctx);
		return -1;
	}
	EVP_MD_CTX_free(ctx);
	return 0;
}

int sign_asym_verify(unsigned char* msg, int msg_len, unsigned char* signature, int signature_len, EVP_PKEY* pubkey){
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if(ctx == NULL)
		return -1;
	if(EVP_VerifyInit(ctx, EVP_sha256()) != 1){
		EVP_MD_CTX_free(ctx);
		return -1;
	}
	if(EVP_VerifyUpdate(ctx, msg, msg_len) != 1){
		EVP_MD_CTX_free(ctx);
		return -1;
	}
	int ret = EVP_VerifyFinal(ctx, signature, signature_len, pubkey);
	EVP_MD_CTX_free(ctx);
	return ret;
}

int verify_cert(X509_STORE *store, X509 *cert){
	X509_STORE_CTX* cert_ctx = X509_STORE_CTX_new();
	if(cert_ctx == NULL){
		std::cerr << "Errore nella creazione dello store context" << std::endl;
		X509_STORE_CTX_free(cert_ctx);
		return -1;
	}
	
	if(X509_STORE_CTX_init(cert_ctx, store, cert, NULL) != 1){
		std::cerr << "Errore durente l'inizializzazione dello store context" << std::endl;
		X509_STORE_CTX_free(cert_ctx);
		return -1;
	}
	
	if(X509_verify_cert(cert_ctx) != 1) {
		X509_STORE_CTX_free(cert_ctx);
		return 0;
	}
	
	X509_STORE_CTX_free(cert_ctx);
	return 1;
}
