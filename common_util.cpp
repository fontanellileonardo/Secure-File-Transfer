#include "common_util.h"

std::fstream fs;
static size_t NUM_BLOCKS = ( FRAGM_SIZE / BLOCK_SIZE ) * BLOCK_SIZE;

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

int Session::initialize(const EVP_CIPHER *type_encr, const EVP_MD *type_auth){
	key_encr = new char[EVP_CIPHER_key_length(type_encr)];
	if(get_random(key_encr, EVP_CIPHER_key_length(type_encr)) < 0)
		return -1;
	
	key_auth = new char[EVP_MD_size(type_auth)];
	if(get_random(key_auth, EVP_MD_size(type_auth)) < 0)
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

int Session::set_key_auth(const EVP_MD *type, char* key){
	if(key == NULL)
		return -1;
	
	if(key_auth != NULL)
		delete[] key_auth;
	
	key_auth = new char[EVP_MD_size(type)];
	memcpy(key_auth, key, EVP_MD_size(type));
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

int hash_bytes(unsigned char* msg, size_t msg_len, unsigned char** digest, size_t* digest_len, Session* session){
	unsigned int digestlen;
	*digest = new unsigned char[EVP_MD_size(EVP_sha256())];
	
	size_t key_auth_len = EVP_CIPHER_key_length(EVP_aes_128_cbc());
	char key_auth_buffer[key_auth_len];
	session->get_key_encr(key_auth_buffer);
	
	//EVP_MD_CTX* ctx;
	//ctx = EVP_MD_CTX_new();
	HMAC_CTX* ctx = HMAC_CTX_new();
	if(ctx == NULL)
		return -1;
	//if(EVP_DigestInit(ctx, EVP_sha256()) != 1){
	if(HMAC_Init_ex(ctx, key_auth_buffer, key_auth_len, EVP_sha256(), NULL) != 1){
		//EVP_MD_CTX_free(ctx);
		HMAC_CTX_free(ctx);
		return -1;
	}
	//if(EVP_DigestUpdate(ctx, msg, msg_len) != 1){
	if(HMAC_Update(ctx, msg, msg_len) != 1){
		//EVP_MD_CTX_free(ctx);
		HMAC_CTX_free(ctx);
		return -1;
	}
	//if(EVP_DigestFinal(ctx, *digest, &digestlen) != 1){
	if(HMAC_Final(ctx, *digest, &digestlen) != 1){
		//EVP_MD_CTX_free(ctx);
		HMAC_CTX_free(ctx);
		return -1;
	}
	*digest_len = (size_t)digestlen;
	
	//EVP_MD_CTX_free(ctx);
	HMAC_CTX_free(ctx);
	return 0;
}

int hash_verify(unsigned char* msg, size_t msg_len, unsigned char* received_digest, Session* session){
	unsigned char* digest;
	size_t digest_len;
	
	if(hash_bytes(msg, msg_len, &digest, &digest_len, session) < 0)
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
	uint32_t buflen_n;
	size_t received = 0;
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

int receive_data_encr(char** plaintext, size_t* plaintext_len, Session* session){
	size_t buflen;
	ssize_t ret = receive_size_hmac(session, &buflen);
	if(ret < 0)
		return ret;
	
	// Alloco il buffer per i dati in ingresso
	char input_buffer[buflen];
	
	// Ricevo i dati in ingresso
	size_t received = 0;
	ret = 0;
	while(received < buflen){
		ret = recv(session->get_fd(), input_buffer + received, (buflen) - received, 0);
		if(ret < 0){
			return -1;
		}
		if(ret == 0){
			return -1;
		}
		received += ret;
	}
	
	if(received != buflen)
		return 0;
	
	// Controllo se il numero sequenziale è corretto
	uint32_t seqnum = session->get_counterpart_nonce();
	if(seqnum != ntohl(*((uint32_t*)input_buffer))){
		std::cerr << "Errore sequence number" << std::endl;
		return -1;
	}
	
	// Controllo l'hash
	if(hash_verify((unsigned char*)input_buffer, (buflen - EVP_MD_size(EVP_sha256())), (unsigned char*)(input_buffer + buflen - EVP_MD_size(EVP_sha256())), session) != 1){
		std::cerr << "Errore hash" << std::endl;
		return -1;
	}
	
	// Decripto il comando
	unsigned char key_encr_buffer[EVP_CIPHER_key_length(EVP_aes_128_cbc())];
	session->get_key_encr((char*)key_encr_buffer);
	unsigned char iv_buffer[EVP_CIPHER_iv_length(EVP_aes_128_cbc())];
	session->get_iv((char*)iv_buffer, EVP_CIPHER_iv_length(EVP_aes_128_cbc()));
	
	if(decrypt_symm((unsigned char*)(input_buffer + sizeof(seqnum)), (buflen - (sizeof(seqnum) + EVP_MD_size(EVP_sha256()))), (unsigned char**)plaintext, plaintext_len, EVP_aes_128_cbc(), key_encr_buffer, iv_buffer) < 0){
		std::cerr << "Errore decrypt" << std::endl;
		return -1;
	}
	
	return 1;
}

int receive_size_hmac(Session* session, size_t* size){
	size_t buflen = sizeof(uint32_t) + sizeof(uint32_t) + EVP_MD_size(EVP_sha256());// 4 + 4 + 32
	char input_buffer[buflen];
	
	// Ricevo i byte
	if(recv(session->get_fd(), input_buffer, buflen, MSG_WAITALL) < 0)
		return 0;
	
	// Controllo se il numero sequenziale è corretto
	uint32_t seqnum = session->get_counterpart_nonce();
	if(seqnum != ntohl(*((uint32_t*)input_buffer))){
		std::cerr << "Errore sequence number" << std::endl;
		return -1;
	}
	
	// Controllo l'hash
	if(hash_verify((unsigned char*)input_buffer, (buflen - EVP_MD_size(EVP_sha256())), (unsigned char*)(input_buffer + buflen - EVP_MD_size(EVP_sha256())), session) != 1){
		std::cerr << "Errore hash" << std::endl;
		return -1;
	}
	
	// Copio il valore nella variabile size
	*size = (size_t)htonl(*((uint32_t*)(input_buffer + sizeof(uint32_t))));
	
	return 1;
}

int send_data(unsigned int fd, const char* buffer, size_t buflen){
	size_t sent = 0;
	ssize_t ret;
	
	uint32_t buflen_n = htonl(buflen);
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

int send_data_encr(const char* buffer, size_t buflen, Session* session){
	// Recupero le chiavi simmetriche dalla struttura dati
	char key_encr_buffer[EVP_CIPHER_key_length(EVP_aes_128_cbc())];
	session->get_key_encr(key_encr_buffer);
	char iv_buffer[EVP_CIPHER_iv_length(EVP_aes_128_cbc())];
	session->get_iv(iv_buffer, EVP_CIPHER_iv_length(EVP_aes_128_cbc()));
	
	// Recupero il numero sequenziale e ne controllo la validità
	uint32_t seqnum = session->get_my_nonce();
	if(seqnum == (UINT32_MAX - 1)){// Me ne servono 2, uno per la dimensione e uno per il messaggio da inviare, dunque: UINT32_MAX - 1
		return 0;
		//std::cerr << "Il numero sequenziale ha raggiunto il limite. Terminazione..." << std::endl;
		//quit_client(i, &master, true);
		//continue;
		//TODO: gestire
	}
	uint32_t seqnum_msg = htonl(seqnum + 1);
	
	// Cifro il messggio (contenuto in buffer)
	char* ciphertext_buffer;
	size_t ciphertext_buffer_len;
	if(encrypt_symm((unsigned char*)buffer, buflen, (unsigned char**)&ciphertext_buffer, &ciphertext_buffer_len, EVP_aes_128_cbc(), (unsigned char*)key_encr_buffer, (unsigned char*)iv_buffer) < 0)
		return 0;
	
	// Copio il numero sequenziale e messaggio nel buffer su cui verrà calcolato l'hash
	size_t to_be_hashed_len = sizeof(seqnum_msg) + ciphertext_buffer_len;
	unsigned char to_be_hashed[to_be_hashed_len];
	memcpy(to_be_hashed, &seqnum_msg, sizeof(seqnum_msg));
	memcpy(to_be_hashed + sizeof(seqnum_msg), ciphertext_buffer, ciphertext_buffer_len);
	
	// Calcolo l'hash di (numero sequenziale, messaggio)
	unsigned char* digets_buffer;
	size_t digets_buffer_len;
	if(hash_bytes(to_be_hashed, to_be_hashed_len, &digets_buffer, &digets_buffer_len, session) < 0)
		return 0;
	
	// Copio il numero sequenziale, messaggio e hash nel buffer che verrà inviato
	size_t output_buffer_len = sizeof(seqnum_msg) + ciphertext_buffer_len + digets_buffer_len;
	unsigned char output_buffer[output_buffer_len];
	memcpy(output_buffer, &seqnum_msg, sizeof(seqnum_msg));
	memcpy(output_buffer + sizeof(seqnum_msg), ciphertext_buffer, ciphertext_buffer_len);
	memcpy(output_buffer + sizeof(seqnum_msg) + ciphertext_buffer_len, digets_buffer, digets_buffer_len);
	
	delete[] ciphertext_buffer;
	delete[] digets_buffer;
	ssize_t ret;
	
	// Invio la dimensione (protetta da hash) del messaggio che sto per inviare
	ret = send_size_hmac(htonl(seqnum), htonl(output_buffer_len), session);
	if(ret < 1)
		return ret;
	
	// Incremento il contatore interno perchè ho incrementato "seqnum_msg" di uno
	session->get_my_nonce();
	
	// Invio i dati
	size_t sent = 0;
	
	while(sent < output_buffer_len){
		ret = send(session->get_fd(), output_buffer + sent, output_buffer_len - sent, 0);
		//std::cout << "Inviati: " << ret << " byte" << std::endl;
		if(ret < 0){
			return -1;
		} 
		sent += ret;
	}
	return (sent == output_buffer_len)?1:(-1);
}

void send_error(unsigned int fd){
	uint32_t buflen_n = htonl(0);
	send(fd, &buflen_n, sizeof(buflen_n), 0);
}

int send_size_hmac(uint32_t seqnum, uint32_t size, Session* session){
	// Copio il numero sequenziale e size nel buffer su cui verrà calcolato l'hash
	size_t to_be_hashed_len = sizeof(seqnum) + sizeof(size);
	unsigned char to_be_hashed[to_be_hashed_len];
	memcpy(to_be_hashed, &seqnum, sizeof(seqnum));
	memcpy(to_be_hashed + sizeof(seqnum), &size, sizeof(size));
	
	// Calcolo l'hash
	unsigned char* digets_buffer;
	size_t digets_buffer_len;
	if(hash_bytes(to_be_hashed, to_be_hashed_len, &digets_buffer, &digets_buffer_len, session) < 0)
		return 0;
	
	// Copio il numero sequenziale, size e hash nel buffer che verrà inviato
	size_t output_buffer_len = sizeof(seqnum) + sizeof(size) + digets_buffer_len;
	unsigned char output_buffer[output_buffer_len];
	memcpy(output_buffer, &seqnum, sizeof(seqnum));
	memcpy(output_buffer + sizeof(seqnum), &size, sizeof(size));
	memcpy(output_buffer + sizeof(seqnum) + sizeof(size), digets_buffer, digets_buffer_len);
	
	delete[] digets_buffer;
	
	// Invio i dati
	size_t sent = 0;
	ssize_t ret;
	
	while(sent < output_buffer_len){
		ret = send(session->get_fd(), output_buffer + sent, output_buffer_len - sent, 0);
		//std::cout << "Inviati: " << ret << " byte" << std::endl;
		if(ret < 0){
			return -1;
		} 
		sent += ret;
	}
	return (sent == output_buffer_len)?1:(-1);
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

// Calcola la dimensione del file
long long int fsize() {
	// Scorre fino alla fine del file in modo da calcolare la lunghezza in Byte
	fs.seekg(0, fs.end);
	// Conta il num di "caratteri" e quindi il numero di byte 
	// Se la dim del file non può essere salvata in un intero -> ERRORE!!!
	long long int fsize = fs.tellg(); 
	// Si riposiziona all'inizio del file
	fs.seekg(0, fs.beg);
	return fsize;
}

int encryptAndSendFile(size_t file_len, unsigned char* key, unsigned char* iv, unsigned char * ciphertext, int TCP_socket){	
	int i;
	EVP_CIPHER_CTX * ctx;
	int len = 0;
	int ciphertext_len = 0;
	
	//create and initialize context
	ctx = EVP_CIPHER_CTX_new();
	
	//Encrypt init
	EVP_EncryptInit(ctx, EVP_aes_128_cbc(), key, NULL);
	
	int message_type;
	uint32_t umessage_type;
	
	//comando per specificare operazione
	message_type = COMMAND_DOWNLOAD;
	umessage_type = htonl(message_type);
	int ret = send(TCP_socket, &umessage_type, sizeof(uint32_t), 0);
	std::cout << "Valore di ret: "<< ret << std::endl;
	if (ret <= 0) {
		std::cout << "Errore nell'invio del comando"<< std::endl;
		exit(1);
	}
	std::cout<<"Comando inviato: "<< message_type << std::endl;

	//invio lunghezza file	
	long long int ufile_len = htonl(file_len);
	ret = send(TCP_socket, &ufile_len, sizeof(uint64_t), 0);
	std::cout << "Valore di ret: "<< ret << std::endl;
	if (ret <= 0) {
		std::cout << "Errore nell'invio della grandezza del file"<< std::endl;
		exit(1);
	}
	std::cout<<"lunghezza file: "<<file_len<<std::endl;
	
	// conterrà una porzione del file da inviare
	char* buffer = new char[FRAGM_SIZE];
	size_t nread;
	uint32_t ulen_cipher;
	std::cout <<"Iterazioni da fare nel for sono:"<< (file_len/FRAGM_SIZE ) << std::endl;
	for( i = 0; i < (file_len/FRAGM_SIZE); i++){
		std::cout<<"Iterazione:"<<i<<std::endl;
		fs.read(buffer,FRAGM_SIZE);	
		EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)buffer, FRAGM_SIZE);
		if(len == 0) {
			printf("Errore nella EncryptUpdate\n");
			exit(1);
		}
		ciphertext_len += len;
		ulen_cipher = htonl(len);
		std::cout << "grandezza chuck: " << len << std::endl;
		int ret = send(TCP_socket, &ulen_cipher, sizeof(uint32_t), 0);
		std::cout << "Valore di ret nell'invio della grandezza del chunck: "<< ret << std::endl;
		if (ret != sizeof(uint32_t)) {
			std::cout << "Errore nell'invio della grandezza del chunck"<< std::endl;
			exit(1);
		}
		std::cout<<"grandezza chunck in bit: "<< ulen_cipher << std::endl;
		ret = send(TCP_socket, ciphertext, len, 0);
		std::cout << "Valore di ret nell'invio del chunck: "<< ret << std::endl;
		if (ret != len) {
			std::cout << "Errore nell'invio del chunck"<< std::endl;
			exit(1);
		}		
		std::cout<<"ciphertext is: "<<std::endl;	
		std::cout<<std::endl<<std::endl;				
	}
	std::cout << "Sono fuori dal for" << std::endl;
	int index = 0;
	if (file_len % FRAGM_SIZE != 0) {
		fs.read((char*)buffer,(file_len%FRAGM_SIZE));
        EVP_EncryptUpdate(ctx, &ciphertext[index], &len, (unsigned char*)buffer, file_len%FRAGM_SIZE);
		index +=len;
		ciphertext_len +=len;    
    }
	// Aggiungo il padding
	if( 1 != EVP_EncryptFinal(ctx, &ciphertext[index], &len)) {
		std::cout<<"errore encr final, valore di len: "<<len<<std::endl;
		exit(1);
	}	
	ciphertext_len +=len;
	len += index;	
	ulen_cipher = htonl((size_t)len);
	std::cout<<"grandezza chunck dopo send: "<< ntohl(ulen_cipher) << std::endl;
	ret = send(TCP_socket, &ulen_cipher, sizeof(uint32_t), 0);
	std::cout << "Valore di ret nell'invio della grandezza del chunck: "<< ret << std::endl;
	if (ret != sizeof(uint32_t)) {
		std::cout << "Errore nell'invio della grandezza del chunck"<< std::endl;
		exit(1);
	} 
	ret = send(TCP_socket, ciphertext, len, 0);	
	std::cout << "Valore di ret nell'invio del chunck: "<< ret << std::endl;
	if (ret != len) {
		std::cout << "Errore nell'invio del chunck"<< std::endl;
		exit(1);
	}
	//clean context
	EVP_CIPHER_CTX_free(ctx);
	fs.close();
	// free the memory
	memset(buffer, 0, FRAGM_SIZE);
	delete[] buffer;

	return ciphertext_len;
}

void encrypt(int TCP_socket){
	unsigned char *key = (unsigned char*) "0123456789012345";
	// in realtà dovrebbe essere grande quanto il maggior multiplo di 16 che FRAGM_SIZE riesce ad avere
	size_t dim_ct = ( FRAGM_SIZE / BLOCK_SIZE ) * BLOCK_SIZE;
	unsigned char* ciphertext = new unsigned char[dim_ct + BLOCK_SIZE];
	std::string path = CLIENT_FILES_PATH;
	path.append("/ice.jpg");
	std::cout<<"File path:"<<path<<std::endl;
	fs.open(path.c_str(), std::fstream::in | std::fstream::binary);
	if(!fs) { std::cout<<"Errore apertura file."<<std::endl; exit(1); }
	long long int ssst = fsize();
	std::cout<<"dim file in encrypt: " << ssst << std::endl;
	unsigned char* iv;
	encryptAndSendFile(ssst, key, iv, ciphertext, TCP_socket);
	delete[] ciphertext;
}

int decryptAndWriteFile(int TCP_socket,  unsigned char* key, unsigned char* iv){
	
	uint64_t ufile_len;
	size_t file_len;
	
	recv(TCP_socket, &ufile_len, sizeof(uint64_t), 0);
	file_len = ntohl(ufile_len);
	std::cout<<"dimensione file:"<< file_len <<std::endl;
	
	EVP_CIPHER_CTX * dctx;
	int dlen = 0;
	int plaintext_len = 0;
	
	//create and initialize context
	dctx = EVP_CIPHER_CTX_new();
	//decrypt init
	EVP_DecryptInit(dctx, EVP_aes_128_cbc(), key, NULL);
	//decrypt update, one call is enough because our message is very short
	
	// string o lasciare unsigned char??
	unsigned char* ciphertext = new unsigned char[NUM_BLOCKS + BLOCK_SIZE];
	unsigned char* plaintext = new unsigned char[NUM_BLOCKS + BLOCK_SIZE];
	uint32_t ulen_cipher;
	uint len_cipher;
	unsigned int i;
	int fw;

	std::string path = SERVER_FILES_PATH;
	path.append("/ice.jpg");
	std::cout<<"File path:"<<path<<std::endl;
	std::fstream fs;
	fs.open(path.c_str(), std::fstream::out | std::fstream::binary);
	if(!fs) { std::cout<<"Errore apertura file."<<std::endl; exit(1); }

	std::cout <<"Iterazioni da fare nel for sono:"<< (file_len/FRAGM_SIZE ) << std::endl;
	int ret;
	for(i = 0; i < (file_len/FRAGM_SIZE ); i++) {
		std::cout<<"Iterazione:"<<i<<std::endl;
		ret = recv(TCP_socket, &ulen_cipher, sizeof(uint32_t), MSG_WAITALL);
		std::cout << "Valore di ret nella ricezione della grandezza del chunck: "<< ret << std::endl;
		if(ret != sizeof(uint32_t)) {
			std::cout<<"Errore nella ricezione della lunghezza del chunk" << std::endl;
			exit(1);
		}
		len_cipher = ntohl(ulen_cipher);
		std::cout << "ulen_cipher dopo la recv: " << ulen_cipher << std::endl;
		std::cout << "grandezza chuck tradotta: " << len_cipher << std::endl;
		// Aspetto che sia ricevuto tutto il ciphertext
		ret = recv(TCP_socket, ciphertext, len_cipher, MSG_WAITALL);
		std::cout << "Valore di ret nella ricezione del cipher: "<< ret << std::endl; 
		if(ret != len_cipher) {
			std::cout<<"Errore nella ricezione del chunk" << std::endl;
			exit(1);
		}
		if(!EVP_DecryptUpdate(dctx, plaintext, &dlen, ciphertext, len_cipher)) {
			std::cout<<"errore nella DecryptUpdate. dlen: "<<dlen<<std::endl;
			exit(1);
		}
		plaintext_len +=dlen;
		fs.write((const char*)plaintext, dlen);
		std::cout<<"plain size is: "<<dlen<<std::endl;
		std::cout<<std::endl;	
  	}
	std::cout<<"Sono fuori dal for"<<std::endl;
	ret = recv(TCP_socket, &ulen_cipher, sizeof(uint32_t), MSG_WAITALL);
	std::cout << "Valore di ret nella ricezione della grandezza del chunck: "<< ret << std::endl; 
	if(ret == -1) {
		std::cout<<"Errore nella ricezione del chunk" << std::endl;
		exit(1);
	}	
	len_cipher = ntohl(ulen_cipher);
	ret = recv(TCP_socket, ciphertext, len_cipher, MSG_WAITALL); 	
	std::cout << "Valore di ret nella ricezione del chunck: "<< ret << std::endl; 
	if(ret != len_cipher) {
		std::cout<<"Errore nella ricezione del chunk" << std::endl;
		exit(1);
	}	
	// ultimo dato ricevuto potrebbe essere o solo padding, o contenente anche del plaintext significativo	
	if (file_len % FRAGM_SIZE != 0) {
		if( !EVP_DecryptUpdate(dctx, plaintext, &dlen, ciphertext, len_cipher)) {
				std::cout<<"errore nella DecryptUpdate. dlen: "<<dlen<<std::endl;
				exit(1);
			}
			plaintext_len +=dlen;
			fs.write((const char*)plaintext, dlen);
	}	
  	//decrypt finalize
	std::cout << "byte decriptati nell'ultimo frammento prima della final: "<< dlen << std::endl;
	if( 1 != EVP_DecryptFinal(dctx, (unsigned char*)plaintext, &dlen)) {
		std::cout<<"errore final. dlen è: "<<dlen<<std::endl;
		exit(1);
	}
	std::cout << "byte decriptati con la final: "<< dlen << std::endl;
	plaintext_len += dlen;
	std::cout << "byte decriptati in totatle: "<< plaintext_len << std::endl;
	if(dlen != 0)
		fs.write((const char*)plaintext, dlen);
	fs.close();
	//clean context decr
	EVP_CIPHER_CTX_free(dctx);
	delete[] ciphertext;
	memset(plaintext, 0, FRAGM_SIZE);
	delete[] plaintext;

	return 0;	
}

void decrypt(int TCP_socket){
	unsigned char *key = (unsigned char*) "0123456789012345";
	unsigned char* iv;
	decryptAndWriteFile(TCP_socket, key, iv);
	//printf("sono fuori dal for\n");
}