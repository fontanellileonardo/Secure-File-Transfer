#include "common_util.h"

std::fstream fs;
static size_t NUM_BLOCKS = ( FRAGM_SIZE / BLOCK_SIZE ) * BLOCK_SIZE;

Session::Session(unsigned int fd){//TODO: passare il tipo di algoritmo (es: EVP_aes_128_cbc()) al costruttore
	this->fd = fd;//TODO: da usare al posto di TCP_socket
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
	if(iv != NULL)
		delete[] iv;
	if(key_encr != NULL)
		delete[] key_encr;
	if(key_auth != NULL)
		delete[] key_auth;
	if(counterpart_pubkey != NULL)
		EVP_PKEY_free(counterpart_pubkey);
}

uint32_t Session::get_counterpart_nonce(){
	return counterpart_nonce++;
}

EVP_PKEY* Session::get_counterpart_pubkey(){
	return counterpart_pubkey;
}

unsigned int Session::get_fd(){
	return fd;
}

int Session::get_iv(char* buffer){
	if(iv == NULL)
		return -1;

	memcpy(buffer, iv, EVP_CIPHER_iv_length(EVP_aes_128_cbc()));
	return 0;
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
	return my_nonce++;
}

int Session::initialize(const EVP_CIPHER *type){
	/*
	iv = new char[EVP_CIPHER_iv_length(type)];
	if(get_random(iv, EVP_CIPHER_iv_length(type)) < 0)
		return -1;
	*/
	
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
	if(*buflen <= 0)
		return -1;
	
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

void decrypt(int TCP_socket, char* fileName){
	unsigned char *key = (unsigned char*) "0123456789012345";
	unsigned char* iv;
	decryptAndWriteFile(TCP_socket, key, iv);
	//printf("sono fuori dal for\n");
}

bool checkFile(std::string filePath){
	if (FILE *file = fopen(filePath.c_str(), "r")) {
        fclose(file);
        return true;
    } else {
        return false;
    }   
}
