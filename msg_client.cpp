#include <sys/types.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <unistd.h> 
#include <netinet/in.h>
#include <arpa/inet.h> //conversione little-big endian 
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>
#include <fstream>

#include "client_util.h"
#include "common_util.h"

#define FRAGM_SIZE 33
#define BLOCK_SIZE 16

//static size_t CIPHER_SIZE = ( FRAGM_SIZE / BLOCK_SIZE ) * BLOCK_SIZE;

/*
// Va bene anche in c++?
size_t fsize(FILE* fp) {
	fseek(fp, 0, SEEK_END);
	long int clear_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	return clear_size;
}

int encryptAndSendFile(FILE* fp,size_t file_len, unsigned char* key, unsigned char* iv, unsigned char * ciphertext, int TCP_socket){	
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
	send(TCP_socket, &umessage_type, sizeof(uint32_t), 0);

	//invio lunghezza file	
	uint16_t ufile_len = htons(file_len);
	send(TCP_socket, &ufile_len, sizeof(uint16_t), 0);
	//printf("lunghezza file: %zd\n", file_len);
	std::cout<<"lunghezza file: "<<file_len<<std::endl;
	
	unsigned char buffer[FRAGM_SIZE];
	size_t buff_len = sizeof(buffer);
	//printf("sizeof buffer: %zd\n", buff_len);
	std::cout<<"sizeof buffer: "<<buff_len<<std::endl;
	size_t nread;
	uint16_t ulen_cipher;
	for( i = 0; i < (file_len/FRAGM_SIZE); i++){
		if((nread = fread(buffer, 1, sizeof(buffer), fp)) > 0){
			//printf("plaintext is: \n");
			std::cout<<"plaintext is:"<<std::endl;
			BIO_dump_fp(stdout, (const char * ) buffer, buff_len);	
			EVP_EncryptUpdate(ctx, ciphertext, &len, buffer, buff_len);
			if(len == 0) {
				printf("Errore nella EncryptUpdate\n");
				exit(1);
			}
			ciphertext_len += len;
			//printf(" ciphertext_len : %i,  byte criptati a questa iterazione: %i\n",ciphertext_len, len);
			std::cout<<"ciphertext_len"<<ciphertext_len<<",byte criptati a questa iterazione: "<<len<<std::endl;
			//printf("invio %zd\n", len);
			ulen_cipher = htons((size_t)len);
			send(TCP_socket, &ulen_cipher, sizeof(uint16_t), 0);
			send(TCP_socket, ciphertext, len, 0);		
			//printf("ciphertext is: \n");
			std::cout<<"ciphertext is: "<<std::endl;
			BIO_dump_fp(stdout, (const char * ) ciphertext, len);	
			//printf("\n\n");
			std::cout<<std::endl<<std::endl;
		}
		else {
			std::cout<<"errore fread"<<std::endl;
			//printf("errore fread\n");
			exit(1);
		}					
	}
	//printf("file_len mod FRAGM_SIZE: %ld\n", (file_len % FRAGM_SIZE));
	int index = 0;
	if (file_len % FRAGM_SIZE != 0) {
		nread = fread(buffer, 1, (file_len%FRAGM_SIZE), fp);
        EVP_EncryptUpdate(ctx, &ciphertext[index], &len, buffer, file_len%FRAGM_SIZE);
		index +=len;
		//printf("Grandezza del file non è multiplo di 16. Len è: %d\n",len);
		ciphertext_len +=len;    
    }
	//finalize encrypt and adds the padding
	if( 1 != EVP_EncryptFinal(ctx, &ciphertext[index], &len)) {
		//printf("errore encr final, valore di len: %zd\n",len);
		std::cout<<"errore encr final, valore di len: "<<len<<std::endl;
		exit(1);
	}	
	ciphertext_len +=len;
	len += index;	
	//printf("ciphertext_len is after final: %i. Len è: %d\n", ciphertext_len, len);
	// DUBBIO: ciphertext qui può essere più grande di len. E' un problema?
	BIO_dump_fp(stdout, (const char * ) ciphertext, len);
	ulen_cipher = htons((size_t)len);
	send(TCP_socket, &ulen_cipher, sizeof(uint16_t), 0);
	// DUBBIO: ciphertext potrebbe essere più grande. Ma send invia solamente len bit? 
	send(TCP_socket, ciphertext, len, 0);	
	//clean context
	EVP_CIPHER_CTX_free(ctx);
	fclose(fp);
	return ciphertext_len;
}


void encrypt(int TCP_socket){
	unsigned char *key = (unsigned char*) "0123456789012345";
	//printf("in encript\n");
	// in realtà dovrebbe essere grande quanto il maggior multiplo di 16 che FRAGM_SIZE riesce ad avere
	size_t dim_ct = ( FRAGM_SIZE / BLOCK_SIZE ) * BLOCK_SIZE;
	unsigned char ciphertext[dim_ct + BLOCK_SIZE];
	//TESTING DIMENSION FILE
	FILE* fp = fopen("fileprova.txt", "r+");
	size_t ssst = fsize(fp);
	unsigned char* iv;
	encryptAndSendFile(fp,ssst, key, iv, ciphertext, TCP_socket);
	
}
*/

int main(int argc, char* argv[]){
	
	int TCP_socket;
	struct sockaddr_in sv_addr;
	//int message_type;
	int user_quit;
	size_t buflen;
	char* input_buffer = NULL;
	uint8_t message_type;
	int command;
	char buffer[MAX_COMMAND_INPUT];
	int ret;
	//int ris;
	// ad indicare che non e'  registrato	
	//int user_count = -1;	
	
	//controllo che ci siano tutti i parametri necessari
	if(argc != 3){
		std::cout<<"parametri input errati : sono necessari ip_server, port_server"<<std::endl;
		//printf("parametri input errati : sono necessari ip_server, port_server\n");
		return 1;
	}
	
	// Controllo che la porta sia valida
	int server_port = atoi(argv[2]);
	if(server_port < 1 || server_port > USHRT_MAX){
		std::cout << "Errore: Porta non valida" << std::endl;
		return 1;
	}
	
	//===== Chiave privata =====
	OpenSSL_add_all_algorithms();
	EVP_PKEY* prvkey;
	if(load_private_key(CLIENT_PRVKEY, CLIENT_PRVKEY_PASSWORD, &prvkey) < 0){
		std::cerr << "Errore durante il caricamento della chiave privata" << std::endl;
		exit(-1);
	}
	
	//===== Creazione store =====
	
	// Leggo il certificato CA
	X509* CA_cert = NULL;
	if(load_cert(CA_CERTIFICATE_FILENAME, &CA_cert) < 0){
		std::cerr << "Errore durante il caricamento del certificato CA" << std::endl;
		exit(-1);
	}
	
	// Leggo il CRL
	X509_CRL* crl = NULL;
	if(load_crl(CRL_FILENAME, &crl) < 0){
		std::cerr << "Errore durante il caricamento del CRL" << std::endl;
		exit(-1);
	}
	
	// Creazione dello store dei certificati
	X509_STORE* store = NULL;
	if(create_store(&store, CA_cert, crl) < 0){
		std::cerr << "Errore durante la creazioni dello store" << std::endl;
		exit(-1);
	}
	
	//===== Creazione socket =====
	
	fd_set master;
	fd_set read_fds;
	
	FD_ZERO(&master);
	FD_ZERO(&read_fds);
	
	// to catch input keyboard command.
	FD_SET(fileno(stdin), &master);	
	
	// Creazione dell'indirizzo del server
	memset(&sv_addr, 0, sizeof(sv_addr));//TODO: valutare se è pericolosa
	sv_addr.sin_family = AF_INET;
	sv_addr.sin_port = htons(server_port);
	
	// Imposto l'indirizzo IP del server
	if(inet_pton(AF_INET, argv[1], &sv_addr.sin_addr) < 1){
		std::cout << "Indirizzo IP del server non valido, errore: " << errno << std::endl;
	}
	
	// Creazione del socket
	if((TCP_socket = socket(AF_INET, SOCK_STREAM, 0))<0){
		//printf("errore creazione socket tcp, err:#%d\n", errno);
		std::cerr<<"errore creazione socket tcp, err: #"<<errno<<std::endl;
		exit(5);
	}
	Session session = Session(0);
	
	// Connessione del socket
	if(connect(TCP_socket, (struct sockaddr*)&sv_addr, sizeof(sv_addr))<0){
		//printf("impossibile connettersi al server, err: #%d\n", errno);
		std::cerr<<"impossibile connettersi al server, err: #"<<errno<<std::endl;
		exit(6);
	}
	
	// Controllo che il server abbia accettato la connessione
	recv(TCP_socket, &message_type, sizeof(message_type), 0);
	if(message_type == MESSAGE_FULL){
		std::cout<<"massimo numero di utenti connessi, riprovare piu' tardi"<<std::endl;
		//printf("massimo numero di utenti connessi, riprovare piu' tardi\n");
		exit(7);
	}
	
	// Aggiungo il socket al set
	FD_SET(TCP_socket, &master);
	//printf("connesso al server\n");
	std::cout<<"connesso al server"<<std::endl;
	
	//===== HANDSHAKE - PASSO 1 =====
	
	// Leggo il certificato del client
	X509* client_certificate = NULL;
	if(load_cert(CLIENT_CERTIFICATE_FILENAME, &client_certificate) < 0){
		std::cerr << "Errore durante il caricamento del certificato" << std::endl;
		exit(-1);
	}
	
	//  Debug
	X509_NAME* abc = X509_get_subject_name(client_certificate);
	char* temp_buffer = X509_NAME_oneline(abc, NULL, 0);
	std::cout << "Certificato client:" << temp_buffer << std::endl;
	// /Debug
	
	// Serializzo il certificato del client
	size_t cert_size;
	unsigned char* cert_buffer = NULL;
	cert_size = i2d_X509(client_certificate, &cert_buffer);
	if(cert_size < 0){
		std::cerr<<"Errore nella serializzazione del certificato"<<std::endl;
		exit(-1);
	}
	
	// Invio il certificato serializzato e il numero sequenziale, preceduti dal byte che indica il tipo di messaggio
	message_type = HANDSHAKE_1;
	send(TCP_socket, &message_type, sizeof(message_type), 0);
	
	// Invio il certificato
	if(send_data(TCP_socket, (const char*)cert_buffer, cert_size) < 0){
		std::cerr<<"Errore durante l'invio del certificato"<<std::endl;
		exit(-1);
	}
	delete[] cert_buffer;
	cert_buffer = NULL;
	
	// Recupero il numero sequenziale
	uint32_t nonce_buffer = session.get_my_nonce();
	if(nonce_buffer == UINT32_MAX){
		quitClient(TCP_socket);//TODO: chiudere correttamente il client in tutti i casi di errore
		close(TCP_socket);
		exit(-1);
	}
	
	// Invio il numero sequenziale
	if(send_data(TCP_socket, (const char*)&nonce_buffer, sizeof(nonce_buffer)) < 0){
		std::cerr<<"Errore durante l'invio del numero sequenziale"<<std::endl;
		exit(-1);
	}
	
	//===== PASSO 2 =====
	
	// Ricevo i dati in ingresso (certificato)
	if(receive_data(TCP_socket, &input_buffer, &buflen) < 0){
		std::cerr << "Errore durante la ricezione del certificato del server" << std::endl;
		exit(-1);
	}
	
	// Deserializzo il certificato del server appena ricevuto
	// d2i_X509(...) incrementa il puntatore, è necessario conservarne il valore originale per deallocarlo successivamente
	temp_buffer = input_buffer;
	X509* server_certificate = d2i_X509(NULL, (const unsigned char**)&temp_buffer, buflen);
	if(server_certificate == NULL){
		std::cerr << "Errore durante la ricezione del certificato del client" << std::endl;
		exit(-1);
	}
	
	// Dealloco il buffer allocato nella funzione receive_data(...)
	delete[] input_buffer;
	input_buffer = NULL;
	
	//  Debug
	abc = X509_get_subject_name(server_certificate);
	temp_buffer = X509_NAME_oneline(abc, NULL, 0);
	std::cout << "Certificato server:" << temp_buffer << std::endl;
	// /Debug
	
	// Verifico il certificato
	ret = verify_cert(store, server_certificate);
	if(ret < 0){// Errore interno durante la verifica
		exit(-1);
	}
	if(ret == 0){// Certificato non valido
		quitClient(TCP_socket);
		exit(-1);
	}
	
	// Estraggo la chiave pubblica del server dal certificato
	EVP_PKEY *server_pubkey = NULL;
	server_pubkey = X509_get_pubkey(server_certificate);
	if(server_pubkey == NULL){
		std::cerr << "Errore durante l'estrazione della chiave pubblica del server" << std::endl;
		quitClient(TCP_socket);
		exit(-1);
	}
	else{
		session.set_counterpart_pubkey(server_pubkey);
	}
	
	// Ricevo i dati in ingresso (chiavi simmetriche cifrate)
	size_t ciphertextlen;
	unsigned char* ciphertext_buffer = NULL;
	if(receive_data(TCP_socket, (char**)&ciphertext_buffer, &ciphertextlen) < 0){
		std::cerr << "Errore durante la ricezione del certificato del server" << std::endl;
		exit(-1);
	}
	
	//  Debug
	std::cout << "Dimensione ciphertext_buffer: " << ciphertextlen << std::endl;
	BIO_dump_fp(stdout, (const char*)ciphertext_buffer, ciphertextlen);
	// /Debug
	
	// Ricevo i dati in ingresso (encrypted_key)
	size_t encrypted_key_len;
	unsigned char* encrypted_key = NULL;
	if(receive_data(TCP_socket, (char**)&encrypted_key, &encrypted_key_len) < 0){
		std::cerr << "Errore durante la ricezione di encrypted_key" << std::endl;
		exit(-1);
	}
	
	//  Debug
	std::cout << "Dimensione encrypted_key: " << encrypted_key_len << std::endl;
	BIO_dump_fp(stdout, (const char*)encrypted_key, encrypted_key_len);
	// /Debug
	
	// Ricevo i dati in ingresso (IV)
	size_t iv_len;
	unsigned char* iv = NULL;
	if(receive_data(TCP_socket, (char**)&iv, &iv_len) < 0){
		std::cerr << "Errore durante la ricezione di IV" << std::endl;
		exit(-1);
	}
	
	//  Debug
	std::cout << "Dimensione iv: " << iv_len << std::endl;
	BIO_dump_fp(stdout, (const char*)iv, iv_len);
	// /Debug
	
	// Ricevo i dati in ingresso (numero sequenziale)
	if(receive_data(TCP_socket, &input_buffer, &buflen) < 0){
		std::cerr << "Errore durante la ricezione del numero sequenziale" << std::endl;
		exit(-1);
	}
	
	//  Debug
	std::cout << "Dimensione input_buffer: " << buflen << std::endl;
	BIO_dump_fp(stdout, (const char*)input_buffer, buflen);
	// /Debug
	
	if(nonce_buffer != *((uint32_t*)input_buffer)){
		std::cerr << "Il numero sequenziale non corrisponde" << std::endl;
		exit(-1);
	}
	
	// Dealloco il buffer allocato nella funzione receive_data(...)
	delete[] input_buffer;
	input_buffer = NULL;
	
	// Decifro le chiavi simmetriche
	unsigned char* plaintext_buffer = NULL;
	if(decrypt_asym(ciphertext_buffer, ciphertextlen, encrypted_key, encrypted_key_len, iv, prvkey, &plaintext_buffer, &buflen) < 0){
		std::cerr << "Errore durante la decifratura delle chiavi simmetriche" << std::endl;
		exit(-1);
	}
	
	// Salvo le chiavi simmetriche ricevute
	session.set_key_auth(EVP_aes_128_cbc(), (char*)plaintext_buffer);
	session.set_key_encr(EVP_aes_128_cbc(), (char*)plaintext_buffer + EVP_CIPHER_key_length(EVP_aes_128_cbc()));
	
	//  Debug
	std::cout << "Chiave di autenticazione" << std::endl;
	input_buffer = new char[EVP_CIPHER_key_length(EVP_aes_128_cbc())];
	memset(input_buffer, 0, EVP_CIPHER_key_length(EVP_aes_128_cbc()));
	session.get_key_auth(input_buffer);
	BIO_dump_fp(stdout, (const char*)input_buffer, EVP_CIPHER_key_length(EVP_aes_128_cbc()));
	std::cout << "Chiave di cifratura" << std::endl;
	session.get_key_encr(input_buffer);
	BIO_dump_fp(stdout, (const char*)input_buffer, EVP_CIPHER_key_length(EVP_aes_128_cbc()));
	// /Debug
	
	user_quit = 0;
	print_available_commands();	
	while(user_quit == 0){
		read_fds = master;
		int fdmax = (fileno(stdin) > TCP_socket)? fileno(stdin) : TCP_socket;		
		print_prompt();
		select(fdmax+1, &read_fds, NULL, NULL, NULL);
		if(FD_ISSET(fileno(stdin), &read_fds)){//input da terminale
			// controllare come prendere byte da tastiera
			// SLIDE 11-12 SECURECODING
			//fgets(buffer, sizeof(buffer), stdin);	
			std::cin>>buffer;		
  		   	command = identifyCommand(buffer);
			switch(command){
				case COMMAND_HELP:
					std::cout<<MESSAGE_USER_COMMAND_DETAILED<<std::endl;
					//printf("%s", MESSAGE_USER_COMMAND_DETAILED);
					break;					
				case COMMAND_FILELIST:
					std::cout<<"Contatto il server..."<<std::endl;
					//printf("Contatto il server...\n");
					//modificare con struct file
					//struct users all_user[MAX_USER_CONNECTED];					
					//user_count = retrieveClientList(TCP_socket, all_user);
					break;					
				case COMMAND_UPLOAD:	
					break;						
				case COMMAND_DOWNLOAD:
					//encrypt(TCP_socket);
					break;
				case COMMAND_QUIT:
					quitClient(TCP_socket);
					close(TCP_socket);
					return 0;
				default:
					std::cout << MESSAGE_INVALID_COMMAND << std::endl;
					break;
			}
		}
		
		if(FD_ISSET(TCP_socket, &read_fds)){// Input dalla rete
		//il server si e' disconnesso
			std::cout<<"Ci sono problemi con il server, ci scusiamo per il disagio"<<std::endl;
			//printf("\nCi sono problemi con il server, ci scusiamo per il disagio\n");
			return 0;
		}
	}
	return 0;
}

