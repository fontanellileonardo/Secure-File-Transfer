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

#include "client_util.h"
#include "common_util.h"

EVP_PKEY* prvkey = NULL;
X509* client_certificate = NULL;
X509* server_certificate = NULL;
EVP_PKEY* server_pubkey = NULL;

void terminate(int value){
	if(TCP_socket)
		close(TCP_socket);
	// Dealloco la chiave pubblica del server
	if(server_pubkey != NULL)
		EVP_PKEY_free(server_pubkey);
	// Dealloco il certificato del server
	if(server_certificate != NULL)
		X509_free(server_certificate);
	// Dealloco il certificato del client
	if(client_certificate != NULL)
		X509_free(client_certificate);
	// Dealloco la chiave privata
	if(prvkey != NULL)
		EVP_PKEY_free(prvkey);
	// Removes all ciphers and digests from the table
	EVP_cleanup();
	exit(value);
}

int main(int argc, char* argv[]){
	struct sockaddr_in sv_addr;
	//int message_type;
	int user_quit;
	size_t buflen;
	char* input_buffer = NULL;
	uint8_t message_type;
	uint8_t command;
	char buffer[MAX_COMMAND_INPUT];
	int ret;
	
	//controllo che ci siano tutti i parametri necessari
	if(argc != 3){
		std::cout<<"parametri input errati : sono necessari ip_server, port_server"<<std::endl;
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
	if(load_private_key(CLIENT_PRVKEY, CLIENT_PRVKEY_PASSWORD, &prvkey) < 0){
		std::cerr << "Errore durante il caricamento della chiave privata" << std::endl;
		terminate(-1);
	}
	
	//===== Creazione store =====
	
	// Leggo il certificato CA
	X509* CA_cert = NULL;
	if(load_cert(CA_CERTIFICATE_FILENAME, &CA_cert) < 0){
		std::cerr << "Errore durante il caricamento del certificato CA" << std::endl;
		terminate(-2);
	}
	
	// Leggo il CRL
	X509_CRL* crl = NULL;
	if(load_crl(CRL_FILENAME, &crl) < 0){
		std::cerr << "Errore durante il caricamento del CRL" << std::endl;
		terminate(-3);
	}
	
	// Creazione dello store dei certificati
	X509_STORE* store = NULL;
	if(create_store(&store, CA_cert, crl) < 0){
		std::cerr << "Errore durante la creazioni dello store" << std::endl;
		terminate(-4);
	}
	
	//===== Creazione socket =====
	
	fd_set master;
	fd_set read_fds;
	
	FD_ZERO(&master);
	FD_ZERO(&read_fds);
	
	// to catch input keyboard command.
	FD_SET(fileno(stdin), &master);	
	
	// Creazione dell'indirizzo del server
	memset(&sv_addr, 0, sizeof(sv_addr));
	sv_addr.sin_family = AF_INET;
	sv_addr.sin_port = htons(server_port);
	
	// Imposto l'indirizzo IP del server
	if(inet_pton(AF_INET, argv[1], &sv_addr.sin_addr) < 1){
		std::cout << "Indirizzo IP del server non valido, errore: " << errno << std::endl;
	}
	
	// Creazione del socket
	if((TCP_socket = socket(AF_INET, SOCK_STREAM, 0))<0){
		std::cerr << "Errore creazione socket tcp, err: #" << errno << std::endl;
		terminate(-5);
	}
	
	// Imposto il timeout sul socket
	struct timeval timeout;
	timeout.tv_sec = 10;
	timeout.tv_usec = 0;
	setsockopt(TCP_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	
	// Creazione oggetto utilizzato per contenere le informazioni sulla connessione
	Session session = Session(TCP_socket);
	
	// Connessione del socket
	if(connect(TCP_socket, (struct sockaddr*)&sv_addr, sizeof(sv_addr))<0){
		std::cerr << "Impossibile connettersi al server, err: #" << errno << std::endl;
		terminate(-6);
	}
	
	// Controllo che il server abbia accettato la connessione
	recv(TCP_socket, &message_type, sizeof(message_type), 0);
	if(message_type == MESSAGE_FULL){
		std::cout << "Massimo numero di utenti connessi, riprovare piu' tardi" << std::endl;
		terminate(-7);
	}
	
	// Aggiungo il socket al set
	FD_SET(TCP_socket, &master);
	std::cout << "Connesso al server" << std::endl;
	
	//===== HANDSHAKE - PASSO 1 =====
	
	// Leggo il certificato del client
	if(load_cert(CLIENT_CERTIFICATE_FILENAME, &client_certificate) < 0){
		std::cerr << "Errore durante il caricamento del certificato" << std::endl;
		terminate(-8);
	}
	
	//  Debug
	X509_NAME* abc_1 = X509_get_subject_name(client_certificate);// The returned value is an internal pointer which MUST NOT be freed
	char* temp_buffer_1 = X509_NAME_oneline(abc_1, NULL, 0);
	std::cout << "Certificato client: " << temp_buffer_1 << std::endl;
	OPENSSL_free(temp_buffer_1);
	// /Debug
	
	// Serializzo il certificato del client
	size_t cert_size;
	unsigned char* cert_buffer = NULL;
	cert_size = i2d_X509(client_certificate, &cert_buffer);
	if(cert_size < 0){
		std::cerr << "Errore nella serializzazione del certificato" << std::endl;
		terminate(-9);
	}
	
	// Invio i byte che indicano il tipo di messaggio (HANDSHAKE)
	size_t command_len = 4 + 16 + 32;// numero sequenziale + comando cifrato + hash(numero sequenziale, comando cifrato)
	unsigned char handshake_command[command_len];
	memset(handshake_command, 0, command_len);
	if(send(TCP_socket, &handshake_command, command_len, 0) != (int)command_len){
		std::cerr << "Errore durante l'inizializzazione della connessione sicura" << std::endl;
		terminate(-10);
	}
	
	// Invio il certificato
	if(send_data(TCP_socket, (const char*)cert_buffer, cert_size) < 0){
		std::cerr << "Errore durante l'invio del certificato" << std::endl;
		terminate(-11);
	}
	
	OPENSSL_free(cert_buffer);
	cert_buffer = NULL;
	
	// Recupero il numero sequenziale
	uint32_t nonce_buffer = session.get_my_nonce();
	if(nonce_buffer == UINT32_MAX){
		std::cerr << "Il numero sequenziale ha raggiunto il limite. Terminazione..." << std::endl;
		send_error(TCP_socket);
		terminate(-12);
	}
	
	//  Debug
	std::cout << "Numero sequenziale client: " << nonce_buffer << std::endl;
	// /Debug
	
	nonce_buffer = htonl(nonce_buffer);
	
	// Invio il numero sequenziale
	if(send_data(TCP_socket, (const char*)&nonce_buffer, sizeof(nonce_buffer)) < 0){
		std::cerr << "Errore durante l'invio del nonce" << std::endl;
		terminate(-13);
	}
	
	//===== PASSO 2 =====
	
	// Ricevo i dati in ingresso (certificato)
	if(receive_data(TCP_socket, &input_buffer, &buflen) < 0){
		std::cerr << "Errore durante la ricezione del certificato del server" << std::endl;
		terminate(-14);
	}
	
	if(buflen > 0){
		// Deserializzo il certificato del server appena ricevuto
		// d2i_X509(...) incrementa il puntatore, è necessario conservarne il valore originale per deallocarlo successivamente
		char* temp_buffer_deser = input_buffer;
		server_certificate = d2i_X509(NULL, (const unsigned char**)&temp_buffer_deser, buflen);
		if(server_certificate == NULL){
			std::cerr << "Errore durante la deserializzazione del certificato del server" << std::endl;
			terminate(-15);
		}
		
		// Dealloco il buffer allocato nella funzione receive_data(...)
		delete[] input_buffer;
		input_buffer = NULL;
		
		//  Debug
		X509_NAME* abc_2 = X509_get_subject_name(server_certificate);// The returned value is an internal pointer which MUST NOT be freed
		char* temp_buffer_2 = X509_NAME_oneline(abc_2, NULL, 0);
		std::cout << "Certificato server: " << temp_buffer_2 << std::endl;
		OPENSSL_free(temp_buffer_2);
		// /Debug
		
		// Verifico il certificato
		ret = verify_cert(store, server_certificate);
		if(ret < 0){// Errore interno durante la verifica
			terminate(-16);
		}
		if(ret == 0){
			std::cout << "Certificato del server non valido" << std::endl;
			terminate(-17);
		}
		
		// Estraggo la chiave pubblica del server dal certificato
		server_pubkey = NULL;
		server_pubkey = X509_get_pubkey(server_certificate);
		if(server_pubkey == NULL){
			std::cerr << "Errore durante l'estrazione della chiave pubblica del server" << std::endl;
			terminate(-18);
		}
		else{
			session.set_counterpart_pubkey(server_pubkey);
		}
	}
	else{
		std::cout << "Errore di comunicazione con il server" << std::endl;
		terminate(-100);
	}
	
	// Ricevo i dati in ingresso (chiavi simmetriche cifrate)
	size_t ciphertextlen;
	unsigned char* ciphertext_buffer = NULL;
	if(receive_data(TCP_socket, (char**)&ciphertext_buffer, &ciphertextlen) < 0){
		std::cerr << "Errore durante la ricezione delle chiavi simmetriche cifrate" << std::endl;
		terminate(-19);
	}
	
	if(ciphertextlen == 0){
		std::cout << "Errore di comunicazione con il server" << std::endl;
		terminate(-100);
	}
	
	// Ricevo i dati in ingresso (encrypted_key)
	size_t encrypted_key_len;
	unsigned char* encrypted_key = NULL;
	if(receive_data(TCP_socket, (char**)&encrypted_key, &encrypted_key_len) < 0){
		std::cerr << "Errore durante la ricezione di encrypted_key" << std::endl;
		terminate(-20);
	}
	
	if(encrypted_key_len == 0){
		std::cout << "Errore di comunicazione con il server" << std::endl;
		terminate(-100);
	}
	
	// Ricevo i dati in ingresso (IV)
	size_t iv_len;
	unsigned char* iv = NULL;
	if(receive_data(TCP_socket, (char**)&iv, &iv_len) < 0){
		std::cerr << "Errore durante la ricezione di IV" << std::endl;
		terminate(-21);
	}
	
	if(iv_len == 0){
		std::cout << "Errore di comunicazione con il server" << std::endl;
		terminate(-100);
	}
	
	// Ricevo i dati in ingresso (nonce)
	if(receive_data(TCP_socket, &input_buffer, &buflen) < 0){
		std::cerr << "Errore durante la ricezione del numero sequenziale del client" << std::endl;
		terminate(-22);
	}
	
	if(buflen == 0){
		std::cout << "Errore di comunicazione con il server" << std::endl;
		terminate(-100);
	}
	
	if(nonce_buffer != *((uint32_t*)input_buffer)){
		std::cerr << "Il numero sequenziale del client non corrisponde" << std::endl;
		send_error(TCP_socket);
		terminate(-23);
	}
	
	// Inizializzo il buffer per la verifica del messaggio
	size_t msg_to_be_verified_len = ciphertextlen + encrypted_key_len + iv_len + buflen;
	unsigned char* msg_to_be_verified = new unsigned char[msg_to_be_verified_len];
	memcpy(msg_to_be_verified, ciphertext_buffer, ciphertextlen);
	memcpy(msg_to_be_verified + ciphertextlen, encrypted_key, encrypted_key_len);
	memcpy(msg_to_be_verified + ciphertextlen + encrypted_key_len, iv, iv_len);
	memcpy(msg_to_be_verified + ciphertextlen + encrypted_key_len + iv_len, input_buffer, buflen);
	
	// Dealloco il buffer allocato nella funzione receive_data(...)
	delete[] input_buffer;
	input_buffer = NULL;
	
	// Decifro le chiavi simmetriche
	unsigned char* plaintext_buffer = NULL;
	if(decrypt_asym(ciphertext_buffer, ciphertextlen, encrypted_key, encrypted_key_len, iv, prvkey, &plaintext_buffer, &buflen) < 0){
		std::cerr << "Errore durante la decifratura delle chiavi simmetriche" << std::endl;
		send_error(TCP_socket);
		terminate(-24);
	}
	
	delete[] ciphertext_buffer;
	ciphertext_buffer = NULL;
	delete[] encrypted_key;
	encrypted_key = NULL;
	
	// Salvo le chiavi simmetriche ricevute e IV
	session.set_key_auth(EVP_sha256(), (char*)plaintext_buffer);
	session.set_key_encr(EVP_aes_128_cbc(), (char*)plaintext_buffer + EVP_MD_size(EVP_sha256()));
	session.set_iv(EVP_aes_128_cbc(), (char*)iv);
	
	delete[] plaintext_buffer;
	plaintext_buffer = NULL;
	delete[] iv;
	iv = NULL;
	
	// Ricevo la firma di ({chiavi simmetriche}Kek, {Kek}Ka+, IV, numero_sequenziale)
	if(receive_data(TCP_socket, &input_buffer, &buflen) < 0){
		std::cerr << "Errore durante la ricezione della firma" << std::endl;
		terminate(-25);
	}
	
	if(buflen == 0){
		std::cout << "Errore di comunicazione con il server" << std::endl;
		terminate(-100);
	}
	
	ret = sign_asym_verify(msg_to_be_verified, msg_to_be_verified_len, (unsigned char*)input_buffer, buflen, session.get_counterpart_pubkey());
	if(ret < 0){// Errore interno durante la verifica
		std::cerr << "Errore durante la verifica della firma" << std::endl;
		send_error(TCP_socket);
		terminate(-26);
	}
	if(ret == 0){// Certificato non valido
		std::cerr << "Firma non valida" << std::endl;
		send_error(TCP_socket);
		terminate(-27);
	}
	
	delete[] input_buffer;
	input_buffer = NULL;
	
	// Ricevo il numero sequenziale del server
	if(receive_data(TCP_socket, &input_buffer, &buflen) < 0){
		std::cerr << "Errore durante la ricezione del numero sequenziale del server" << std::endl;
		terminate(-28);
	}
	
	if(buflen == 0){
		std::cout << "Errore di comunicazione con il server" << std::endl;
		terminate(-100);
	}
	
	nonce_buffer = *((uint32_t*)input_buffer);
	
	// Salvo il numero sequenziale del server
	session.set_counterpart_nonce(ntohl(nonce_buffer));
	
	//  Debug
	std::cout << "Numero sequenziale server: " << ntohl(nonce_buffer) << std::endl;
	// /Debug
	
	//===== PASSO 3 =====
	
	// Invio il numero sequenziale del server
	if(send_data(TCP_socket, (const char*)&nonce_buffer, sizeof(nonce_buffer)) < 0){
		std::cerr << "Errore durante l'invio del numero sequenziale del server" << std::endl;
		terminate(-29);
	}
	
	// Firmo il numero sequenziale ricevuto dal server
	if(sign_asym((char*)&nonce_buffer, sizeof(nonce_buffer), prvkey, (unsigned char**)&ciphertext_buffer, &ciphertextlen) < 0){
		std::cerr << "Errore durante la firma del numero sequenziale" << std::endl;
		terminate(-30);
	}
	
	// Invio la firma del numero sequenziale
	if(send_data(TCP_socket, (const char*)ciphertext_buffer, ciphertextlen) < 0){
		std::cerr<<"Errore durante l'invio della firma del numero sequenziale"<<std::endl;
		terminate(-31);
	}
	
	//  Debug
	std::cout << "Scambio chiavi simmetriche con il server eseguito" << std::endl;
	// /Debug
	
	user_quit = 0;
	std::cout << MESSAGE_USER_COMMAND << std::endl;
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
				case COMMAND_LIST:
					{
						// Invio il comando
						if(send_command(COMMAND_LIST, session) != 1){
							std::cerr << "Il numero sequenziale ha raggiunto il limite. Terminazione..." << std::endl;
							terminate(-1);
						}
						
						// Ricevo i dati in ingresso (lista file)
						int ret = receive_data_encr(&input_buffer, &buflen, &session);
						if(ret < 1)
							terminate(0);
						
						// Stampo la lista
						std::cout << input_buffer << std::endl;
						
						// Dealloco il buffer allocato nella funzione receive_data_encr(...)
						delete[] input_buffer;
						input_buffer = NULL;
					}
					break;
				case COMMAND_HELP:
					std::cout << MESSAGE_USER_COMMAND << std::endl;
					break;				
				case COMMAND_UPLOAD:	
					break;						
				case COMMAND_DOWNLOAD:
					encrypt(TCP_socket);
					break;
				case COMMAND_QUIT:
					terminate(0);
				default:
					std::cout << MESSAGE_INVALID_COMMAND << std::endl;
					break;
			}
		}
		
		if(FD_ISSET(TCP_socket, &read_fds)){// Input dalla rete
		//TODO: controllare che byte arrivano per capire se è una disconnessione causata dalla quit_client() sul server
		//il server si e' disconnesso
			std::cout<<"Input dalla rete"<<std::endl;
			return 0;
		}
	}
	return 0;
}
