#include <iostream>
#include <vector>
#include <unistd.h>

#include "common_util.h"
#include "utils.h"
#include "server_util.h"

EVP_PKEY* prvkey = NULL;
X509* CA_cert = NULL;
X509_CRL* crl = NULL;
X509_STORE* store = NULL;
X509* server_certificate = NULL;

int connected_user_number = 0;

// list
std::string list;

std::vector<Session*> clients;

Session *get_client_by_fd(unsigned int fd){
	for(auto i = clients.begin(); i != clients.end(); i++){
		if((*i)->get_fd() == fd)
			return *i;
	}
	return NULL;
}

//pone l'utente in stato offline e chiude la connessione tcp
// se notify_error = true comunica al client di chiudere la connessione
void quit_client(unsigned int socket, fd_set* master, bool notify_error){
	if(notify_error){
		send_error(socket);
	}
	
	close(socket);
	FD_CLR(socket, master);
	
	// Elimino la struttura corrispondente al client appena disconnesso
	for(auto i = clients.begin(); i != clients.end(); i++){
		if((*i)->get_fd() == socket){
			delete(*i);
			clients.erase(i);
			break;
		}
	}
	
	connected_user_number--;
	std::cout << "Client con file descriptor " << socket << " disconnesso" << std::endl;
	
	return;	
}

void terminate(int value){// Distruggo lo store dei certificati
	// Dealloco il certificato del server
	if(server_certificate != NULL)
		X509_free(server_certificate);
	// Dealloco lo store
	if(store != NULL)
		X509_STORE_free(store);
	// Dealloco il crl
	if(crl != NULL)
		X509_CRL_free(crl);
	// Dealloco il certificato della CA
	if(CA_cert != NULL)
		X509_free(CA_cert);
	// Dealloco la chiave privata
	if(prvkey != NULL)
		EVP_PKEY_free(prvkey);
	//Distruggo la tabella interna degli algoritmi
	EVP_cleanup();
	std::cout << "Server terminato";
	exit(value);
}

int main(int argc, char *argv[]){
	
	// File descriptor e il "contatore" di socket
	fd_set master;
	fd_set read_fds;
	unsigned int fdmax;
	
	// Strutture per gli indirizzi di server e client
	struct sockaddr_in sv_addr;
	struct sockaddr_in cl_addr;
	
	unsigned int listener; //descrittore del socket principale
	unsigned int newfd; //descrittore del socket con nuovo client
	
	X509_NAME* abc = NULL;
	char* temp_buffer = NULL;
	
	// Controllo che ci siano tutti i parametri necessari
	if(argc != 2){
		std::cout << "Inserire la porta" << std::endl;
		//printf("Inserire la porta\n");
		return 1;
	}
	
	// Controllo che la porta sia valida
	int server_port = atoi(argv[1]);
	if(server_port < 1 || server_port > USHRT_MAX){
		std::cout << "Errore: Porta non valida" << std::endl;
		return 1;
	}
	
	//===== Chiave privata =====
	OpenSSL_add_all_algorithms();
	if(load_private_key(SERVER_PRVKEY, SERVER_PRVKEY_PASSWORD, &prvkey) < 0){
		std::cerr << "Errore durante il caricamento della chiave privata" << std::endl;
		terminate(-1);
	}
	
	//===== Creazione store =====
	
	// Leggo il certificato CA
	if(load_cert(CA_CERTIFICATE_FILENAME, &CA_cert) < 0){
		std::cerr << "Errore durante il caricamento del certificato CA" << std::endl;
		terminate(-2);
	}
	
	// Leggo il CRL
	if(load_crl(CRL_FILENAME, &crl) < 0){
		std::cerr << "Errore durante il caricamento del CRL" << std::endl;
		terminate(-3);
	}
	
	// Creazione dello store dei certificati
	if(create_store(&store, CA_cert, crl) < 0){
		std::cerr << "Errore durante la creazioni dello store" << std::endl;
		terminate(-4);
	}
	
	//===== Certificato server =====
	
	// Leggo il certificato del server
	if(load_cert(SERVER_CERTIFICATE_FILENAME, &server_certificate) < 0){
		std::cerr << "Errore durante il caricamento del certificato del server" << std::endl;
		terminate(-5);
	}
	
	//  Debug
	abc = X509_get_subject_name(server_certificate);// The returned value is an internal pointer which MUST NOT be freed
	temp_buffer = X509_NAME_oneline(abc, NULL, 0);
	std::cout << "Certificato server: " << temp_buffer << std::endl;
	OPENSSL_free(temp_buffer);
	temp_buffer = NULL;
	// /Debug
	
	//===== Creazione socket =====
	
	// Reset FDs
	FD_ZERO(&master);
	FD_ZERO(&read_fds);
	
	// Creazione del socket principale
	if((listener = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		std::cerr << "Errore nella creazione del socket listener, errore: " << errno << std::endl;
		terminate(-6);
	}
	
	// Specifico di riusare il socket
	const int trueFlag = 1;
	setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &trueFlag, sizeof(int));
	
	// Creazione dell'indirizzo del server
	memset(&sv_addr, 0, sizeof(sv_addr));
	sv_addr.sin_family = AF_INET;
	sv_addr.sin_port = htons(server_port);
	sv_addr.sin_addr.s_addr = INADDR_ANY;
	
	// Binding
	if(bind(listener, (struct sockaddr*)&sv_addr, sizeof(sv_addr)) < 0){
		std::cerr << "Errore bind listener, errore: " << errno << std::endl;
		terminate(-7);
	}	
	
	// Putting in listen mode
	if(listen(listener, 10) < 0){
		std::cerr << "Errore su settaggio listen, errore: " << errno << std::endl;
		terminate(-8);
	}
	
	// Add "listener" socket to the "master" set and update "socket counter"
	FD_SET(listener, &master);
	fdmax = listener;
	
	std::cout << "Server attivo, in attesa di connessioni." << std::endl;
		
	while(1){
		read_fds = master;
		select(fdmax + 1, &read_fds, NULL, NULL, NULL);
		for(unsigned int i=0; i<=fdmax; i++){
			if(FD_ISSET(i, &read_fds)){
				if(i == listener){// Nuova richiesta di connessione
					socklen_t addrlen = sizeof(cl_addr);
					if((newfd = accept(listener, (struct sockaddr*)&cl_addr, &addrlen)) < 0){
						std::cerr << "Accept non riuscita, errore: " << errno << std::endl;
						continue;
					}
					
					// Imposto il timeout sul nuovo socket
					struct timeval timeout;
					timeout.tv_sec = 10;
					timeout.tv_usec = 0;
					setsockopt(newfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
					
					// Add "newfd" socket to the "master" set and update "socket counter"
					FD_SET(newfd, &master);
					if(newfd > fdmax)
						fdmax = newfd;
					
					// Controllo il numero di utenti connessi
					connected_user_number++;
					uint8_t message_type;
					if(connected_user_number > MAX_USER_CONNECTED){
						message_type = MESSAGE_FULL;
						std::cout << "Numero massimo utenti raggiunto" << std::endl;
					}
					else{
						message_type = MESSAGE_NOT_FULL;
						std::cout << "Nuovo utente connesso" << std::endl;
					}
					
					send(newfd, &message_type, sizeof(message_type), 0);
					
					if(connected_user_number > MAX_USER_CONNECTED){
						close(newfd);
						FD_CLR(newfd, &master);
						connected_user_number--;
					}
					else{
						// Aggiungo un nuovo elemento alla struttura contenente le info sui client connessi
						Session *client = new Session(newfd);
						clients.push_back(client);
					}
				}
				else{// Richiesta da client già connesso
					size_t buflen, ciphertextlen;
					char* input_buffer = NULL;
					char* output_buffer = NULL;
					char* plaintext_buffer = NULL;
					char* ciphertext_buffer = NULL;
					uint8_t message_type;
					uint32_t nonce;
					int ret;
					X509_NAME* client_certificate_name = NULL;
					char* client_certificate_name_buffer = NULL;
					
					X509* client_certificate = NULL;
					EVP_PKEY* client_pubkey = NULL;
					
					// Vengono utilizzati solo nella parte di handshake
					unsigned char* encrypted_key = NULL;
					size_t encrypted_key_len = 0;
					unsigned char* iv = NULL;
					
					// Recupero la struttura che contiene i dati relativi al client che ha inviato il messaggio
					Session *client = get_client_by_fd(i);
					
					ret = recv_command(message_type, client);
					if(ret < 0){
						quit_client(i, &master, false);
						continue; //passo al prossimo fd pronto
					}
					else if(ret == 0){
						std::cout << "Comando sconosciuto" << std::endl;
						continue; //passo al prossimo fd pronto
					}
					
					//fflush(stdout);

					switch(message_type){
						case HANDSHAKE:
							// Ricevo i dati in ingresso (certificato)
							if(receive_data(i, &input_buffer, &buflen) < 0){
								std::cerr << "Errore durante la ricezione del certificato del client" << std::endl;
								quit_client(i, &master, false);
								continue;
							}
							
							if(buflen > 0){
								// Deserializzo il certificato del client appena ricevuto
								// d2i_X509(...) incrementa il puntatore, è necessario conservarne il valore originale per deallocarlo successivamente
								temp_buffer = input_buffer;
								client_certificate = d2i_X509(NULL, (const unsigned char**)&temp_buffer, buflen);
								if(client_certificate == NULL){
									std::cerr << "Errore durante la deserializzazione del certificato del client" << std::endl;
									quit_client(i, &master, true);
									continue;
								}
								
								// Dealloco il buffer allocato nella funzione receive_data(...)
								delete[] input_buffer;
								input_buffer = NULL;
								
								//  Debug
								abc = X509_get_subject_name(client_certificate);
								temp_buffer = X509_NAME_oneline(abc, NULL, 0);
								std::cout << "Certificato client: " << temp_buffer << std::endl;
								OPENSSL_free(temp_buffer);
								temp_buffer = NULL;
								// /Debug
								
								// Verifico se il client è autorizzato
								client_certificate_name = X509_get_subject_name(client_certificate);// The returned value is an internal pointer which MUST NOT be freed
								client_certificate_name_buffer = X509_NAME_oneline(client_certificate_name, NULL, 0);
								if(!is_authorized(AUTHORIZED_CLIENTS_PATH, std::string(client_certificate_name_buffer))){
									std::cout << "Client non autorizzato" << std::endl;
									quit_client(i, &master, true);
									continue;
								}
								
								OPENSSL_free(client_certificate_name_buffer);
								client_certificate_name_buffer = NULL;
								
								// Verifico il certificato
								ret = verify_cert(store, client_certificate);
								if(ret < 0){// Errore interno durante la verifica
									quit_client(i, &master, true);
									continue;
								}
								if(ret == 0){// Certificato non valido
									std::cout << "Certificato del client non valido" << std::endl;
									quit_client(i, &master, true);
									continue;
								}
								
								// Estraggo la chiave pubblica del client dal certificato
								client_pubkey = X509_get_pubkey(client_certificate);
								if(client_pubkey == NULL){
									std::cerr << "Errore durante l'estrazione della chiave pubblica del client" << std::endl;
									quit_client(i, &master, true);
									continue;
								}
								else{
									client->set_counterpart_pubkey(client_pubkey);
								}
							}
							else{
								std::cout << "Errore di comunicazione con il client" << std::endl;
								quit_client(i, &master, false);
								continue;
							}
							
							// Ricevo i dati in ingresso (nonce)
							if(receive_data(i, &input_buffer, &buflen) < 0){
								std::cerr << "Errore durante la ricezione del numero sequenziale del client" << std::endl;
								quit_client(i, &master, false);
								continue;
							}
							
							if(buflen > 0){
								// Salvo il numero sequenziale del client
								nonce = *((uint32_t*)input_buffer);
								client->set_counterpart_nonce(ntohl(nonce));
								
								//  Debug
								std::cout << "Numero sequenziale client: " << ntohl(nonce) << std::endl;
								// /Debug
								
								// Dealloco il buffer allocato nella funzione receive_data(...)
								delete[] input_buffer;
								input_buffer = NULL;
							}
							else{
								std::cout << "Errore di comunicazione con il client" << std::endl;
								quit_client(i, &master, false);
								continue;
							}
							
							//===== PASSO 2 =====
							
							// Serializzo il certificato del server
							size_t cert_size;
							cert_size = i2d_X509(server_certificate, (unsigned char**)&output_buffer);
							if(cert_size < 0){
								std::cerr << "Errore nella serializzazione del certificato" << std::endl;
								quit_client(i, &master, true);
								continue;
							}
							
							// Invio il certificato
							if(send_data(i, output_buffer, cert_size) < 0){
								std::cerr << "Errore durante l'invio del certificato" << std::endl;
								quit_client(i, &master, false);
								continue;
							}
							
							OPENSSL_free(output_buffer);
							output_buffer = NULL;
							
							// Genero le chiavi di cifratura e autenticazione
							if(client->initialize(EVP_aes_128_cbc(), EVP_sha256()) < 0){
								std::cerr << "Errore durante la generazione delle chiavi simmetriche" << std::endl;
								quit_client(i, &master, true);
								continue;
							}
							
							// Cifro le chiavi appena generate con la chiave pubblica del client
							plaintext_buffer = new char[EVP_MD_size(EVP_sha256()) + EVP_CIPHER_key_length(EVP_aes_128_cbc())];
							client->get_key_auth(plaintext_buffer);
							client->get_key_encr(plaintext_buffer + EVP_MD_size(EVP_sha256()));
							
							// Cifro le chiavi simmetriche
							if(encrypt_asym(plaintext_buffer, (EVP_MD_size(EVP_sha256()) + EVP_CIPHER_key_length(EVP_aes_128_cbc())), client->get_counterpart_pubkey(), EVP_aes_128_cbc(), (unsigned char**)&ciphertext_buffer, &ciphertextlen, &encrypted_key, &encrypted_key_len, &iv) < 0){
								std::cerr << "Errore durante la cifratura delle chiavi simmetriche" << std::endl;
								quit_client(i, &master, true);
								continue;
							}
							
							// Salvo il valore di IV
							client->set_iv(EVP_aes_128_cbc(), (char*)iv);
							
							delete[] plaintext_buffer;
							plaintext_buffer = NULL;
							
							// Inizializzo il buffer per la parte da firmare ({chiavi simmetriche}Kek, {Kek}Ka+, IV, numero_sequenziale)
							buflen = ciphertextlen + encrypted_key_len + EVP_CIPHER_iv_length(EVP_aes_128_cbc()) + sizeof(nonce);
							plaintext_buffer = new char[buflen];
							
							// Copio le chiavi cifrate nel buffer appena creato
							memcpy(plaintext_buffer, ciphertext_buffer, ciphertextlen);
							
							delete[] ciphertext_buffer;
							ciphertext_buffer = NULL;
							
							// Invio le chiavi cifrate al client
							if(send_data(i, plaintext_buffer, ciphertextlen) < 0){
								std::cerr << "Errore durante l'invio delle chiavi simmetriche cifrate" << std::endl;
								quit_client(i, &master, true);
								continue;
							}
							
							// Copio encrypted_key nel buffer da firmare
							memcpy((plaintext_buffer + ciphertextlen), encrypted_key, encrypted_key_len);
							
							delete[] encrypted_key;
							encrypted_key = NULL;
							
							// Invio encrypted_key al client
							if(send_data(i, (plaintext_buffer + ciphertextlen), encrypted_key_len) < 0){
								std::cerr << "Errore durante l'invio di encrypted_key" << std::endl;
								quit_client(i, &master, false);
								continue;
							}
							
							// Copio IV nel buffer da firmare
							memcpy((plaintext_buffer + ciphertextlen + encrypted_key_len), iv, EVP_CIPHER_iv_length(EVP_aes_128_cbc()));
							
							delete[] iv;
							iv = NULL;
							
							// Invio IV al client
							if(send_data(i, (plaintext_buffer + ciphertextlen + encrypted_key_len), EVP_CIPHER_iv_length(EVP_aes_128_cbc())) < 0){
								std::cerr << "Errore durante l'invio di IV" << std::endl;
								quit_client(i, &master, false);
								continue;
							}
							
							// Copio il numero sequenziale del client nel buffer da firmare
							memcpy(plaintext_buffer + ciphertextlen + encrypted_key_len + EVP_CIPHER_iv_length(EVP_aes_128_cbc()), &nonce, sizeof(nonce));
							
							// Invio il numero sequenziale al client
							if(send_data(i, (const char*)&nonce, sizeof(nonce)) < 0){
								std::cerr << "Errore durante l'invio del numero sequenziale del client" << std::endl;
								quit_client(i, &master, false);
								continue;
							}
							
							// Firmo l'insieme dei dati ({chiavi simmetriche}Kek, {Kek}Ka+, IV, numero_sequenziale)
							if(sign_asym(plaintext_buffer, buflen, prvkey, (unsigned char**)&ciphertext_buffer, &ciphertextlen) < 0){
								std::cerr << "Errore durante la firma digitale" << std::endl;
								quit_client(i, &master, true);
								continue;
							}
							
							delete[] plaintext_buffer;
							plaintext_buffer = NULL;
							
							// Invio la firma di ({chiavi simmetriche}Kek, {Kek}Ka+, IV, numero_sequenziale)
							if(send_data(i, ciphertext_buffer, ciphertextlen) < 0){
								std::cerr << "Errore durante l'invio della firma" << std::endl;
								quit_client(i, &master, false);
								continue;
							}
							
							delete[] ciphertext_buffer;
							ciphertext_buffer = NULL;
							
							// Recupero il numero sequenziale
							nonce = client->get_my_nonce();
							if(nonce == UINT32_MAX){
								std::cerr << "Il numero sequenziale ha raggiunto il limite. Terminazione..." << std::endl;
								quit_client(i, &master, true);
								continue;
							}
							
							//  Debug
							std::cout << "Numero sequenziale server: " << nonce << std::endl;
							// /Debug
							
							nonce = htonl(nonce);
							
							// Invio il numero sequenziale
							if(send_data(i, (const char*)&nonce, sizeof(nonce)) < 0){
								std::cerr << "Errore durante l'invio del numero sequenziale del server" << std::endl;
								quit_client(i, &master, false);
								continue;
							}
							
							//===== PASSO 3 =====
							
							// Ricevo i dati in ingresso (numero sequenziale del server)
							if(receive_data(i, &input_buffer, &buflen) < 0){
								std::cerr << "Errore durante la ricezione del numero sequenziale del server" << std::endl;
								quit_client(i, &master, false);
								continue;
							}
							
							if(buflen > 0){
								if(nonce != *((uint32_t*)input_buffer)){
									std::cerr << "Il numero sequenziale del server non corrisponde" << std::endl;
									quit_client(i, &master, false);
									continue;
								}
							
								delete[] input_buffer;
								input_buffer = NULL;
							}
							else{
								std::cout << "Errore di comunicazione con il client" << std::endl;
								quit_client(i, &master, false);
								continue;
							}
							
							if(buflen > 0){
								// Ricevo i dati in ingresso (firma del numero sequenziale del server)
								if(receive_data(i, &input_buffer, &buflen) < 0){
									std::cerr << "Errore durante la ricezione della firma del numero sequenziale del server" << std::endl;
									quit_client(i, &master, false);
									continue;
								}
								
								// Verifico la firma
								ret = sign_asym_verify((unsigned char*)&nonce, sizeof(nonce), (unsigned char*)input_buffer, buflen, client->get_counterpart_pubkey());
								if(ret < 0){
									std::cerr << "Errore durante la verifica della firma" << std::endl;
									quit_client(i, &master, false);
									continue;
								}
								if(ret == 0){
									std::cerr << "Firma non valida" << std::endl;
									quit_client(i, &master, false);
									continue;
								}
								
								//  Debug
								std::cout << "Scambio chiavi simmetriche con il client eseguito" << std::endl;
								// /Debug
							}
							else{
								std::cout << "Errore di comunicazione con il client" << std::endl;
								quit_client(i, &master, false);
								continue;
							}
							
							break;
							
						case COMMAND_LIST:
							std::cout << "Ricevuto comando list" << std::endl;
							{
								// Costruisco la lista
								std::string list = list_files(SERVER_FILES_PATH);
								
								// Aggiungo il carattere di terminazione alla stringa
								const char* temp0 = list.c_str();
								char temp1[list.size() + 1];
								strncpy((char*)temp1, temp0, list.size());
								temp1[list.size()] = '\0';
								
								// Invio la lista
								int ret;
								ret = send_data_encr(temp1, (list.size() + 1), client);
								if(ret < 1){
									if(ret == 0)
										quit_client(i, &master, true);
									else
										quit_client(i, &master, false);
								}
							}
							
							break;
						case COMMAND_DOWNLOAD: {
							std::cout << "Comando di download ricevuto..." << std::endl;
							 
							// Ricevo il nome del file
							char* fileName = NULL;
							if(receive_file_name(&fileName, client) == -1) {
								std::cerr << "Errore nella ricezione del nome del file" << std::endl;
								if(send_nack(client) == -1)
									quit_client(i, &master, true);
								if(fileName != NULL)
									delete[] fileName;
								continue;
							}

							// controlla se il file esiste
							std::string filePath = SERVER_FILES_PATH;
							filePath.append(fileName);
							if(!checkFile(filePath)){
								std::cout << "Il file richiesto dal client non esiste" << std::endl;
								if(send_nack(client) == -1){
									quit_client(i, &master, true);
									delete[] fileName;
									continue;
								}
							}
							else{
								if(send_ack(client) == -1){
									quit_client(i, &master, true);
									delete[] fileName;
									continue;
								}
								std::cout<<"File esistente"<<std::endl;
								// inizializzo il buffer che conterrà il ciphertext
								size_t dim_ct = ( FRAGM_SIZE / BLOCK_SIZE ) * BLOCK_SIZE;
								unsigned char* ciphertext = new unsigned char[dim_ct + BLOCK_SIZE];

								std::cout << "Download del file in corso..." << std::endl;

								//Gestisce l'invio della dimensione del file, della dimensione dei chunk e dei chunk
								if(encryptAndSendFile(filePath, client) == -1) {
									std::cerr << "Errore nell'invio del file. Terminazione..." << std::endl;
									quit_client(i, &master, true);
								} else 
									std::cout << "Download del file completato" << std::endl;
							
								delete[] ciphertext;
							}
							delete[] fileName;

						}
							break;
						case COMMAND_UPLOAD:
						{
							std::cout<<"Comando di upload ricevuto..."<<std::endl;

							// Ricevo il nome del file
							char* fileName = NULL;
							if(receive_file_name(&fileName, client) == -1) {
								std::cerr << "Errore nella ricezione del nome del file" << std::endl;
								send_nack(client);
								if(fileName != NULL)
									delete[] fileName;
								continue;
							}

							send_ack(client);

							std::cout << "Upload del file in corso..." << std::endl;

							std::string filePath = SERVER_FILES_PATH;
							filePath.append(fileName);

							// come iv utilizzo il seq num del client
							if(decryptAndWriteFile(filePath, client) == -1){
								std::cerr << "Errore nella ricezione del file. Terminazione..." << std::endl;
							} else
								std::cout << "Upload del file completato" << std::endl;
							delete[] fileName;
						}
							break;
						case COMMAND_QUIT:
							quit_client(i, &master, false);
							break;
						default:
							std::cout << "Errore nella comunicazione con il client" << std::endl;
							continue;		
					}
				}
			}
		}
	}
	
	terminate(0);
	return 0;
}
