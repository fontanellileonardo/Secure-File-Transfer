#include <iostream>
#include <vector>

#include "server_util.h"
#include "common_util.h"

#define FRAGM_SIZE 33
#define BLOCK_SIZE 16

//static size_t CIPHER_SIZE = ( FRAGM_SIZE / BLOCK_SIZE ) * BLOCK_SIZE;//TODO: forse non tiene conto dell'eventuale padding
// pari al blocco intero

int connected_user_number = 0;

/*
// da controllare se va bene anche in c++
size_t fsize(FILE* fp){
	fseek(fp, 0, SEEK_END);
	long int clear_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	return clear_size;
}

int decryptAndWriteFile(int TCP_socket,  unsigned char* key, unsigned char* iv){
	
	uint16_t ufile_len;
	size_t file_len;
	
	//uint32_t umessage_type = 5;
	recv(TCP_socket, &ufile_len, sizeof(uint16_t), 0);
	file_len = ntohs(ufile_len);
	std::cout<<"dimensione file:"<<std::endl;
	//printf("dimensione file: %zd\n", file_len);
	
	EVP_CIPHER_CTX * dctx;
	int dlen = 0;
	int plaintext_len = 0;
	
	//create and initialize context
	dctx = EVP_CIPHER_CTX_new();
	//decrypt init
	EVP_DecryptInit(dctx, EVP_aes_128_cbc(), key, NULL);
	//decrypt update, one call is enough because our message is very short
	
	// string o lasciare unsigned char??
	unsigned char ciphertext[CIPHER_SIZE + BLOCK_SIZE];
	unsigned char plaintext[CIPHER_SIZE + BLOCK_SIZE];
	uint16_t ulen_cipher;
	size_t len_cipher;
	unsigned int i;
	int fw;
	FILE *fpp = fopen("fileprovaricez.txt", "w");
	for(i = 0; i < (file_len/FRAGM_SIZE ); i++){
		//printf("entro nel for\n");	
		recv(TCP_socket, &ulen_cipher, sizeof(uint16_t), 0);
		len_cipher = ntohs(ulen_cipher);
		//printf("ho ricevuto lunghezza: %zd\n", len_cipher);
		// DUBBIO: per farlo bene forse qui si dovrebbe allora un buffer in memoria dinamica di dimensione len_cipher
		recv(TCP_socket, &ciphertext, len_cipher, 0); 	
		//printf("ciphertext received is:\n");
		BIO_dump_fp(stdout, (const char * ) ciphertext, len_cipher);
		
		for (uint j = 0; j < len_cipher; j+=BLOCK_SIZE) {
			if( !EVP_DecryptUpdate(dctx, plaintext, &dlen, &ciphertext[j], BLOCK_SIZE)) {
				//printf("errore nella DecryptUpdate. dlen: %d\n",dlen);
				std::cout<<"errore nella DecryptUpdate. dlen: "<<dlen<<std::endl;
				exit(1);
			}
			// DUBBIO: anche se dlen è 32 plaintext_len è 16... Perchè??
			plaintext_len +=dlen;
			//printf("plaintext_len  :%i dlen: %d\n", plaintext_len,dlen);
			fw = fwrite(plaintext, 1, dlen, fpp);
			//printf("scritti %i bytes \n", fw);
			std::cout<<"plain is: "<<dlen<<std::endl;
			//printf("plain is: %d\n",dlen);
			BIO_dump_fp(stdout, (const char * ) plaintext, dlen);
			std::cout<<std::endl;	
			//printf("\n");
			//printf("j: %d; len_cipher: %ld; j+BLOCK_SIZE: %d\n",j,len_cipher, j+BLOCK_SIZE);
		}
  }
	//printf("i alla fine del for: %d\n",i);
	recv(TCP_socket, &ulen_cipher, sizeof(uint16_t), 0);
	len_cipher = ntohs(ulen_cipher);
	// DUBBIO: qui dovrei allocare dinamicamente un nuovo array ciphertext di lunghezza len_cipher
	recv(TCP_socket, ciphertext, len_cipher, 0); 	
	//printf("ciphertext received out the for is: %ld\n", len_cipher);
	BIO_dump_fp(stdout, (const char * ) ciphertext, len_cipher);

	// ultimo dato ricevuto potrebbe essere o solo padding, o contenente anche del plaintext significativo	
	if (file_len % FRAGM_SIZE != 0) {
		for (uint j = 0; j < len_cipher; j+=BLOCK_SIZE) {
			if( !EVP_DecryptUpdate(dctx, plaintext, &dlen, &ciphertext[j], BLOCK_SIZE)) {
				//printf("errore nella DecryptUpdate. dlen: %d\n",dlen);
				std::cout<<"errore nella DecryptUpdate. dlen: "<<dlen<<std::endl;
				exit(1);
			}
			// DUBBIO: anche se dlen è 32 plaintext_len è 16... Perchè??
			plaintext_len +=dlen;
			//printf("plaintext_len  :%i dlen: %d\n", plaintext_len,dlen);
			fw = fwrite(plaintext, 1, dlen, fpp);
			//printf("scritti %i bytes \n", fw);
			//printf("plain is: %d\n",dlen);
			BIO_dump_fp(stdout, (const char * ) plaintext, dlen);	
			//printf("\n");
			std::cout<<std::endl;
		}
	}	

  //printf("plain is BEFORE FINAL:\n");
	BIO_dump_fp(stdout, (const char * ) plaintext, dlen);
  //decrypt finalize
	if( 1 != EVP_DecryptFinal(dctx, plaintext, &dlen)) {
		//printf("errore final. dlen è: %d\n",dlen);
		std::cout<<"errore final. dlen è: "<<dlen<<std::endl;
		exit(1);
	}
	plaintext_len += dlen;
	// qui dovrei controllare che dlen non sia 0 altrimenti è inutile scrivere nel file
	//printf("plain is AFTER FINAL:\n");
	BIO_dump_fp(stdout, (const char * ) plaintext, dlen);
	fw = fwrite(plaintext, 1, dlen, fpp);
	//printf("plain is: %d\n", dlen);
	BIO_dump_fp(stdout, (const char * ) plaintext, dlen);	
	fclose(fpp);
	//clean context decr
	//printf("print prima\n");
	EVP_CIPHER_CTX_free(dctx);
	//printf("print dopo\n");
	return 0;	
}

void decrypt(int TCP_socket){
	unsigned char *key = (unsigned char*) "0123456789012345";
	unsigned char* iv;
	decryptAndWriteFile(TCP_socket, key, iv);
	//printf("sono fuori dal for\n");
}
*/

std::vector<Session*> clients;

Session *get_client_by_fd(unsigned int fd){
	for(auto i = clients.begin(); i != clients.end(); i++){
		if((*i)->get_fd() == fd)
			return *i;
	}
	return NULL;
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
	
	// Reset FDs
	FD_ZERO(&master);
	FD_ZERO(&read_fds);
	
	// Controllo che ci siano tutti i parametri necessari
	if(argc != 2){
		std::cout<<"Inserire la porta"<<std::endl;
		//printf("Inserire la porta\n");
		return 1;
	}
	
	// Controllo che la porta sia valida
	int server_port = atoi(argv[1]);
	if(server_port < 1 || server_port > USHRT_MAX){
		std::cout << "Errore: Porta non valida" << std::endl;
		return 1;
	}
	
	// Creazione del socket principale
	if((listener = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		//printf("Errore nella creazione del socket listener, errore: %d \n", errno);
		std::cout<<"Errore nella creazione del socket listener, errore: "<<errno<<std::endl;
		exit(1);
	}
	
	// Specifico di riusare il socket
	const int trueFlag = 1;
	setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &trueFlag, sizeof(int));
	
	// Creazione dell'indirizzo del server
	memset(&sv_addr, 0, sizeof(sv_addr));//TODO: valutare se è pericolosa
	sv_addr.sin_family = AF_INET;
	sv_addr.sin_port = htons(server_port);
	sv_addr.sin_addr.s_addr = INADDR_ANY;
	
	// Binding
	if(bind(listener, (struct sockaddr*)&sv_addr, sizeof(sv_addr)) < 0){
		std::cout<<"errore bind listener, errore: "<<errno<<std::endl;
		//printf("errore bind listener, errore: %d, \n", errno);
		exit(2);
	}	
	
	// Putting in listen mode
	if(listen(listener, 10) < 0){
		std::cout<<"errore su settaggio listen, errore: "<<errno<<std::endl;
		//printf("errore su settaggio listen, errore: %d \n", errno);
		exit(3);
	}
	
	// Add "listener" socket to the "master" set and update "socket counter"
	FD_SET(listener, &master);
	fdmax = listener;
		
	//printf("Server attivo, in attesa di connessioni. \n");
	std::cout<<"Server attivo, in attesa di connessioni."<<std::endl;
		
	while(1){
		read_fds = master;
		select(fdmax + 1, &read_fds, NULL, NULL, NULL);
		for(unsigned int i=0; i<=fdmax; i++){
			if(FD_ISSET(i, &read_fds)){
				if(i == listener){// Nuova richiesta di connessione
					socklen_t addrlen = sizeof(cl_addr);
					if((newfd = accept(listener, (struct sockaddr*)&cl_addr, &addrlen)) < 0){
						std::cerr << "Accept non riuscita, errore: " << errno << std::endl;
						return 1;
					}
					
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
						Session *client = new Session(newfd);
						clients.push_back(client);
						
						for(auto i = clients.begin(); i != clients.end(); i++)
							std::cout << "client fd " << (*i)->get_fd() << std::endl;
					}
				}
				else{// Richiesta da client già connesso
					size_t buflen;
					char* input_buffer = NULL;
					char* temp_buffer = NULL;
					//char input_buffer[512];
					uint8_t message_type;
					
					// Recupero la struttura che contiene i dati relativi al client che ha inviato il messaggio
					Session *client = get_client_by_fd(i);
					
					// Ricevo comando
					if(recv(i, &message_type, sizeof(message_type), 0) <= 0){
						quitClient(i, &master);
						connected_user_number--;
						std::cout<<"user disconnesso senza !quit, verra' messo offline"<<std::endl;						
						//printf("user disconnesso senza !quit, verra' messo offline\n");
						continue; //passi al prossimo pronto
					}
					
					fflush(stdout);//TODO: a cosa serve?
					
					X509* client_certificate = NULL;
					X509_NAME* abc = NULL;
					switch(message_type){
						case HANDSHAKE_1:
							std::cout << "Handshake fase 1" << std::endl;
							// Ricevo i dati in ingresso (certificato)
							if(receive_data(i, &input_buffer, &buflen) < 0){
								quitClient(i, &master);
								connected_user_number--;
								std::cout<<"user disconnesso senza !quit, verra' messo offline"<<std::endl;						
								//printf("user disconnesso senza !quit, verra' messo offline\n");
							}
							
							// Deserializzo il certificato del client appena ricevuto
							// d2i_X509(...) incrementa il puntatore, è necessario conservarne il valore originale per deallocarlo successivamente
							temp_buffer = input_buffer;
							client_certificate = d2i_X509(NULL, (const unsigned char**)&temp_buffer, buflen);
							if(client_certificate == NULL){
								std::cerr << "Errore durante la ricezione del certificato del client" << std::endl;
								exit(-1);
							}
							
							// Dealloco il buffer allocato nella funzione receive_data(...)
							delete[] input_buffer;
							input_buffer = NULL;
							
							//  Debug
							abc = X509_get_subject_name(client_certificate);
							temp_buffer = X509_NAME_oneline(abc, NULL, 0);
							std::cout << "Certificato:" << temp_buffer << std::endl;
							// /Debug
							
							// Ricevo i dati in ingresso (nonce)
							if(receive_data(i, &input_buffer, &buflen) < 0){
								quitClient(i, &master);
								connected_user_number--;
								std::cout<<"user disconnesso senza !quit, verra' messo offline"<<std::endl;						
								//printf("user disconnesso senza !quit, verra' messo offline\n");
							}
							
							//  Debug
							client->store_counterpart_nonce(*((uint32_t*)input_buffer));
							std::cout << "Client nonce: " << client->get_counterpart_nonce() << std::endl;
							// /Debug
							
							// Dealloco il buffer allocato nella funzione receive_data(...)
							delete[] input_buffer;
							input_buffer = NULL;
							
							break;
						case COMMAND_FILELIST:
							//TODO: implementare funzionalità
							break;
						case COMMAND_DOWNLOAD:
							//decrypt(i);
							break;
						case COMMAND_UPLOAD:		
							//TODO: implementare funzionalità	
							break;
						case COMMAND_QUIT:
							quitClient(i, &master);
							connected_user_number--;
							break;
						default:
							std::cout<<"errore nella comunicazione con il client"<<std::endl;
							//printf("errore nella comunicazione con il client\n");
							continue;		
					}// switch
				}// else
			}// if
		}// for
	}// while
	
	std::cout << "Server terminato";
	return 0;
}

//TODO: Si usa a volte return, a volte exit. Sistemare


