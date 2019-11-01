#include "server_util.h"

#define FRAGM_SIZE 33
#define BLOCK_SIZE 16

static size_t CIPHER_SIZE = ( FRAGM_SIZE / BLOCK_SIZE ) * BLOCK_SIZE;

int connected_user_number = 0;

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
	cout<<"dimensione file:"<<endl;
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
	int i;
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
				cout<<"errore nella DecryptUpdate. dlen: "<<dlen<<endl;
				exit(1);
			}
			// DUBBIO: anche se dlen è 32 plaintext_len è 16... Perchè??
			plaintext_len +=dlen;
			//printf("plaintext_len  :%i dlen: %d\n", plaintext_len,dlen);
			fw = fwrite(plaintext, 1, dlen, fpp);
			//printf("scritti %i bytes \n", fw);
			cout<<"plain is: "<<dlen<<endl;
			//printf("plain is: %d\n",dlen);
			BIO_dump_fp(stdout, (const char * ) plaintext, dlen);
			cout<<endl;	
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
				cout<<"errore nella DecryptUpdate. dlen: "<<dlen<<endl;
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
			cout<<endl;
		}
	}	

  //printf("plain is BEFORE FINAL:\n");
	BIO_dump_fp(stdout, (const char * ) plaintext, dlen);
  //decrypt finalize
	if( 1 != EVP_DecryptFinal(dctx, plaintext, &dlen)) {
		//printf("errore final. dlen è: %d\n",dlen);
		cout<<"errore final. dlen è: "<<dlen<<endl;
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

int main(int argc, char *argv[] ){
	
	fd_set master;
	fd_set read_fds;
	int fdmax;
		
	struct sockaddr_in sv_addr; 
	struct sockaddr_in cl_addr;
		
	int listener;
	int newfd;
		

	socklen_t addrlen;
	int i;
		
	FD_ZERO(&master);
	FD_ZERO(&read_fds);
		
	if(argc<2){
		cout<<"Inserire la porta"<<endl;
		//printf("Inserire la porta\n");
		return 1;
	}
		
	if((listener = socket(AF_INET, SOCK_STREAM, 0)) < 0 ){
		//printf("Errore nella creazione del socket listener, errore: %d \n", errno);
		cout<<"Errore nella creazione del socket listener, errore: "<<errno<<endl;
		exit(1);
	}
		
	int trueFlag = 1;
	setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &trueFlag, sizeof(int));
		
	sv_addr.sin_family = AF_INET;
		
	//controllo su argc
	sv_addr.sin_port = htons(atoi(argv[argc-1]));

	sv_addr.sin_addr.s_addr = INADDR_ANY;
	if(bind(listener, (struct sockaddr*)&sv_addr, sizeof(sv_addr))< 0){
		cout<<"errore bind listener, errore: "<<errno<<endl;
		//printf("errore bind listener, errore: %d, \n", errno);
		exit(2);
	}	
		
	if(listen(listener, 10)<0) {
		cout<<"errore su settaggio listen, errore: "<<errno<<endl;
		//printf("errore su settaggio listen, errore: %d \n", errno);
		exit(3);
	}
	FD_SET(listener, &master);
	fdmax = listener;
		
	//printf("Server attivo, in attesa di connessioni. \n");
	cout<<"Server attivo, in attesa di connessioni."<<endl;
		
	while(1){
		read_fds = master;
		select(fdmax + 1, &read_fds, NULL, NULL, NULL);
		for(i=0; i<=fdmax; i++){
			if(FD_ISSET(i, &read_fds)){
				if(i == listener){
					//nuova connessione al server
					// cambiare cl_addr con sockaddr_in?
					addrlen = sizeof(cl_addr);
					newfd = accept(listener, (struct sockaddr*)&cl_addr, &addrlen);
					FD_SET(newfd, &master);
					if(newfd > fdmax)
						fdmax = newfd;				
					connected_user_number++;
					//printf("nuovo user connesso\n");	
					cout<<"nuovo user connesso"<<endl;
					// All the communications must be confidential,
					// authenticated, and replay-protected.

					int message_type;
					uint32_t umessage_type;

					if(connected_user_number>=MAX_USER_CONNECTED)
						message_type = MESSAGE_FULL;
					else
						message_type = MESSAGE_NOT_FULL;			
					umessage_type = htonl(message_type);
					send(newfd, &umessage_type, sizeof(uint32_t), 0);
					if(connected_user_number>=MAX_USER_CONNECTED){
						close(newfd);
						FD_CLR(newfd, &master);
					}		
					continue;
				}
				else{	
					// controllo invio criptaggio ecc ecc
					int message_type;
					uint32_t umessage_type;
					
					//se client disconnesso gestisci disconnessione
					if(recv(i, &umessage_type, sizeof(uint32_t), 0)<= 0){		
						quitClient(i, &master);	
						cout<<"user disconnesso senza !quit, verra' messo offline"<<endl;						
						//printf("user disconnesso senza !quit, verra' messo offline\n");
						continue; //passi al prossimo pronto
					}
					fflush(stdout);
					message_type = ntohl(umessage_type);						
					switch(message_type){
						case COMMAND_FILELIST:
							break;
						case COMMAND_DOWNLOAD:
							decrypt(i);
							break;
						case COMMAND_UPLOAD:			
							break;
						case COMMAND_QUIT:
							quitClient(i, &master);
							connected_user_number--;
							break;
						default:
							cout<<"errore nella comunicazione con il client"<<endl;
							//printf("errore nella comunicazione con il client\n");
							continue;		
					}// switch
				}// else
			}// if
		}// for
	}// while
	return 0;
}




