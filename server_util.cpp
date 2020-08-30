#include "server_util.h"

//Carica il file CRL
/*
int load_crl(string filename, X509_CRL * crl){
	FILE* file = fopen(filename.c_str(), "r");
	if(!file){
		return -1;
	}
	crl = PEM_read_X509_CRL(file, NULL, NULL, NULL);
	if(!crl){
		return -1;
	}
	fclose(file);
	return 0;
}
*/

// Alloca un nuovo buffer e vi inserisce i dati ricevuti.
// Deallocare sempre il buffer non appena i dati in esso contenuti non servono più
/*
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
	
	std::cout << "Dati in ingresso di dimensione: " << *buflen << " byte" << std::endl;
	
	// Alloco il buffer per i dati in ingresso
	char* temp_buffer = new char[*buflen];
	if(temp_buffer == NULL)
		return -1;
	printf("Checkpoint 1. temp_buffer address: %p, value: %p\n", &temp_buffer, temp_buffer);
	printf("Checkpoint 1. input_buffer locale address: %p, value: %p\n", input_buffer, *input_buffer);
	
	// Ricevo i dati in ingresso
	while(received < *buflen){
		std::cout << "received: " << received << ", *buflen: " << *buflen << ", ret: " << ret << std::endl;
		ret = recv(fd, temp_buffer + received, (*buflen) - received, 0);
		std::cout << "Ricevuti: " << ret << " byte" << std::endl;
		if(ret < 0){
			return -1;
		}
		if(ret == 0){
			return -1;
		}
		received += ret;
	}
	std::cout << "Uscito dal ciclo: " << std::endl;
	*input_buffer = temp_buffer;
	
	return 0;
}
*/
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

//pone l'utente in stato offline e chiude la connessione tcp
void quitClient(int socket, fd_set* master){
	
	close(socket);//TODO: vedere se conviene chiudere sul server o sul client
	FD_CLR(socket, master);

	return;	
}
