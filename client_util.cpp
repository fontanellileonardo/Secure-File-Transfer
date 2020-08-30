#include "client_util.h"

//identifica il comando ricevuto dall'utente da tastiera
int identifyCommand(char* command){

	if(strlen(command) != 6 && strncmp(command, "!help", 5)== 0){
		return COMMAND_HELP;
	}
	if(strlen(command) != 6 && strncmp(command, "!quit", 5)== 0){
		return COMMAND_QUIT;
	}
	if(strlen(command) != 10 && strncmp(command, "!download", 9) == 0)
		return COMMAND_DOWNLOAD;
	return COMMAND_INVALID;
}

//Carica il certificato come file .pem
int load_cert(std::string filename, X509** cert){
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

//funzione che stampa a video i comandi disponibili per l'utente
void print_available_commands(){
	//printf("%s",MESSAGE_USER_COMMAND);
    std::cout<<MESSAGE_USER_COMMAND;
	return;
}

//stampa sul terminale
void print_prompt(){
	std::cout << ">";
	// clean the output buffer
	fflush(stdout);
	return;
}

//chiede al server di sloggare l'utente mettendone lo stato in offline e termina.
void quitClient(int socket){
	
	uint32_t message_type, message_type_n;
	message_type = COMMAND_QUIT;
	message_type_n = htonl(message_type);
	send(socket, &message_type_n, sizeof(uint32_t), 0);
	
	return;
}

int send_data(unsigned int fd, const char* buffer, size_t buflen){
	size_t sent = 0;
	ssize_t ret;
	
	while(sent < buflen){
		ret = send(fd, buffer + sent, buflen - sent, 0);
		std::cout << "Inviati: " << ret << " byte" << std::endl;
		if(ret < 0){
			return -1;
		} 
		sent += ret;
	}
	return (sent == buflen)?0:(-1);
}
