#include "client_util.h"

//identifica il comando ricevuto dall'utente da tastiera
int identifyCommand(char* command){

	if(strlen(command) != 6 && strncmp(command, "!list", 5)== 0){
		return COMMAND_LIST;
	}
	if(strlen(command) != 6 && strncmp(command, "!help", 5)== 0){
		return COMMAND_HELP;
	}
	if(strlen(command) != 6 && strncmp(command, "!quit", 5)== 0){
		return COMMAND_QUIT;
	}
	if(strlen(command) != 8 && strncmp(command, "!upload", 7) == 0){
		return COMMAND_UPLOAD;
	}
	if(strlen(command) != 10 && strncmp(command, "!download", 9) == 0)
		return COMMAND_DOWNLOAD;
	return COMMAND_INVALID;
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
	close(socket);
	return;
}
