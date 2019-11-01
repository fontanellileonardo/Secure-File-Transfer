#include "client_util.h"

//funzione che stampa a video i comandi disponibili per l'utente
void command_available(){
	//printf("%s",MESSAGE_USER_COMMAND);
    cout<<MESSAGE_USER_COMMAND;
	return;
}

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

//chiede al server di sloggare l'utente mettendone lo stato in offline e termina.
void quitClient(int socket){
	
	int message_type;
	uint32_t umessage_type;
	message_type = COMMAND_QUIT;
	// htonl() converte unsigned integer da host byte order a net byte order
	umessage_type = htonl(message_type);
	send(socket, &umessage_type, sizeof(uint32_t), 0);
	
	return;
}

//stampa sul terminale
void print_prompt(){

	//printf(">");
	cout << ">";
	// clean the output buffer
	fflush(stdout);
	return;
}