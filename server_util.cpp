#include "server_util.h"

//pone l'utente in stato offline e chiude la connessione tcp
void quitClient(int socket, fd_set* master){
	
	close(socket);
	FD_CLR(socket, master);

	return;	
}

