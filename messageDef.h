#define COMMAND_HELP 1
#define COMMAND_UPLOAD 2
#define COMMAND_DOWNLOAD 3
#define COMMAND_FILELIST 4
#define COMMAND_QUIT 5
#define COMMAND_INVALID 6


#define MESSAGE_STORED_END 15
#define MESSAGE_INCOMING 17

#define MESSAGE_FULL 25
#define MESSAGE_NOT_FULL 26

#define MAX_USER_CONNECTED 128
// numero massimo di utenti connessi contemporaneamente sul server

#define MAX_COMMAND_INPUT 80
//numero di caratteri inseribili dall'utente quando vuole dare un comando

#define MAX_CHAR_INPUT 1024
//numero massimo di caratteri inseribili per messaggio in una linea senza andare a capo

#define MESSAGE_USER_COMMAND "\nSono disponibili i seguenti comandi:\n !help\n !upload filename\n !download\n !quit\n\n"

#define MESSAGE_USER_COMMAND_DETAILED "\n!help ->visualizza i comandi disponibili\n !upload filename -> upload file chiamato filename sul server\n !download filename -> download filename dal server\n !files -> visualizza i file disponibili e la loro dimensione\n !quit -> disconnette l'utente dal server ed esce\n\n"
