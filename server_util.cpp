#include "server_util.h"

bool is_authorized(std::string authorized_clients, std::string client){
	bool ret = false;
	std::string temp;
	std::ifstream infile;
	infile.open(authorized_clients);
	if(!infile){
		std::cerr << "Errore nel caricamento della lista dei client autorizzati" << std::endl;
		return false;
	}
	while(!infile.eof()){
		getline(infile, temp);
		if(temp.compare(client) == 0){
			ret = true;
			break;
		}
	}
	infile.close();
	return ret;
}

std::string list_files(std::string path){
	DIR* folder = opendir(path.c_str());
	struct dirent* dp;
	std::string temp;
	std::string ret = std::string("File disponibili sul server:\n");
	while((dp = readdir(folder)) != NULL){
		char *filename = dp->d_name;
		if(filename[0] == '.')
			continue;
		temp = std::string(filename);
		ret += "\t"+temp;
	}
	closedir(folder);
	return ret;
}

int recv_command(uint8_t &message_type, Session* client){
	size_t command_len = 4 + 16 + 32;// numero sequenziale + comando cifrato + hash(numero sequenziale, comando cifrato)
	unsigned char command[command_len];
	
	if(recv(client->get_fd(), &command, command_len, MSG_WAITALL) < 0)
		return -1;
	
	// Se i byte sono tutti zero, allora è una richiesta di stabilire la connessione sicura
	unsigned char handshake_command[command_len];
	memset(handshake_command, 0, command_len);
	if(memcmp(command, handshake_command, command_len) == 0){
		message_type = HANDSHAKE;
		//  Debug
		std::cout << "HANDSHAKE" << std::endl;
		// /Debug
		return 1;
	}
	
	// Controllo se il numero sequenziale è corretto
	uint32_t client_nonce = client->get_counterpart_nonce();
	if(client_nonce != ntohl(*((uint32_t*)command))){
		return -1;
	}
	
	// Controllo l'hash
	int ret = hash_verify(command, 4 + 16, command + 4 + 16);
	if(ret < 1)
		return ret;
	
	// Decripto il comando
	unsigned char key_encr_buffer[EVP_CIPHER_key_length(EVP_aes_128_cbc())];
	client->get_key_encr((char*)key_encr_buffer);
	unsigned char iv_buffer[EVP_CIPHER_iv_length(EVP_aes_128_cbc())];
	client->get_iv((char*)iv_buffer, EVP_CIPHER_iv_length(EVP_aes_128_cbc()));
	
	unsigned char* plaintext;
	size_t plaintextlen;
	if(decrypt_symm((unsigned char*)(command + 4), 16, &plaintext, &plaintextlen, EVP_aes_128_cbc(), key_encr_buffer, iv_buffer) < 0)
		return -1;
	
	message_type = *((uint8_t*)plaintext);
	return 1;
}
