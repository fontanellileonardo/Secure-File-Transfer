#include "client_util.h"

//identifica il comando ricevuto dall'utente da tastiera
uint8_t identifyCommand(char* command){

	if(strlen(command) != 6 && strncmp(command, "!list", 5)== 0){
		return COMMAND_FILELIST;
	}
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

//stampa sul terminale
void print_prompt(){
	std::cout << ">";
	// clean the output buffer
	fflush(stdout);
	return;
}

int send_command(uint8_t command, Session &session){
	unsigned char key_encr_buffer[EVP_CIPHER_key_length(EVP_aes_128_cbc())];
	session.get_key_encr((char*)key_encr_buffer);
	unsigned char iv_buffer[EVP_CIPHER_iv_length(EVP_aes_128_cbc())];
	session.get_iv((char*)iv_buffer, EVP_CIPHER_iv_length(EVP_aes_128_cbc()));
	
	uint32_t seqnum = session.get_my_nonce();
	if(seqnum == UINT32_MAX)
		return 0;
	seqnum = htonl(seqnum);
	
	unsigned char* ciphertext_buffer;
	size_t ciphertext_buffer_len;
	encrypt_symm((unsigned char*)&command, sizeof(command), &ciphertext_buffer, &ciphertext_buffer_len, EVP_aes_128_cbc(), key_encr_buffer, iv_buffer);
	
	size_t temp_len = sizeof(seqnum) + ciphertext_buffer_len;
	unsigned char temp[temp_len];
	memcpy(temp, &seqnum, sizeof(seqnum));
	memcpy(temp + sizeof(seqnum), ciphertext_buffer, ciphertext_buffer_len);
	
	unsigned char* digets_buffer;
	size_t digets_buffer_len;
	hash_bytes(temp, temp_len, &digets_buffer, &digets_buffer_len, &session);
	
	size_t output_buffer_len = sizeof(seqnum) + ciphertext_buffer_len + digets_buffer_len;
	unsigned char output_buffer[output_buffer_len];
	memcpy(output_buffer, &seqnum, sizeof(seqnum));
	memcpy(output_buffer + sizeof(seqnum), ciphertext_buffer, ciphertext_buffer_len);
	memcpy(output_buffer + sizeof(seqnum) + ciphertext_buffer_len, digets_buffer, digets_buffer_len);
	
	delete[] ciphertext_buffer;
	delete[] digets_buffer;
	
	send(session.get_fd(), output_buffer, output_buffer_len, 0);
	return 1;
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
