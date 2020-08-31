#include "common_util.h"

Session::Session(int fd){
	this->fd = fd;//TODO: da usare al posto di TCP_socket
	my_nonce = 9;//TODO: generarlo casualmente
	counterpart_nonce = 0;
}

uint32_t Session::get_counterpart_nonce(){
	return counterpart_nonce++;
}

uint32_t Session::get_my_nonce(){
	return my_nonce++;
}

void Session::store_counterpart_nonce(uint32_t nonce){
	counterpart_nonce = nonce;
}
