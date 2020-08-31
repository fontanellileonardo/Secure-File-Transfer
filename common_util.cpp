#include "common_util.h"

Session::Session(unsigned int fd){
	this->fd = fd;//TODO: da usare al posto di TCP_socket
	my_nonce = 9;//TODO: generarlo casualmente
	counterpart_nonce = 0;
}

uint32_t Session::get_counterpart_nonce(){
	return counterpart_nonce++;
}

unsigned int Session::get_fd(){
	return fd;
}

uint32_t Session::get_my_nonce(){
	return my_nonce++;
}

void Session::store_counterpart_nonce(uint32_t nonce){
	counterpart_nonce = nonce;
}

int create_store(X509_STORE **store, X509 *CA_cert, X509_CRL *crl){
	*store = X509_STORE_new();
	if(store == NULL){
		std::cerr << "Errore durante la creazione dello store" << std::endl;
		return -1;
	}

	if(X509_STORE_add_cert(*store, CA_cert) != 1){
		std::cerr << "Errore durante l'aggiunta del certificato allo store" << std::endl;
		return -1;
	}

	if(X509_STORE_add_crl(*store, crl) != 1){
		std::cerr << "Errore durante di CRL allo store" << std::endl;
		return -1;
	}

	if(X509_STORE_set_flags(*store, X509_V_FLAG_CRL_CHECK) != 1){
		std::cerr << "Errore durante l'impostazione dei flag allo store" << std::endl;
		return -1;
	}
	return 0;
}

//Carica il certificato come file .pem
int load_cert(std::string filename, X509 **cert){
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
