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
