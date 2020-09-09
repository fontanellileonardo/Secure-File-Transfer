#include "server_util.h"

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
