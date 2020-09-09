#include <dirent.h>
#include <fstream>
#include <iostream>
#include <string.h>
#include <vector>

bool is_authorized(std::string authorized_clients, std::string client);
std::string list_files(std::string path);
