#include <dirent.h>
#include <fstream>
#include <iostream>
#include <string.h>
#include <vector>

#include "common_util.h"
#include "utils.h"

bool is_authorized(std::string authorized_clients, std::string client);
std::string list_files(std::string path);
int recv_command(uint8_t &command, Session* session);
