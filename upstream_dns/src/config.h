#ifndef CONFIG_H
#define CONFIG_H

#include "types.h"

#include <ctype.h>

int load_config(int argc, char** argv);
int create_server_socket(int port);

int load_hints(const char* filename);
void free_hints();

#endif /* CONFIG_H */ 
