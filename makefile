all:  client server


client: msg_client.cpp client_util.cpp
	g++ -Wall -o client msg_client.cpp client_util.cpp common_util.cpp -lcrypto

server: msg_server.cpp server_util.cpp
	g++ -Wall -o server msg_server.cpp server_util.cpp common_util.cpp -lcrypto
