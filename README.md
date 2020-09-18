# Foundations of CyberSecurity Project
This repository contains the files and the documentation for the didactical project for the Foundation of CyberSecurity course.

## Assignment
Develop a client-server application in which:
* The server stores in local a set of files, each of which can have size up
to 4 GB.
* The client can request for a list of the files available on the server.
* The client can download one of the available files. This operation
must be memory-efficient both for client and server.
* The client can upload a file, possibly overwriting an existing one on the server. This operation must be memory-efficient both for client and server.

Implement the application and satisfy the following requirements:
* All the communications must be ​*confidential*, *authenticated*, and *replay-protected*​.
* The code must follow the secure coding best practices.
* The code must be implemented in C language and using the OpenSSL
library.
* In the final implementation client and server DO NOT HAVE a
pre-shared symmetric key.

## Documentation
The documentation of the project is available [here](docs/Documentation.pdf). You will find the explanation of the implementation choiches and the handshake and communication protocols. 
The documentation is available in Italian. For English details, you can contact me personally.

## Run the code
In order to run the code, you must positionate the terminal in the folder of the project and type:
```sh
make
```
in order to compile the executable for both server and client.
For executing the code, for the server the command is the following:
```sh
./server <port>
```
and for the client (in a separate command line):
```sh
./client <localhost> <server_port>
```

## Credits
E. Petrangeli, A. De Roberto, L. Fontanelli