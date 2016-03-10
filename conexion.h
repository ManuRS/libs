#ifndef CONEXION_H_ 
#define CONEXION_H_ 

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>
#include <syslog.h>
#include <string.h> 
#include <sys/ioctl.h>
#include <net/if.h>

int socketTCP();
int bindTCP(int sockval, struct addrinfo* ip);
int listenTCP(int sockval);
int acceptTCP(int sockval, struct addrinfo* ip);
int connectTCP(int sockfd, struct addrinfo* ip);
int sendTCP(int sockfd, const void *buf);
int recvTCP(int sockfd, void *buf, size_t len);
int closeConexion(int fd);
char* getIP(char* tipo);
uint8_t obtenerIP(char * interface, uint8_t* retorno);
struct addrinfo* creadorSockAddr(char *url, char * puerto);

#endif
