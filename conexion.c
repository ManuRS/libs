#include "conexion.h"

int debug=0;

/**
 * @page socketTCP \b socketTCP
 *
 * @brief Llamada para crear un socket.
 *
 * @section SYNOPSIS
 * 	\b #include \b "/includes/G-2313-10-P1-conexion.h"
 *  \b lib/libG-2313-10-P1-conexion.a 
 *
 *	\b int \b socketTCP \b (\b void\b )
 * 
 * @section descripcion DESCRIPCIÓN
 *
 * Es la función llamada cada vez que se quiere abrir un nuevo socket.
 * 
 * No tiene parámetros de entrada.
 *
 * @section retorno RETORNO
 * Devuelve un int que corresponde al socket.
 *
 * @section seealso VER TAMBIÉN
 * \b bindTCP(3).
 *
 * @section authors AUTOR
 * Manuel Reyes (manuel.reyes@estudiante.uam.es)
 * Jorge Guillen (jorge.guillen@estudiante.uam.es)
*/
int socketTCP(){
    int sockval;
    
    if((sockval = socket(AF_INET, SOCK_STREAM, 0)) < 0 ){
        syslog(LOG_ERR, "Error creating socket");
        switch(errno){
            case EACCES:
                syslog(LOG_ERR, "Permission to create a socket of the specified type and/or protocol is denied.");
                return -1;
            case EAFNOSUPPORT:
                syslog(LOG_ERR, "The implementation does not support the specified address family.");
                return -1;
            case EINVAL:
                syslog(LOG_ERR, "Unknown protocol, or protocol family not available. || Invalid flags in type.");
                return -1;
            case EMFILE:
                syslog(LOG_ERR, "Process file table overflow. || The system limit on the total number of open files has been reached.");
                return -1;
            case ENOBUFS:
                syslog(LOG_ERR, "Insufficient memory is available.  The socket cannot be created until sufficient resources are freed.");
                return -1;
            case ENOMEM:
                syslog(LOG_ERR, "Insufficient memory is available.  The socket cannot be created until sufficient resources are freed.");
                return -1;
            case EPROTONOSUPPORT:
                syslog(LOG_ERR, "The protocol type or the specified protocol is not supported within this domain.");
                return -1;
        }
        return -1;
    }

    return sockval;
}

/**
 * @page bindTCP \b bindTCP
 *
 * @brief Llamada para prepararse una conexion.
 *
 * @section SYNOPSIS
 * 	\b #include \b "/includes/G-2313-10-P1-conexion.h"
 *  \b lib/libG-2313-10-P1-conexion.a 
 *
 *	\b int \b bindTCP \b (\b int sockval, struct addrinfo* ip\b )
 * 
 * @section descripcion DESCRIPCIÓN
 *
 * Es la función llamada cada vez que se quiere preparar una conexion.
 * 
 * Sus parametros de entrada son un int que corresponde al socket y una estructura addrinfo a rellenar.
 *
 * @section retorno RETORNO
 * Devuelve un int que corresponde al codigo de error.
 *
 * @section seealso VER TAMBIÉN
 * \b listenTCP(3).
 *
 * @section authors AUTOR
 * Manuel Reyes (manuel.reyes@estudiante.uam.es)
 * Jorge Guillen (jorge.guillen@estudiante.uam.es)
*/
int bindTCP(int sockval, struct addrinfo* ip){
    
    if(bind (sockval,  ip->ai_addr, ip->ai_addrlen)<0){
        syslog(LOG_ERR, "Error binding socket");
        switch(errno){
            case EACCES:
                syslog(LOG_ERR, "The address is protected, and the user is not the superuser.");
                return -1;
            case EADDRINUSE:
                syslog(LOG_ERR, "The given address is already in use.");
                return -1;
            case EBADF:
                syslog(LOG_ERR, "sockfd is not a valid descriptor.");
                return -1;
            case EINVAL:
                syslog(LOG_ERR, "The socket is already bound to an address..");
                return -1;
            case ENOTSOCK:
                syslog(LOG_ERR, "sockfd is a descriptor for a file, not a socket.");
                return -1;
        }
        return -1;
    }
    return 1;
}

/**
 * @page listenTCP \b listenTCP
 *
 * @brief Llamada para escuchar en un socket.
 *
 * @section SYNOPSIS
 * 	\b #include \b "/includes/G-2313-10-P1-conexion.h"
 *  \b lib/libG-2313-10-P1-conexion.a 
 *
 *	\b int \b listenTCP \b (\b int sockval\b )
 * 
 * @section descripcion DESCRIPCIÓN
 *
 * Es la función llamada cada vez que se quiere escuchar conexiones en un socket.
 * 
 * Su parametro de entrada es un int que corresponde al socket.
 *
 * @section retorno RETORNO
 * Devuelve un int que corresponde al codigo de error.
 *
 * @section seealso VER TAMBIÉN
 * \b acceptTCP(3).
 *
 * @section authors AUTOR
 * Manuel Reyes (manuel.reyes@estudiante.uam.es)
 * Jorge Guillen (jorge.guillen@estudiante.uam.es)
*/
int listenTCP(int sockval){
    
    if(listen (sockval, 4)<0){
        syslog(LOG_ERR, "Error listenining");
        switch(errno){
            case EADDRINUSE:
                syslog(LOG_ERR, "Another socket is already listening on the same port.");
                return -1;
            case EBADF:
                syslog(LOG_ERR, "The argument sockfd is not a valid descriptor.");
                return -1;
            case ENOTSOCK:
                syslog(LOG_ERR, "The argument sockfd is not a socket.");
                return -1;
            case EOPNOTSUPP:
                syslog(LOG_ERR, "The socket is not of a type that supports the listen() operation.");
                return -1;
        }
        return -1;
    }
    return 1;
}

/**
 * @page acceptTCP \b acceptTCP
 *
 * @brief Llamada para acceptar una conexion.
 *
 * @section SYNOPSIS
 * 	\b #include \b "/includes/G-2313-10-P1-conexion.h"
 *  \b lib/libG-2313-10-P1-conexion.a 
 *
 *	\b int \b acceptTCP \b (\b int sockval, struct addrinfo* ip\b )
 * 
 * @section descripcion DESCRIPCIÓN
 *
 * Es la función llamada cada vez que se quiere acceptar una conexion.
 * 
 * Sus parametros de entrada son un int que corresponde al socket y una estructura addrinfo con los datos a usar.
 *
 * @section retorno RETORNO
 * Devuelve un int que corresponde al codigo de error.
 *
 * @section seealso VER TAMBIÉN
 * \b recvTCP(3).
 *
 * @section authors AUTOR
 * Manuel Reyes (manuel.reyes@estudiante.uam.es)
 * Jorge Guillen (jorge.guillen@estudiante.uam.es)
*/
int acceptTCP(int sockval, struct addrinfo* ip){
    int desc;
    
    if((desc = accept(sockval, ip->ai_addr, &ip->ai_addrlen))<0){
        syslog(LOG_ERR, "Error accepting");
        switch(errno){
            case EAGAIN:
                syslog(LOG_ERR, "The socket is marked nonblocking and no connections are present to be accepted.  POSIX.1-2001 allows either error to be returned for this case, and does not require these constants to have the same value, so a portable application should check for both pos‐sibilities.");
                return -1;
            case EBADF:
                syslog(LOG_ERR, "The descriptor is invalid.");
                return -1;
            case ECONNABORTED:
                syslog(LOG_ERR, "A connection has been aborted.");
                return -1;
            case EFAULT:
                syslog(LOG_ERR, "The addr argument is not in a writable part of the user address space.");
                return -1;
            case EINTR:
                syslog(LOG_ERR, "The system call was interrupted by a signal that was caught before a valid connection arrived; see signal(7).");
                return -1;
            case EINVAL:
                syslog(LOG_ERR, "Socket is not listening for connections, or addrlen is invalid (e.g., is negative). || (accept4()) invalid value in flags.");
                return -1;
            case EMFILE:
                syslog(LOG_ERR, "The per-process limit of open file descriptors has been reached. || The system limit on the total number of open files has been reached.");
                return -1;
            case ENOBUFS:
                syslog(LOG_ERR, "Not enough free memory.  This often means that the memory allocation is limited by the socket buffer limits, not by  the  system memory.");
                return -1;
            case ENOMEM:
                syslog(LOG_ERR, "Not enough free memory.  This often means that the memory allocation is limited by the socket buffer limits, not by  the  system memory.");
                return -1;
            case ENOTSOCK:
                syslog(LOG_ERR, "The descriptor references a file, not a socket.");
                return -1;
            case EOPNOTSUPP:
                syslog(LOG_ERR, "The descriptor references a file, not a socket.");
                return -1;
            case EPROTO:
                syslog(LOG_ERR, "EPROTO");
                return -1;
            case EPERM:
                syslog(LOG_ERR, "Firewall rules forbid connection.");
                return -1;
        }
        return -1;
    }
    return desc;
}

/**
 * @page connectTCP \b connectTCP
 *
 * @brief Llamada para crear una conexion.
 *
 * @section SYNOPSIS
 * 	\b #include \b "/includes/G-2313-10-P1-conexion.h"
 *  \b lib/libG-2313-10-P1-conexion.a 
 *
 *	\b int \b connectTCP \b (\b int sockval, struct addrinfo* ip\b )
 * 
 * @section descripcion DESCRIPCIÓN
 *
 * Es la función llamada cada vez que se quiere crear una conexion.
 * 
 * Sus parametros de entrada son un int que corresponde al socket y una estructura addrinfo con los datos a usar.
 *
 * @section retorno RETORNO
 * Devuelve un int que corresponde al codigo de error.
 *
 * @section seealso VER TAMBIÉN
 * \b sendTCP(3).
 *
 * @section authors AUTOR
 * Manuel Reyes (manuel.reyes@estudiante.uam.es)
 * Jorge Guillen (jorge.guillen@estudiante.uam.es)
*/
int connectTCP(int sockfd, struct addrinfo* ip){

    int ret;
    
    if ((ret = connect(sockfd, ip->ai_addr, ip->ai_addrlen)) < 0){
    syslog(LOG_ERR, "Error accepting");
        switch(errno){
            case EACCES:
                syslog(LOG_ERR, "Write permission is denied on the socket file, or search permission is denied for one of the directories in the path prefix.");
                return -1;
            case EPERM:
                syslog(LOG_ERR, "The user tried to connect to a broadcast address without  having the  socket  broadcast  flag  enabled  or the connection request failed because of a local firewall rule.");
                return -1;
             case EADDRINUSE:
                syslog(LOG_ERR, "Local address is already in use.");
                return -1;
             case EAFNOSUPPORT:
                syslog(LOG_ERR, "The passed address didn't have the correct address family in its sa_family field.");
                return -1;
             case EAGAIN:
                syslog(LOG_ERR, "No  more free local ports or insufficient entries in the routing cache.");
                return -1;
             case EALREADY:
                syslog(LOG_ERR, "The socket is nonblocking and a previous connection attempt  has not yet been completed.");
                return -1;
             case EBADF:
                syslog(LOG_ERR, "The  file  descriptor is not a valid index in the descriptor table.");
                return -1;
             case ECONNREFUSED:
                syslog(LOG_ERR, "No-one listening on the remote address.");
                return -1;
             case EFAULT:
                syslog(LOG_ERR, "The socket structure  address  is  outside  the  user's  address space.");
                return -1;
             case EINPROGRESS:
                syslog(LOG_ERR, "The socket is nonblocking and the connection cannot be completed immediately.");
                return -1;
             case EINTR:
                syslog(LOG_ERR, "The system call was interrupted by a signal that was caught; see signal(7).");
                return -1;
             case EISCONN:
                syslog(LOG_ERR, "The socket is already connected.");
                return -1;
             case ENETUNREACH:
                syslog(LOG_ERR, "Network is unreachable.");
                return -1;
             case ENOTSOCK:
                syslog(LOG_ERR, "The file descriptor is not associated with a socket.");
                return -1;
             case ETIMEDOUT:
                syslog(LOG_ERR, "Timeout while attempting connection.  The server may be too busy to accept new connections.  Note that for IP sockets the timeout may be very long when syncookies are enabled on the server.");
                return -1;  
        
        }
        return -1;
    }
    return ret;
}

/**
 * @page sendTCP \b sendTCP
 *
 * @brief Llamada para enviar.
 *
 * @section SYNOPSIS
 * 	\b #include \b "/includes/G-2313-10-P1-conexion.h"
 *  \b lib/libG-2313-10-P1-conexion.a 
 *
 *	\b int \b sendTCP \b (\b int sockval, const void *buf\b )
 * 
 * @section descripcion DESCRIPCIÓN
 *
 * Es la función llamada cada vez que se quiere enviar.
 * 
 * Sus parametros de entrada son un int que corresponde al socket y un void puntero con el mensaje a transmitir.
 *
 * @section retorno RETORNO
 * Devuelve un int que corresponde al codigo de error.
 *
 * @section seealso VER TAMBIÉN
 * \b closeConexion(3).
 *
 * @section authors AUTOR
 * Manuel Reyes (manuel.reyes@estudiante.uam.es)
 * Jorge Guillen (jorge.guillen@estudiante.uam.es)
*/
int sendTCP(int sockfd, const void *buf){
    int ret;

    if(debug==1)printf("##ENVIO  -->\n%s\n", (char *)buf);
    if((ret = send(sockfd, buf, strlen(buf), 0)) <0 ){
        syslog(LOG_ERR, "Error sending");
        switch(errno){
            case EACCES:
                syslog(LOG_ERR, "For  UNIX domain sockets, which are identified by pathname) Write permission is denied on the destination socket file, or search permission is denied for one of the directories the path prefix. See path_resolution(7).");
                return -1;
            case EAGAIN:
                syslog(LOG_ERR, "The socket is marked nonblocking and the requested operation would block.  POSIX.1-2001 allows either error to be returned for this case, and  does  not  require these constants to have the same value, so a portable application should check for both possibilities.");
                return -1;
            case EBADF:
                syslog(LOG_ERR, "An invalid descriptor was specified.");
                return -1;
            case ECONNRESET:
                syslog(LOG_ERR, "Connection reset by peer.");
                return -1;
            case EDESTADDRREQ:
                syslog(LOG_ERR, " The socket is not connection-mode, and no peer address is set.");
                return -1;
            case EFAULT:
                syslog(LOG_ERR, "An invalid user space address was specified for an argument.");
                return -1;
            case EINTR:
                syslog(LOG_ERR, "A signal occurred before any data was transmitted; see signal(7).");
                return -1;
            case EINVAL:
                syslog(LOG_ERR, "Invalid argument passed.");
                return -1;
            case EISCONN:
                syslog(LOG_ERR, "The connection-mode socket was connected already but a recipient was specified.  (Now either this error is returned, or the recipient specification is ignored.)");
                return -1;
            case EMSGSIZE:
                syslog(LOG_ERR, "The socket type requires that message be sent atomically, and the size of the message to be sent made this impossible.");
                return -1;
            case ENOBUFS:
                syslog(LOG_ERR, "The  output  queue for a network interface was full.  This generally indicates that the interface has stopped sending, but may be caused by transient congestion. (Normally, this does not occur in Linux.  Packets are just silently dropped when a device queue overflows.)");
                return -1;
            case ENOMEM:
                syslog(LOG_ERR, "No memory available.");
                return -1;
            case ENOTCONN:
                syslog(LOG_ERR, "The socket is not connected, and no target has been given.");
                return -1;
            case ENOTSOCK:
                syslog(LOG_ERR, "The argument sockfd is not a socket.");
                return -1;
            case EOPNOTSUPP:
                syslog(LOG_ERR, "Some bit in the flags argument is inappropriate for the socket type.");
                return -1;
            case EPIPE:
                syslog(LOG_ERR, "The local end has been shut down on a connection oriented socket.  In this case the process will also receive a SIGPIPE unless MSG_NOSIGNAL is set.");
                return -1;
        
        }
        return -1;
    }
    return ret;    
}

/**
 * @page recvTCP \b recvTCP
 *
 * @brief Llamada para recivir.
 *
 * @section SYNOPSIS
 * 	\b #include \b "/includes/G-2313-10-P1-conexion.h"
 *  \b lib/libG-2313-10-P1-conexion.a 
 *
 *	\b int \b recvTCP \b (\b int sockval, void *buf, size_t len\b )
 * 
 * @section descripcion DESCRIPCIÓN
 *
 * Es la función llamada cada vez que se quiere recivir.
 * 
 * Sus parametros de entrada son un int que corresponde al socket y un void puntero con el mensaje a recivir y su tamaño.
 *
 * @section retorno RETORNO
 * Devuelve un int que corresponde al codigo de error.
 *
 * @section seealso VER TAMBIÉN
 * \b closeConexion(3).
 *
 * @section authors AUTOR
 * Manuel Reyes (manuel.reyes@estudiante.uam.es)
 * Jorge Guillen (jorge.guillen@estudiante.uam.es)
*/
int recvTCP(int sockfd, void *buf, size_t len){

    int ret;
    bzero(buf,len);
    if ((ret = recv(sockfd, buf, len, 0)) <= 0 ){
        syslog(LOG_ERR, "Error reciving");
        switch(errno){
            case EAGAIN:
                syslog(LOG_ERR, " The  socket  is  marked  nonblocking  and  the receive operation would block, or a receive timeout had been set and the timeout expired before data was received.");
                return -1;
            case EBADF:
                syslog(LOG_ERR, "The argument sockfd is an invalid descriptor.");
                return -1;
            case ECONNREFUSED:
                syslog(LOG_ERR, "A remote host refused to allow the network connection (typically because it is not running the requested service).");
                return -1;             
            case EFAULT:
                syslog(LOG_ERR, "The receive buffer pointer(s) point outside the process's address space.");
                return -1;
            case EINTR:
                syslog(LOG_ERR, "The receive was interrupted by delivery of a signal before any data were available; see signal(7).");
                return -1;
            case EINVAL:
                syslog(LOG_ERR, "Invalid argument passed.");
                return -1;
            case ENOMEM:
                syslog(LOG_ERR, "Could not allocate memory for recvmsg().");
                return -1;
            case ENOTCONN:
                syslog(LOG_ERR, "The socket is associated with a connection-oriented protocol and has not been connected (see connect(2) and accept(2)).");
                return -1;
            case ENOTSOCK:
                syslog(LOG_ERR, "The argument sockfd does not refer to a socket.");
                return -1;                     
        }
        return -1;
    }
    if(debug==1)printf("$$RECIBO -->\n%s\n", (char*)buf);
    return ret;
}

/**
 * @page closeConexion \b closeConexion
 *
 * @brief Llamada para cerrar un socket.
 *
 * @section SYNOPSIS
 * 	\b #include \b "/includes/G-2313-10-P1-conexion.h"
 *  \b lib/libG-2313-10-P1-conexion.a 
 *
 *	\b int \b closeConexion \b (\b int fd\b )
 * 
 * @section descripcion DESCRIPCIÓN
 *
 * Es la función llamada cada vez que se quiere cerrar un socket.
 * 
 * Su parametro de entrada es un int que corresponde al socket a cerrar.
 *
 * @section retorno RETORNO
 * Devuelve un int que corresponde al codigo de error.
 *
 * @section seealso VER TAMBIÉN
 * \b socketTCP(3).
 *
 * @section authors AUTOR
 * Manuel Reyes (manuel.reyes@estudiante.uam.es)
 * Jorge Guillen (jorge.guillen@estudiante.uam.es)
*/
int closeConexion(int fd){

    int ret;
    if ((ret = close(fd)) < 0){
        syslog(LOG_ERR, "Error closing");
        switch(errno){
            case EBADF:
                syslog(LOG_ERR, "fd isn't a valid open file descriptor.");
                return -1;
            case EINTR:
                syslog(LOG_ERR, "The close() call was interrupted by a signal; see signal(7).");
                return -1;  
            case EIO:
                syslog(LOG_ERR, "An I/O error occurred.");
                return -1;         
        }
        return -1;    
    }
    return ret;
}

/**
 * @page obtenerIP \b obtenerIP
 *
 * @brief Llamada para obtener una ip.
 *
 * @section SYNOPSIS
 * 	\b #include \b "/includes/G-2313-10-P1-conexion.h"
 *  \b lib/libG-2313-10-P1-conexion.a 
 *
 *	\b uint8_t \b obtenerIP \b (\b char * interface, uint8_t* retorno\b )
 * 
 * @section descripcion DESCRIPCIÓN
 *
 * Es la función llamada cada vez que se quiere obtener una ip.
 * 
 * Sus parametros de entrada son un char puntero que corresponde la interfaz a usar y un uint8_t puntero que devolvera la ip.
 *
 * @section retorno RETORNO
 * Devuelve un uint8_t que corresponde al codigo de error.
 *
 * @section seealso VER TAMBIÉN
 * \b getIP(3).
 *
 * @section authors AUTOR
 * Manuel Reyes (manuel.reyes@estudiante.uam.es)
 * Jorge Guillen (jorge.guillen@estudiante.uam.es)
*/
uint8_t obtenerIP(char * interface, uint8_t* retorno){
	int fd;
	struct ifreq ifr;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd<0) {
		if(debug==1)printf("socket_ERROR\n");
		return -1;
	}
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
	if (ioctl(fd, SIOCGIFADDR, &ifr)<0){
		if(debug==1)printf("IOCTL_ERROR 4\n");
		return -1;
	}
	close(fd);
	memcpy(retorno,&(*(struct sockaddr_in *)&ifr.ifr_addr).sin_addr,sizeof(uint8_t)*4);
	return 0;
}

/**
 * @page getIP \b getIP
 *
 * @brief Llamada para obtener una ip.
 *
 * @section SYNOPSIS
 * 	\b #include \b "/includes/G-2313-10-P1-conexion.h"
 *  \b lib/libG-2313-10-P1-conexion.a 
 *
 *	\b char* \b getIP \b (\b char * tipo\b )
 * 
 * @section descripcion DESCRIPCIÓN
 *
 * Es la función llamada cada vez que se quiere obtener una ip.
 * 
 * Su parametro de entrada es un char puntero que corresponde la interfaz a usar.
 *
 * @section retorno RETORNO
 * Devuelve un char puntero que corresponde a la ip.
 *
 * @section seealso VER TAMBIÉN
 * \b obtenerIP(3).
 *
 * @section authors AUTOR
 * Manuel Reyes (manuel.reyes@estudiante.uam.es)
 * Jorge Guillen (jorge.guillen@estudiante.uam.es)
*/
char* getIP(char * tipo){
    
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, tipo, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);

    return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

/**
 * @page creadorSockAddr \b creadorSockAddr
 *
 * @brief Llamada para crear un socket para una address.
 *
 * @section SYNOPSIS
 * 	\b #include \b "/includes/G-2313-10-P1-conexion.h"
 *  \b lib/libG-2313-10-P1-conexion.a 
 *
 *	\b struct addrinfo* \b creadorSockAddr \b (\b char *url, char * puerto\b )
 * 
 * @section descripcion DESCRIPCIÓN
 *
 * Es la función llamada cada vez que se quiere crear un socket para una address.
 * 
 * Sus parametros de entrada son un char puntero que corresponde la url y un char* con el puerto a usar.
 *
 * @section retorno RETORNO
 * Devuelve un struct addrinfo puntero que corresponde a la addr a usar en connectTCP.
 *
 * @section seealso VER TAMBIÉN
 * \b connectTCP(3).
 *
 * @section authors AUTOR
 * Manuel Reyes (manuel.reyes@estudiante.uam.es)
 * Jorge Guillen (jorge.guillen@estudiante.uam.es)
*/
struct addrinfo* creadorSockAddr(char *url, char * puerto){
    struct addrinfo hints, *res=NULL;
    int s;

    /*Preparacion de la estructura*/
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
    hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
    hints.ai_protocol = 0;          /* Any protocol */
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;
    
    if(debug==1)printf("Soy un alguien TCP - encima de getaddrinfo\n");
    
    s = getaddrinfo(url, puerto, &hints, &res);
    if (s != 0) {
        syslog(LOG_ERR, "Error getaddrinfo");
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        return NULL;
    }   
    return res;
}