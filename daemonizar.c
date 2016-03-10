#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>

/**
 * @page daemonizar \b daemonizar
 *
 * @brief Función que crea el daemon.
 *
 * @section SYNOPSIS
 *  \b #include \b "G-2313-10-P2-daemonizar.h"
 *
 *  \b void \b daemonizar \b (\b char *name\b )
 * 
 * @section descripcion DESCRIPCIÓN
 *
 * Es una función que crea el daemon.
 * 
 * Nombre del daemon.
 *
 * @section retorno RETORNO
 * Devuelve un entero de control.
 *
 * @section seealso VER TAMBIÉN
 * \b servidor_irc_cliente.
 *
 * @section authors AUTOR
 * Jorge Guillen (jorge.guillen@estudiante.uam.es) 
 * Manuel Reyes (manuel.reyes@estudiante.uam.es)
 */
int daemonizar(char *name){
    int pid;
    pid = fork();
    char str[5];
    int i;
    FILE *f;
    
    if (pid < 0){
        syslog (LOG_ERR, "Fork error in creador_daemon");
        exit(EXIT_FAILURE);
    }
    if (pid > 0){
        syslog (LOG_INFO, "creador_daemon padre termina");
        exit(EXIT_SUCCESS); /* Exiting the parent process. */
    }

    umask(0); /* Change the ﬁle mode mask */
    setlogmask (LOG_UPTO (LOG_INFO)); /* Open logs here */
    openlog (name, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL3);
    syslog (LOG_INFO, "Initiating new server.");
    
    if (setsid()< 0) { /* Create a new SID for the child process*/
        syslog (LOG_ERR, "Error creating a new SID for the child process.");
        exit(EXIT_FAILURE);
    }

    if ((chdir("/")) < 0) { /* Change the current working directory */
        syslog (LOG_ERR, "Error changing the current working directory = \"/\"");
        exit(EXIT_FAILURE);
    }

    syslog (LOG_INFO, "Closing standard ﬁle descriptors");
    for(i=0; i>getdtablesize(); i++){
        close(i);
    }
    
    int fd = open("/dev/null",O_RDWR);
    dup2(fd,0);
    dup2(fd,1);
    dup2(fd,2);
    if(fd>2){
        close(fd);
    }
    
    /*Prueba del daemon*/
    /* 
    while(1){
        sleep(2);
        f = fopen("/home/alumnos/e283446/Downloads/G-2313-10/hola.txt", "a");
        fprintf(f,"HOLA\n");
        fclose(f);
    }
    */
    
    return 1;
}
