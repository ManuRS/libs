#include "conexion_openssl.h"

/**
 * @page inicializar_nivel_SSL \b inicializar_nivel_SSL
 *
 * @brief Función que inicializa el ssl.
 *
 * @section SYNOPSIS
 * 	\b #include \b "/includes/G-2313-10-P3-conexion_openssl.h"
 *  \b lib/libG-2313-10-P3-conexion_openssl.a 
 *
 *	\b void \b inicializar_nivel_SSL \b (\b void\b )
 * 
 * @section descripcion DESCRIPCIÓN
 *
 * Esta función se encargará de realizar todas las llamadas necesarias para que la aplicación
pueda usar la capa segura SSL.
 * 
 * No tiene parámetros de entrada.
 *
 * @section retorno RETORNO
 * No tiene retorno.
 *
 * @section seealso VER TAMBIÉN
 * \b fijar_contexto_SSL.
 *
 * @section authors AUTOR
 * Manuel Reyes (manuel.reyes@estudiante.uam.es)
 * Jorge Guillen (jorge.guillen@estudiante.uam.es)
*/
void inicializar_nivel_SSL(){
    
    SSL_load_error_strings();

    SSL_library_init();

}

/**
 * @page fijar_contexto_SSL \b fijar_contexto_SSL
 *
 * @brief Función que inicializa el contexto.
 *
 * @section SYNOPSIS
 *  \b #include \b "/includes/G-2313-10-P3-conexion_openssl.h"
 *  \b lib/libG-2313-10-P3-conexion_openssl.a 
 *
 *  \b SSL_CTX* \b fijar_contexto_SSL \b (\b char *certificado, char *path\b )
 * 
 * @section descripcion DESCRIPCIÓN
 *
 * Esta función se encargará de inicializar correctamente el contexto que será utilizado para
la creación de canales seguros mediante SSL. Deberá recibir información sobre las rutas a los certificados y
claves con los que vaya a trabajar la aplicación.
 * 
 * Recibe como parámetros un la ruta al certificado y la ruta al la entidad certificadora.
 *
 * @section retorno RETORNO
 * Devuelve el contexto.
 *
 * @section seealso VER TAMBIÉN
 * \b conectar_canal_seguro_SSL.
 *
 * @section authors AUTOR
 * Manuel Reyes (manuel.reyes@estudiante.uam.es)
 * Jorge Guillen (jorge.guillen@estudiante.uam.es)
*/
SSL_CTX* fijar_contexto_SSL(char *certificado, char *path){
    SSL_CTX *ctx=NULL;

    if((ctx=SSL_CTX_new(SSLv23_method()))==NULL){
        ERR_print_errors_fp(stdout);
        return NULL;
    }

    if(SSL_CTX_load_verify_locations(ctx,path,NULL)==0){
        ERR_print_errors_fp(stdout);
        return NULL;
    }

    SSL_CTX_set_default_verify_paths(ctx);
    ERR_print_errors_fp(stdout);

    if( SSL_CTX_use_certificate_chain_file(ctx, certificado) !=1){
        ERR_print_errors_fp(stdout);
        return NULL;
    }

    if( SSL_CTX_use_PrivateKey_file(ctx, certificado, SSL_FILETYPE_PEM) !=1){
        ERR_print_errors_fp(stdout);
        return NULL;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    ERR_print_errors_fp(stdout);
    return ctx;

}

/**
 * @page conectar_canal_seguro_SSL \b conectar_canal_seguro_SSL
 *
 * @brief Función que conecta con un canal seguro.
 *
 * @section SYNOPSIS
 *  \b #include \b "/includes/G-2313-10-P3-conexion_openssl.h"
 *  \b lib/libG-2313-10-P3-conexion_openssl.a 
 *
 *  \b SSL* \b conectar_canal_seguro_SSL \b (\b SSL_CTX *ctx, int socket\b )
 * 
 * @section descripcion DESCRIPCIÓN
 *
 * Dado un contexto SSL y un descriptor de socket esta función se encargará de
obtener un canal seguro SSL inciando el proceso de handshake con el otro extremo.
 * 
 * Recibe como parámetros el contexto y el socket.
 *
 * @section retorno RETORNO
 * Devuelve el ssl.
 *
 * @section seealso VER TAMBIÉN
 * \b evaluar_post_connectar_SSL.
 *
 * @section authors AUTOR
 * Manuel Reyes (manuel.reyes@estudiante.uam.es)
 * Jorge Guillen (jorge.guillen@estudiante.uam.es)
*/
SSL * conectar_canal_seguro_SSL(SSL_CTX *ctx, int socket){
    SSL *ssl;

    if((ssl = SSL_new(ctx))==NULL){
        ERR_print_errors_fp(stdout);
        return NULL;
    }

    if(SSL_set_fd(ssl, socket)==0){
        ERR_print_errors_fp(stdout);
        return NULL;
    }

    if (SSL_connect(ssl)<1){
        ERR_print_errors_fp(stdout);
        return NULL;
    }

    return ssl;
}

/**
 * @page aceptar_canal_seguro_SSL \b aceptar_canal_seguro_SSL
 *
 * @brief Función que acepta con un canal seguro.
 *
 * @section SYNOPSIS
 *  \b #include \b "/includes/G-2313-10-P3-conexion_openssl.h"
 *  \b lib/libG-2313-10-P3-conexion_openssl.a 
 *
 *  \b SSL* \b aceptar_canal_seguro_SSL \b (\b SSL_CTX *ctx, int socket\b )
 * 
 * @section descripcion DESCRIPCIÓN
 *
 * Dado un contexto SSL y un descriptor de socket esta función se encargará de
bloquear la aplicación, que se quedará esperando hasta recibir un handshake por parte del cliente.
 * 
 * Recibe como parámetros el contexto y el socket.
 *
 * @section retorno RETORNO
 * Devuelve el ssl.
 *
 * @section seealso VER TAMBIÉN
 * \b evaluar_post_connectar_SSL.
 *
 * @section authors AUTOR
 * Manuel Reyes (manuel.reyes@estudiante.uam.es)
 * Jorge Guillen (jorge.guillen@estudiante.uam.es)
*/
SSL * aceptar_canal_seguro_SSL(SSL_CTX *ctx, int socket){
    SSL *ssl;

    if((ssl = SSL_new(ctx))==NULL){
        ERR_print_errors_fp(stdout);
        return NULL;
    }

    if(SSL_set_fd(ssl, socket)==0){
        ERR_print_errors_fp(stdout);
        return NULL;
    }

    if (SSL_accept(ssl)<1){
        ERR_print_errors_fp(stdout);
        return NULL;
    }

    return ssl;
}

/**
 * @page evaluar_post_connectar_SSL \b evaluar_post_connectar_SSL
 *
 * @brief Función que evalua con un canal seguro.
 *
 * @section SYNOPSIS
 *  \b #include \b "/includes/G-2313-10-P3-conexion_openssl.h"
 *  \b lib/libG-2313-10-P3-conexion_openssl.a 
 *
 *  \b int \b evaluar_post_connectar_SSL \b (\b SSL *ssl\b )
 * 
 * @section descripcion DESCRIPCIÓN
 *
 * Esta función comprobará una vez realizado el handshake que el canal de comunicación
se puede considerar seguro.
 * 
 * Recibe como parámetros el ssl.
 *
 * @section retorno RETORNO
 * Devuelve codigo de error.
 *
 * @section seealso VER TAMBIÉN
 * \b enviar_datos_SSL, recibir_datos_SSL\b.
 *
 * @section authors AUTOR
 * Manuel Reyes (manuel.reyes@estudiante.uam.es)
 * Jorge Guillen (jorge.guillen@estudiante.uam.es)
*/
int evaluar_post_connectar_SSL(SSL * ssl){
    if(SSL_get_peer_certificate(ssl)==NULL){
        ERR_print_errors_fp(stdout);
        return -1;
    }

    if(SSL_get_verify_result(ssl)!=X509_V_OK){
        ERR_print_errors_fp(stdout);
        return -1;
    }

    return 1;
}

/**
 * @page enviar_datos_SSL \b enviar_datos_SSL
 *
 * @brief Función que envia a un canal seguro.
 *
 * @section SYNOPSIS
 *  \b #include \b "/includes/G-2313-10-P3-conexion_openssl.h"
 *  \b lib/libG-2313-10-P3-conexion_openssl.a 
 *
 *  \b int \b enviar_datos_SSL \b (\b SSL *ssl, void *msg, int size\b )
 * 
 * @section descripcion DESCRIPCIÓN
 *
 * Esta función enviará datos a través del canal seguro.
 * 
 * Recibe como parámetros el ssl, la cadena a eviar y su tamaño.
 *
 * @section retorno RETORNO
 * Devuelve codigo de error.
 *
 * @section seealso VER TAMBIÉN
 * \b recibir_datos_SSL, cerrar_canal_SSL\b.
 *
 * @section authors AUTOR
 * Manuel Reyes (manuel.reyes@estudiante.uam.es)
 * Jorge Guillen (jorge.guillen@estudiante.uam.es)
*/
int enviar_datos_SSL(SSL *ssl, void *msg, int size){
    int res;

    if((res=SSL_write(ssl, msg, size))<=0){
            ERR_print_errors_fp(stdout);
            perror("Error enviar");
            return -1;
    }
    return res;
}

/**
 * @page recibir_datos_SSL \b recibir_datos_SSL
 *
 * @brief Función que recibe de un canal seguro.
 *
 * @section SYNOPSIS
 *  \b #include \b "/includes/G-2313-10-P3-conexion_openssl.h"
 *  \b lib/libG-2313-10-P3-conexion_openssl.a 
 *
 *  \b int \b recibir_datos_SSL \b (\b SSL *ssl, void *msg, int size\b )
 * 
 * @section descripcion DESCRIPCIÓN
 *
 * Esta función recibirá datos a través del canal seguro.
 * 
 * Recibe como parámetros el ssl, la cadena donde recibir y su tamaño.
 *
 * @section retorno RETORNO
 * Devuelve codigo de error.
 *
 * @section seealso VER TAMBIÉN
 * \b enviar_datos_SSL, cerrar_canal_SSL\b.
 *
 * @section authors AUTOR
 * Manuel Reyes (manuel.reyes@estudiante.uam.es)
 * Jorge Guillen (jorge.guillen@estudiante.uam.es)
*/
int recibir_datos_SSL(SSL *ssl, void *msg, int size){
    int res;

    if((res=SSL_read(ssl, msg, size))<=0){
            ERR_print_errors_fp(stdout);
            perror("Error recibir");
            return -1;
    }
    return res;
}

/**/
/**
 * @page cerrar_canal_SSL \b cerrar_canal_SSL
 *
 * @brief Función que cierra un canal seguro.
 *
 * @section SYNOPSIS
 *  \b #include \b "/includes/G-2313-10-P3-conexion_openssl.h"
 *  \b lib/libG-2313-10-P3-conexion_openssl.a 
 *
 *  \b int \b cerrar_canal_SSL \b (\b SSL *ssl, SSL_CTX *ctx, int socket\b )
 * 
 * @section descripcion DESCRIPCIÓN
 *
 * Esta función liberará todos los recursos y cerrará el canal de comunicación seguro creado
previamente.
 * 
 * Recibe como parámetros el ssl, el contexto y el socket.
 *
 * @section retorno RETORNO
 * Devuelve codigo de error.
 *
 * @section seealso VER TAMBIÉN
 * \b inicializar_nivel_SSL.
 *
 * @section authors AUTOR
 * Manuel Reyes (manuel.reyes@estudiante.uam.es)
 * Jorge Guillen (jorge.guillen@estudiante.uam.es)
*/
int cerrar_canal_SSL(SSL *ssl, SSL_CTX *ctx, int socket){
   int res;

   if((res=SSL_shutdown(ssl))==0){
        if(SSL_shutdown(ssl)!=1){
            ERR_print_errors_fp(stdout);
            return -1;
        }
    }else if(res!=1){
        ERR_print_errors_fp(stdout);
        return -1;
    }

    SSL_free(ssl);
    ERR_print_errors_fp(stdout);

    SSL_CTX_free(ctx);
    ERR_print_errors_fp(stdout);

    if(closeConexion(socket)<0){
        return -1;
    }

    return 1;
}
