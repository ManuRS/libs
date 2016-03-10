#ifndef CONEXION_OPENSSL_H_ 
#define CONEXION_OPENSSL_H_ 

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <string.h> 

#include "conexion.h"

void inicializar_nivel_SSL();
SSL_CTX* fijar_contexto_SSL(char *certificado, char *path);
SSL * conectar_canal_seguro_SSL(SSL_CTX *ctx, int socket);
SSL * aceptar_canal_seguro_SSL(SSL_CTX *ctx, int socket);
int evaluar_post_connectar_SSL(SSL * ssl);
int enviar_datos_SSL(SSL *ssl, void *msg, int size);
int recibir_datos_SSL(SSL *ssl, void *msg, int size);
int cerrar_canal_SSL(SSL *ssl, SSL_CTX *ctx, int socket);

#endif
