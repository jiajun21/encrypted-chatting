#ifndef _SECURE_H_
#define _SECURE_H_

#include <stdlib.h>

/* due to block alignment, return value of following two functions
   secure_send & secure_recv can be larger than "len" */
int secure_send(int channel, const void * buf, size_t len, int flags,
                const unsigned char * key, const unsigned char * iv);
int secure_recv(int channel, void * buf, size_t len, int flags,
                const unsigned char * key, const unsigned char * iv);

int secure_init_server(void);
int secure_build_key_server(int channel, unsigned char * key, unsigned char * iv);
void secure_finish_server(void);

int secure_init_client(void);
int secure_build_key_client(int channel, unsigned char * key, unsigned char * iv);
void secure_finish_client(void);

#endif
