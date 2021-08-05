# encrypted-chatting

## what are required:
1. openssl:     1.1.1g
2. mysql:       8.0.21

## how to configure:
1. modify ./include/protocol.h

how to compile:
1. place mysql/*.h under /usr/include/mysql
2. place openssl/*.h under /usr/include/openssl
3. place libcrypto.so under (somedir)
4. place libmysqlclient.so under (somedir)
5. modify FLAGopenssl & FLAGmysql in ./Makefile
6. `make`
