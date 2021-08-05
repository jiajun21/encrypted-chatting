FLAG = -Wall -I./include/
FLAGmysql = -L/usr/lib64/mysql -lmysqlclient
FLAGopenssl = -L/usr/lib64/ -lcrypto

.PHONY: all
all: server client

server: server.o log.o secure.o database.o
	gcc -o server $(FLAG) $(FLAGmysql) $(FLAGopenssl) -pthread \
		server.o log.o secure.o database.o
client: client.o secure.o
	gcc -o client $(FLAG) $(FLAGopenssl) -pthread \
		client.o secure.o

server.o: ./src/server.c ./include/log.h ./include/secure.h \
		./include/database.h ./include/protocol.h
	gcc -c $(FLAG) ./src/server.c
client.o: ./src/client.c ./include/secure.h ./include/protocol.h
	gcc -c $(FLAG) ./src/client.c
log.o: ./src/log.c ./include/log.h ./include/protocol.h
	gcc -c $(FLAG) ./src/log.c
secure.o: ./src/secure.c ./include/secure.h ./include/protocol.h
	gcc -c $(FLAG) ./src/secure.c
database.o: ./src/database.c ./include/database.h ./include/protocol.h
	gcc -c $(FLAG) ./src/database.c

clean:
	rm server.o client.o log.o secure.o database.o
