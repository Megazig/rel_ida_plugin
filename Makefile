SRC=rel.cpp
OBJS=rel.o
CC=g++
LD=g++
#CC=clang++ -v -Wall
#LD=clang++
CFLAGS=-D__IDP__ -D__PLUGIN__ -c -D__LINUX__ \
	   -I/usr/local/idaadv/sdk/include -std=c++11 $(SRC)
LDFLAGS=--shared $(OBJS) -L/usr/local/idaadv -lida \
		-Wl,--version-script=./plugin.script
all:
	$(CC) $(CFLAGS)
	$(LD) $(LDFLAGS) -o rel.plx

install:
	sudo cp rel.plx /usr/local/idaadv/plugins

clean:
	rm -f rel.plx rel.o

