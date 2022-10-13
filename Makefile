#Makefile
all: send-arp

send-arp: mysendarp.o main.o arphdr.o ethhdr.o ip.o mac.o
	g++ -o send-arp mysendarp.o main.o arphdr.o ethhdr.o ip.o mac.o -lpcap

main.o: mysendarp.h main.cpp

mysendarp.o: mysendarp.h mysendarp.cpp arphdr.h ethhdr.h

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

clean:
	rm -f send-arp
	rm -f *.o

