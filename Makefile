#Makefile
all: my-arp-spoof

my-arp-spoof: myarpspoof.o main.o arphdr.o ethhdr.o ip.o mac.o
	g++ -o arp-spoof myarpspoof.o main.o arphdr.o ethhdr.o ip.o mac.o -lpcap

main.o: myarpspoof.h main.cpp

myarpspoof.o: myarpspoof.h myarpspoof.cpp arphdr.h ethhdr.h

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

clean:
	rm -f arp-spoof
	rm -f *.o

