#pragma once

#include <arpa/inet.h>
#include <cstdio>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pcap.h>
#include <unistd.h>
#include "arphdr.h"
#include "ethhdr.h"

typedef struct {
	Ip MyIp;
	Mac MyMac;
}IpMac;

char * MyMacAddress(char* InInterface);
char * MyIpAddress(char* InInterface);
bool CheckIp(char* InTestIp);
bool SendArpRequest(pcap_t* pcap, IpMac InSender, IpMac InAttacker);
//bool get_sender_mac(const u_char* packet, char* sender_ip, char* sender_mac);
void ReceiveArpReply(pcap_t* pcap, IpMac* InSender);
void AttackArp(pcap_t* pcap, IpMac InSender, Ip InTarget,IpMac InAttacker);
void MyArpSpoof(char* InInterface, char* InSenderIp, char* InTargetIp, IpMac InAttacker);
