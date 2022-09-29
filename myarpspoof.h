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
#pragma once

typedef struct {
	char my_ip[16];
	char my_mac[18];
}ip_mac;

bool My_Mac_Address(char* Mac_store, char* interface);
void My_Ip_Address(char* Ip_store, char* interface);
bool get_sender_mac(const u_char* packet, char* sender_ip, char* sender_mac);
bool check_ip(char* test_ip);
bool Send_ARP_Request(pcap_t *pcap, ip_mac* mine, char* sender_ip);
bool Receive_ARP_Reply(pcap_t* pcap, char* sender_ip, char* sender_mac);
void Attack_ARP(pcap_t* pcap, char* sender_ip, char* target_ip, char* sender_mac, ip_mac* mine);
void my_arp_spoof(char* my_interface, char* sender_ip, char* target_ip, ip_mac* mine);
