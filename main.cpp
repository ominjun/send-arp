#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include "mysendarp.h"
#include <sys/wait.h>

void how_to_usage() {
	printf("syntax: pcap-test <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...\n");
	printf("sample: pcap-test wlan0 192.168.0.1 192.168.0.2\n");
}

bool parse(int argc, char* argv[]) {
	if (argc <= 3 || (argc %2)) {
		how_to_usage();
		return false;
	}
	return true;
}

int main(int argc, char* argv[]) {
	
	uint32_t num_seq;
	pid_t pid;
	IpMac Mine;
	char* TempCharString;

	if (!parse(argc, argv)) // 인자 제대로 줬는지 확인
		return -1;

	TempCharString = MyMacAddress(argv[1]);
	if (!TempCharString)// interface에 해당하는 mac address 확인
	{
		fprintf(stderr,"Interface does not match the format\n");
		return -1;
	}
	GetMyMac(&(Mine.MyMac), TempCharString);

	TempCharString = MyIpAddress(argv[1]);// ip 확인
	GetMyIp(&(Mine.MyIp), TempCharString);
	
	for(num_seq=1;num_seq*2<argc;num_seq++)
	{
		pid=fork();
		if(pid == 0) //각 프로세스는 고유의 num_seq를 가지고 argv의 num_seq*2와 num_seq*2+1만 신경쓰면 됨
			break;
		if(pid == -1) //fork 실패 시 다시 시도
			num_seq--;
	}

	if(pid>0) // 자식 프로세스가 좀비프로세스가 안 되게 감시, 모두 종료 후 죽기
	{
		while(wait(NULL)>0);
		printf("arp spoofing 종료\n");
		return 0;
	}
	MySendArp(argv[1],argv[2*num_seq],argv[2*num_seq+1],Mine);
	
	return 0;
}
