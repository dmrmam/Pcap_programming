#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

// 이더넷 헤더 구조체
struct ethheader {
    u_char ether_dhost[6]; // destination MAC 주소
    u_char ether_shost[6]; // source MAC 주소
    u_short ether_type;    // protocol type
};

// IP 헤더 구조체
struct ipheader {
    u_char iph_ihl:4, iph_ver:4; // header length, version
    u_char iph_tos;              // servive type
    u_short iph_len;             // length
    u_short iph_ident;           // 식별자
    u_short iph_flags_offset;    // flag, offset
    u_char iph_ttl;              // TTL
    u_char iph_protocol;         // 상위 프로토콜
    u_short iph_checksum;        // checksum
    struct in_addr iph_sourceip; // source IP 주소
    struct in_addr iph_destip;   // destination IP 주소
};

// TCP 헤더 구조체
struct tcpheader {
    u_short th_sport;  // source 포트
    u_short th_dport;  // destination 포트
    u_int th_seq;      // sequnse number
    u_int th_ack;      // ack
    u_char th_off:4,   // data offset
           th_x2:4;    // 예약된 필드
    u_char th_flags;   // flag bit
    u_short th_win;    // 윈도우 크기
    u_short th_sum;    // checksum
    u_short th_urp;    // 긴급 포인터
};

// 패킷처리 콜백함수
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) { 
		struct ethheader *eth = (struct ethheader *)packet; // 이더넷 헤더 분리
		
		// ipv4 패킷인지 확인
    if (ntohs(eth->ether_type) != 0x0800) return;
     
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader)); // ip 헤더 분리
        struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + (ip->iph_ihl * 4)); // tcp 헤더 분리

        printf("\n==== Captured TCP Packet ====\n");
        printf("From: %s:%d\n", inet_ntoa(ip->iph_sourceip), ntohs(tcp->th_sport));
        printf("To  : %s:%d\n", inet_ntoa(ip->iph_destip), ntohs(tcp->th_dport));
        
        int payload_offset = sizeof(struct ethheader) + (ip->iph_ihl * 4) + (tcp->th_off * 4); // tcp 페이로드가 시작하는 위치 확인
        int payload_size = header->caplen - payload_offset; // 전체 길이 - 페이로드 오프셋
        const u_char *payload = packet + payload_offset; //페이로드 1바이트씩 저장

        if (payload_size > 0) {
            printf("Payload (%d bytes):\n", payload_size);
            for (int i = 0; i < payload_size; i++) { //페이로드 사이즈만큼 반복
                printf("%c", (payload[i] >= 32 && payload[i] <= 126) ? payload[i] : '.'); // 아스키코드 32~127사이의 값들만 출력하고 나머지는 "."으로 출력
            }
            printf("\n");
        } else {
            printf("No Payload Data\n");
        }
    
}

// 패킷 캡처 시작
int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;

    // 네트워크 인터페이스에서 패킷 캡처 시작
    handle = pcap_open_live("en0", BUFSIZ, 1, 1000, errbuf);

    // 필터 컴파일 및 적용
    pcap_compile(handle, &filter, "tcp port 80", 0, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(handle, &filter);

    printf("Starting packet capture...\n");

    // 패킷 캡처 시작
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}