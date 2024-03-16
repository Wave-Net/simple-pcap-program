#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

// 패킷 처리 콜백 함수
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // 패킷 길이 출력
    printf("Packet length: %d\n", pkthdr->len);
    
    // 패킷 헤더 길이 계산 (Ethernet 헤더 크기 14바이트를 기준으로 함)
    int header_length = 14; // 이더넷 헤더 크기
    if (pkthdr->len < header_length) {
        printf("Invalid packet - header length exceeds packet length\n");
        return;
    }

    // 이더넷 헤더 출력
    printf("Ethernet Header:\n");
    for (int i = 0; i < header_length; i++) {
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    printf("\n");

    // 프로토콜 식별
    uint16_t protocol = (packet[12] << 8) | packet[13];
    printf("Protocol: ");
    switch (protocol) {
        case 0x0800:
            printf("IPv4\n");
            break;
        case 0x86DD:
            printf("IPv6\n");
            break;
        default:
            printf("Unknown (0x%04x)\n", protocol);
    }

    // 패킷 페이로드 출력
    printf("Payload:\n");
    for (int i = header_length; i < pkthdr->len; i++) {
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE]; // 에러 버퍼
    pcap_if_t *alldevs; // 모든 네트워크 인터페이스 목록
    pcap_if_t *dev; // 현재 네트워크 인터페이스
    pcap_t *handle; // 패킷 핸들러

    // 모든 네트워크 인터페이스 가져오기
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return(2);
    }

    // 첫 번째 네트워크 인터페이스 선택
    dev = alldevs;

    // 패킷 핸들러 생성
    handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev->name, errbuf);
        pcap_freealldevs(alldevs);
        return(2);
    }

    // 패킷 캡쳐 시작
    printf("Capturing packets...\n");
    pcap_loop(handle, -1, packet_handler, NULL);

    // 메모리 해제
    pcap_freealldevs(alldevs);
    pcap_close(handle);
    
    return(0);
}
