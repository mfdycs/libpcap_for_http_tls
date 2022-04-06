#include <bits/stdc++.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pcap.h>
using namespace std;

#define PCAP_BUF_SIZE 1024
#define PCAP_SRC_FILE 2
#define FILE_NAME "1.pcap"

int tcpCount = 0;
set<string> tcpIP, httpIP;
int httpCount[PCAP_BUF_SIZE];
int httpIdx = 0;

struct massage {
    int id;
    string sourceIP;
    string destIP;
    u_char* data;
    int datalength;
    bool operator<(const massage &other) const {
        return id < other.id;
    }
};

vector<massage> tcp_massage, http_massage, udp_massage, dns_massage, icmp_massage, tls_massage;
int all_count = 0;

#define SSL_MIN_GOOD_VERSION	0x002
#define SSL_MAX_GOOD_VERSION	0x304

#define TLS_HANDSHAKE 22
#define TLS_CLIENT_HELLO 1
#define TLS_SERVER_HELLO 2

#define OFFSET_HELLO_VERSION	9
#define OFFSET_SESSION_LENGTH	43
#define OFFSET_CIPHER_LIST	44

vector<string> t;

char* ssl_version(u_short version);

bool judge_background(string a);

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int main(int argc, char **argv)
{
    freopen("output.txt", "w", stdout);

    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char source[PCAP_BUF_SIZE];
    int maxCountSyn = 0, maxCountHttp = 0, maxIdxSyn = 0, maxIdxHttp = 0;

    fp = pcap_open_offline(FILE_NAME, errbuf);

    if (fp == NULL) {
        fprintf(stderr, "\npcap_open_offline() failed: %s\n", errbuf);
        return 0;
    }

    // 背景流量
    t.push_back("");

    if (pcap_loop(fp, 0, packetHandler, NULL) < 0) {
        fprintf(stderr, "\npcap_loop() failed: %s\n", errbuf);
        return 0;
    }

    return 0;
}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    const struct ether_header* ethernetHeader;
    const struct ip* ipHeader;
    const struct tcphdr* tcpHeader;
    const struct udphdr* udpHeader;
    
    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    u_int sourcePort, destPort;
    u_char *payload;
    int size_payload = 0;
    massage tmp;
    int tmp_http_local = -1;
    ++all_count;

    ethernetHeader = (struct ether_header*)packet;
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);

        if (!judge_background(sourceIP))
            return;
        if (!judge_background(destIP))
            return;

        tmp.id = all_count;
        tmp.sourceIP = sourceIP, tmp.destIP = destIP;

        // TCP协议
        if (ipHeader->ip_p == IPPROTO_TCP) {
            tcpCount++;
            tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            
            sourcePort = ntohs(tcpHeader->source);
            destPort = ntohs(tcpHeader->dest);

            payload = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
            size_payload = ntohs(ipHeader->ip_len) - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));

            tmp.data = payload, tmp.datalength = size_payload;
            tcp_massage.push_back(tmp);

            // HTTP流量
            if (sourcePort == 80 ||  destPort == 80) {
                http_massage.push_back(tmp);
                httpIP.insert(sourceIP);
                httpIP.insert(destIP);
                string tmp_http_payload(reinterpret_cast<char const*>(payload));

                // 判断是否是HTTP报文
                tmp_http_local = tmp_http_payload.find("HTTP/");
                if (tmp_http_local == string::npos) 
                    return;
                
                printf("\n----------------------------------------------\nNo. %d\n", all_count);
                printf("Source: %s:%d\n", sourceIP, sourcePort);
                printf("Destination: %s:%d\n", destIP, destPort);
        
                // User-Agent信息
                tmp_http_local = tmp_http_payload.find("User-Agent");
                if (tmp_http_local != string::npos) {
                    for (int i = tmp_http_local; tmp_http_payload[i] != '\n'; ++i)
                        cout << tmp_http_payload[i];
                    cout << endl;
                }

                // Host信息
                tmp_http_local = tmp_http_payload.find("Host");
                if (tmp_http_local != string::npos) {
                    for (int i = tmp_http_local; tmp_http_payload[i] != '\n'; ++i)
                        cout << tmp_http_payload[i];
                    cout << endl;
                }

                // Content-Type信息
                tmp_http_local = tmp_http_payload.find("Content-Type");
                if (tmp_http_local != string::npos) {
                    for (int i = tmp_http_local; tmp_http_payload[i] != '\n'; ++i)
                        cout << tmp_http_payload[i];
                    cout << endl;
                }
            }

            if (sourcePort == 443 || destPort == 443) {
                tls_massage.push_back(tmp);
                if (size_payload < OFFSET_CIPHER_LIST + 3) 
                    return;
                
                if (payload[0] != TLS_HANDSHAKE)
                    return;

                printf("\n----------------------------------------------\nNo. %d\n", all_count);
                u_short proto_version = payload[1] * 256 + payload[2];
                printf("Source: %s:%d\n", sourceIP, sourcePort);
                printf("Destination: %s:%d\n", destIP, destPort);
                printf("%s ", ssl_version(proto_version));
                u_short hello_version = payload[OFFSET_HELLO_VERSION] * 256 + payload[OFFSET_HELLO_VERSION + 1];

                if (proto_version < SSL_MIN_GOOD_VERSION || proto_version >= SSL_MAX_GOOD_VERSION ||
                    hello_version < SSL_MIN_GOOD_VERSION || hello_version >= SSL_MAX_GOOD_VERSION) {
                    printf("%s bad version(s)\n", ssl_version(hello_version));
                    return;
                }

                const u_char *cipher_data = &payload[OFFSET_SESSION_LENGTH];

                if (size_payload < OFFSET_SESSION_LENGTH + cipher_data[0] + 3) {
                    printf("SessionID too long: %hhu bytes\n", cipher_data[0]);
                    return;
                }

                cipher_data += 1 + cipher_data[0];

                if (payload[5] == TLS_CLIENT_HELLO) {
                    printf("ClientHello %s ", ssl_version(hello_version));
                    u_short cs_len = cipher_data[0] * 256 + cipher_data[1];
                    cipher_data += 2; 
                    int cs_id;
                    for (cs_id = 0; cs_id < cs_len / 2; cs_id++)
                        printf(":%02hhX%02hhX", cipher_data[2 * cs_id], cipher_data[2 * cs_id + 1]);
                    printf(":\n");
                } 
                else if (payload[5] == TLS_SERVER_HELLO) {
                    printf("ServerHello %s ", ssl_version(hello_version));
                    printf("cipher %02hhX%02hhX\n", cipher_data[0], cipher_data[1]);
                } 
                else {
                    printf("Not a Hello\n");
                }
            }
        }
    }
}

bool judge_background(string a) 
{
    for (int i = 0; i < t.size(); ++i) {
        if (a == t[i])
            return false;
    }

    return true;
}

char* ssl_version(u_short version) 
{
	static char hex[7];
	switch (version) {
		case 0x002: return "SSLv2";
		case 0x300: return "SSLv3";
		case 0x301: return "TLSv1";
		case 0x302: return "TLSv1.1";
		case 0x303: return "TLSv1.2";
	}
	snprintf(hex, sizeof(hex), "0x%04hx", version);
	return hex;
}