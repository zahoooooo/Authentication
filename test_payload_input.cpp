#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <poll.h>
#include <thread>
#include <atomic>
#include "libauth.h"

#define SIGNAL_UDP_PORT 19999
#define AUTH_NEXT_HEADER 200

// 全局：是否处于攻击模式 / 高负载模式
std::atomic<bool> g_attack_mode{false};
std::atomic<bool> g_high_load_mode{false};
// 全局：是否启用自动监听
std::atomic<bool> g_auto_listen{false};

// 辅助函数：通过 UDP 通道回传重认证信号
void send_udp_signal(const char* dst_ip_str, const char* payload, int len) {
    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) { perror("UDP socket creation failed"); return; }
    struct sockaddr_in6 dest;
    std::memset(&dest, 0, sizeof(dest));
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(SIGNAL_UDP_PORT);
    inet_pton(AF_INET6, dst_ip_str, &dest.sin6_addr);
    ssize_t sent = sendto(sock, payload, len, 0, (struct sockaddr*)&dest, sizeof(dest));
    if (sent < 0) { perror("UDP sendto failed"); }
    else { std::cout << "[Server] UDP signal sent: " << payload << " -> " << dst_ip_str << ":" << SIGNAL_UDP_PORT << std::endl; }
    close(sock);
}

// 辅助函数：通过 IPv6 raw socket 回传重认证信号
void send_ipv6_reply(const char* dst_ip_str, const char* src_ip_str, const char* payload, int len) {
    int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) { perror("Socket creation failed (Needs sudo)"); return; }
    int hdrincl = 1;
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_HDRINCL, &hdrincl, sizeof(hdrincl)) < 0) {
        perror("setsockopt IPV6_HDRINCL failed"); close(sock); return;
    }
    uint8_t packet[256] = {0};
    uint32_t v_tc_fl = htonl(0x60000000);
    uint16_t p_len = htons(len);
    std::memcpy(packet, &v_tc_fl, 4);
    std::memcpy(packet + 4, &p_len, 2);
    packet[6] = AUTH_NEXT_HEADER;
    packet[7] = 64;
    inet_pton(AF_INET6, dst_ip_str, packet + 8);
    inet_pton(AF_INET6, src_ip_str, packet + 24);
    std::memcpy(packet + 40, payload, len);
    struct sockaddr_in6 dest;
    std::memset(&dest, 0, sizeof(dest));
    dest.sin6_family = AF_INET6;
    inet_pton(AF_INET6, dst_ip_str, &dest.sin6_addr);
    if (sendto(sock, packet, 40 + len, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        perror("IPv6 sendto failed");
    } else {
        std::cout << "[Server] IPv6 signal sent back: " << payload << " -> " << dst_ip_str << std::endl;
    }
    close(sock);
    // 同时通过 UDP 发一份
    send_udp_signal(dst_ip_str, payload, len);
}

// 处理一个接收到的 IPv6+AuthPacket 或裸 AuthPacket，并回传信号（如果需要）
void process_auth_packet(const uint8_t* packet_data, unsigned int packet_len, const char* src_ip, const char* dst_ip) {
    if (g_attack_mode.load()) {
        auth_set_attack_mode(1, nullptr);
        g_attack_mode = false;
    }
    if (g_high_load_mode.load()) {
        auth_set_high_load_mode(1, nullptr);
        g_high_load_mode = false;
    }
    struct re_auth re_info;
    struct auth_report_msg report;
    struct auth_audit_info audit;
    struct auth_decode_msg decode;
    std::memset(&re_info, 0, sizeof(re_info));
    std::memset(&report, 0, sizeof(report));
    std::memset(&audit, 0, sizeof(audit));
    std::memset(&decode, 0, sizeof(decode));

    int result = auth_policy_match_ipv6_packet((char*)packet_data, packet_len, &re_info, &report, &audit, &decode);
    if (result == 3) {
        const char* reply_dst = (src_ip && src_ip[0] != 0) ? src_ip : "::1";
        const char* reply_src = (dst_ip && dst_ip[0] != 0) ? dst_ip : "::1";
        send_ipv6_reply(reply_dst, reply_src, re_info.auth_data, re_info.auth_len);
    }
    std::cout << "\n--- [decode_msg content (external return)] ---" << std::endl;
    std::cout << decode.decode_msg << std::endl;

    std::cout << "\n--- [Parallel decrypt/verify Trace] ---" << std::endl;
    std::cout << auth_get_last_crypto_trace_json() << std::endl;
    std::cout << "\n--- [Audit Verification Result] ---" << std::endl;
    std::cout << "Result: " << result << std::endl;
    std::cout << "Report Message: " << report.report_msg << std::endl;
    std::cout << "\n--- [Audit Compare View] ---" << std::endl;
    for (int i = 0; i < 3; i++) {
        std::cout << "Layer " << (i+1) << " (Alg " << audit.layers[i].alg_id << "): Status=" << audit.layers[i].status
                  << " EffectiveTagBits=" << audit.layers[i].tag_len_bits
                  << " EffectiveTagBytes=" << audit.layers[i].tag_len_bytes << std::endl;
        if (audit.layers[i].recv_tag_hex[0] != '\0') {
            std::cout << " Recv Tag: " << audit.layers[i].recv_tag_hex;
            std::cout << "\n Calc Tag: " << audit.layers[i].calc_tag_hex;
        } else {
            std::cout << " Recv Tag: "; for(int j=0;j<AUTH_MAX_TAG_BYTES;j++) std::printf("%02x", audit.layers[i].recv_tag[j]);
            std::cout << "\n Calc Tag: "; for(int j=0;j<AUTH_MAX_TAG_BYTES;j++) std::printf("%02x", audit.layers[i].calc_tag[j]);
        }
        std::cout << std::endl;
    }
}

// 自动监听线程：从网络接收认证包
void auto_listen_thread() {
    std::cout << "[AutoListen] started, listening on IPv6 Next Header=" << AUTH_NEXT_HEADER << "..." << std::endl;
    int sock = socket(AF_INET6, SOCK_RAW, AUTH_NEXT_HEADER);
    if (sock < 0) { perror("[AutoListen] socket failed"); return; }
    struct sockaddr_in6 bind_addr;
    std::memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin6_family = AF_INET6;
    bind_addr.sin6_addr = in6addr_loopback;  // 绑定 ::1
    if (bind(sock, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) {
        perror("[AutoListen] bind failed"); close(sock); return;
    }
    // 设置超时，便于定期检查exit条件
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    while (g_auto_listen.load()) {
        uint8_t buf[2048];
        struct sockaddr_in6 from;
        socklen_t fromlen = sizeof(from);
        ssize_t n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&from, &fromlen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            perror("[AutoListen] recvfrom error"); break;
        }
        // SOCK_RAW(200) 在不同环境下可能返回：
        // 1) 只有认证 payload，也就是 AuthPacket(AUTH_PACKET_BYTES)；
        // 2) 完整 IPv6 包，也就是 IPv6头(40B)+AuthPacket。
        // 具体格式交给 auth_policy_match_ipv6_packet 统一解析，并输出 decode_msg。
        char src_ip[INET6_ADDRSTRLEN] = {0};
        char dst_ip[INET6_ADDRSTRLEN] = {0};
        if (n >= 40 && ((buf[0] >> 4) == 6)) {
            inet_ntop(AF_INET6, buf + 8, src_ip, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, buf + 24, dst_ip, INET6_ADDRSTRLEN);
            std::cout << "\n[AutoListen] received IPv6 packet len=" << n << " src=" << src_ip << std::endl;
        } else if (n >= AUTH_PACKET_BYTES) {
            inet_ntop(AF_INET6, &from.sin6_addr, src_ip, INET6_ADDRSTRLEN);
            std::cout << "\n[AutoListen] received AuthPayload len=" << n
                      << " src=" << (src_ip[0] ? src_ip : "unknown") << std::endl;
        } else {
            continue;
        }
        process_auth_packet(buf, static_cast<unsigned int>(n), src_ip, dst_ip);
    }
    close(sock);
    std::cout << "[AutoListen] stopped" << std::endl;
}

// 辅助函数：将十六进制字符串转换为字节数组
std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    std::string clean_hex;
    for (char c : hex) { if (std::isxdigit(c)) clean_hex += c; }
    for (size_t i = 0; i < clean_hex.length(); i += 2) {
        std::string byteString = clean_hex.substr(i, 2);
        bytes.push_back((uint8_t) strtol(byteString.c_str(), nullptr, 16));
    }
    return bytes;
}

// 辅助函数：解析 IPv6 头部信息
void parse_ipv6_header(const uint8_t* data, char* out_src, char* out_dst) {
    uint16_t payload_len = ntohs(*(uint16_t*)(data + 4));
    uint8_t next_header = data[6];
    inet_ntop(AF_INET6, data + 8, out_src, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, data + 24, out_dst, INET6_ADDRSTRLEN);
    std::cout << "\n[IPv6 Header Parse Result]" << std::endl;
    std::cout << "Source: " << out_src << std::endl;
    std::cout << "Dest: " << out_dst << std::endl;
    std::cout << "Payload length: " << payload_len << " | Next Header: " << (int)next_header << std::endl;
}

int main() {
    auth_init();
    std::cout << "========= Deep Protocol Audit Test Tool =========" << std::endl;
    std::cout << "========= Signal channels: IPv6 raw + UDP:" << SIGNAL_UDP_PORT << " =========" << std::endl;

    // 1. 设置锁定时间
    std::string ts_input;
    std::cout << "Enter fixed timestamp (press Enter to skip): ";
    std::getline(std::cin, ts_input);
    if (!ts_input.empty()) auth_set_timestamp(std::stoull(ts_input));

    // 2. 设置允许算法池
    std::string pool_input;
    std::cout << "Enter server allowed algorithm pool (default 11,12,13,21,22,23,31,32,33): ";
    std::getline(std::cin, pool_input);
    if (!pool_input.empty()) auth_set_allowed_algs(pool_input.c_str());

    // 3. 询问是否启用自动监听
    std::string auto_input;
    std::cout << "Enable auto-listen mode? (y/n, default y): ";
    std::getline(std::cin, auto_input);
    if (auto_input != "n" && auto_input != "N") {
        g_auto_listen = true;
        std::thread t(auto_listen_thread);
        t.detach();
    }

    while (true) {
        std::cout << "\nEnter command or hex data:" << std::endl;
        std::cout << "  attack   - enable attack mode (require client switch to 13,23,33)" << std::endl;
        std::cout << "  load     - enable high-load mode (require client switch to 11,21,31)" << std::endl;
        std::cout << "  normal   - restore normal mode (require client switch to 12,22,32)" << std::endl;
        std::cout << "  stop     - disable attack/high-load mandatory mode" << std::endl;
        std::cout << "  hex_data - paste hex auth packet manually" << std::endl;
        std::cout << "  exit     - exit" << std::endl;
        std::string hex_input;
        if (!std::getline(std::cin, hex_input) || hex_input.empty()) continue;

        if (hex_input == "exit") { break; }

        if (hex_input == "attack") {
            g_attack_mode = true;
            g_high_load_mode = false;
            auth_set_attack_mode(1, nullptr);
            std::cout << "[Admin] Attack mode enabled. The next received packet will trigger switch to 13,23,33." << std::endl;
            continue;
        }

        if (hex_input == "load") {
            g_high_load_mode = true;
            g_attack_mode = false;
            auth_set_high_load_mode(1, nullptr);
            std::cout << "[Admin] High-load mode enabled. The next received packet will trigger switch to 11,21,31." << std::endl;
            continue;
        }

        if (hex_input == "normal") {
            g_attack_mode = false;
            g_high_load_mode = false;
            auth_set_normal_mode(nullptr);
            std::cout << "[Admin] Normal mode set. The next received packet will trigger switch to 12,22,32." << std::endl;
            continue;
        }

        if (hex_input == "stop") {
            g_attack_mode = false;
            g_high_load_mode = false;
            auth_set_attack_mode(0, nullptr);
            auth_set_high_load_mode(0, nullptr);
            std::cout << "[Admin] Attack/high-load mandatory mode disabled." << std::endl;
            continue;
        }

        // 手动粘贴 hex 数据
        std::vector<uint8_t> raw_data = hex_to_bytes(hex_input);
        char current_src[INET6_ADDRSTRLEN] = {0};
        char current_dst[INET6_ADDRSTRLEN] = {0};
        if (raw_data.size() >= 14) {
            uint16_t ether_type = (raw_data[12] << 8) | raw_data[13];
            if (ether_type == 0x86dd && raw_data.size() >= 14 + 40) {
                parse_ipv6_header(raw_data.data() + 14, current_src, current_dst);
            }
        } else if (raw_data.size() >= 40 && ((raw_data[0] >> 4) == 6)) {
            parse_ipv6_header(raw_data.data(), current_src, current_dst);
        }
        process_auth_packet(raw_data.data(), static_cast<unsigned int>(raw_data.size()), current_src, current_dst);
    }

    g_auto_listen = false;
    return 0;
}
