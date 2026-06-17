#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <cstdlib>
#include <vector>
#include <string>
#include <ctime>
#include <cstdint>
#include <cstring>
#include <thread>
#include <chrono>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#ifdef CONST
#undef CONST
#endif
#ifdef OUT
#undef OUT
#endif

#pragma comment(lib, "ws2_32.lib")

// 高性能
#include "ascon/include/ascon/aead/ascon_aead128.hpp"
#include "Xoodyak/include/xoodyak.hpp"
#include "TinyJAMBU/include/tinyjambu_128.hpp" 
// 强安全
#include "ISAP/include/isap_a_128a.hpp"
#include "ISAP/include/isap_k_128a.hpp" 
#include "TinyJAMBU/include/tinyjambu_256.hpp" 
// 资源受限
#include "Sparkle/include/schwaemm.hpp"
#include "Elephant/include/dumbo.hpp"
#include "GIFT-COFB/include/aead.hpp"

// 静态预共享密钥与随机数验证 (为免协商阶段，直接写死静态Key进行加解密对称验证)
const uint8_t PRE_SHARED_KEY[32] = { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,
                                     0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20 };
const uint8_t FIXED_NONCE[16] = { 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99 };

#pragma pack(push, 1)
struct AuthPacket {
    int algorithm_id;      // 具体采用的算法ID (11, 12, 13 等)
    uint8_t ciphertext[64];
    uint8_t tag[16];
};
#pragma pack(pop)

void generate_random_data(uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) data[i] = static_cast<uint8_t>(std::rand() % 256);
}

// 客户端发起身份验证
void send_auth_packet(SOCKET sock, int alg_id) {
    AuthPacket packet;
    packet.algorithm_id = alg_id;
    std::memset(packet.ciphertext, 0, 64);
    std::memset(packet.tag, 0, 16);

    uint8_t ad[32] = {0}; // 空 AD
    uint8_t pt[64] = {0}; 
    generate_random_data(pt, 64); // 随机生成终端的心跳报文
    
    // 只负责加密（encrypt）
    switch(alg_id) {
        case 11: {
            std::array<uint8_t, 16> k_arr; std::memcpy(k_arr.data(), PRE_SHARED_KEY, 16);
            std::array<uint8_t, 16> n_arr; std::memcpy(n_arr.data(), FIXED_NONCE, 16);
            ascon_aead128::ascon_aead128_t ctx_enc(k_arr, n_arr);
            (void)ctx_enc.absorb_data(std::span<const uint8_t>(ad, 32));
            (void)ctx_enc.finalize_data();
            (void)ctx_enc.encrypt_plaintext(std::span<const uint8_t>(pt, 64), std::span<uint8_t>(packet.ciphertext, 64));
            (void)ctx_enc.finalize_encrypt(std::span<uint8_t, 16>(packet.tag, 16));
            break;
        }
        case 12: xoodyak::encrypt(PRE_SHARED_KEY, FIXED_NONCE, ad, 32, pt, packet.ciphertext, 64, packet.tag); break;
        case 13: tinyjambu_128::encrypt(PRE_SHARED_KEY, FIXED_NONCE, ad, 32, pt, packet.ciphertext, 64, packet.tag); break;
        
        case 21: isap_a_128a::encrypt(PRE_SHARED_KEY, FIXED_NONCE, ad, 32, pt, packet.ciphertext, 64, packet.tag); break;
        case 22: isap_k_128a::encrypt(PRE_SHARED_KEY, FIXED_NONCE, ad, 32, pt, packet.ciphertext, 64, packet.tag); break;
        case 23: tinyjambu_256::encrypt(PRE_SHARED_KEY, FIXED_NONCE, ad, 32, pt, packet.ciphertext, 64, packet.tag); break;
        
        case 31: schwaemm128_128::encrypt(PRE_SHARED_KEY, FIXED_NONCE, ad, 32, pt, packet.ciphertext, 64, packet.tag); break;
        case 32: dumbo::encrypt(PRE_SHARED_KEY, FIXED_NONCE, ad, 32, pt, packet.ciphertext, 64, packet.tag); break;
        case 33: gift_cofb::encrypt(PRE_SHARED_KEY, FIXED_NONCE, ad, 32, pt, packet.ciphertext, 64, packet.tag); break;
    }

    // 发送带有密文和标签的验证包给认证服务端
    send(sock, (const char*)&packet, sizeof(AuthPacket), 0);
    std::cout << "  [Client] -> 发送加密载荷 (算法ID: " << alg_id << ")...\n";
}

int main() {
    SetConsoleOutputCP(65001);
    std::srand((unsigned int)std::time(nullptr));
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    SOCKET connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(8888); // 连接 Authenticator
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

    std::cout << ">> IoT 设备启动，正在请求连接 Authenticator (端口 8888)...\n";
    while (connect(connectSocket, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == SOCKET_ERROR) {
        std::cout << "连接认证网关失败，1秒后重试...\n";
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    std::cout << ">> 已连接 Authenticator！等待下发安全策略。\n";

    while (true) {
        int strategy_decision = 0;
        // 等待接收 1/2/3
        if (recv(connectSocket, (char*)&strategy_decision, sizeof(strategy_decision), 0) > 0) {
            std::cout << "\n-------------------------------------------------\n";
            std::cout << ">> 收到主调度服务器下发的安全策略变更为: [" << strategy_decision << "]\n";
            
            if(strategy_decision == 1) {
                send_auth_packet(connectSocket, 11);
                send_auth_packet(connectSocket, 12);
                send_auth_packet(connectSocket, 13);
            } else if(strategy_decision == 2) {
                send_auth_packet(connectSocket, 21);
                send_auth_packet(connectSocket, 22);
                send_auth_packet(connectSocket, 23);
            } else if(strategy_decision == 3) {
                send_auth_packet(connectSocket, 31);
                send_auth_packet(connectSocket, 32);
                send_auth_packet(connectSocket, 33);
            }
        } else {
            std::cout << "Authenticator 关闭了连接。\n";
            break;
        }
        // 由于Authenticator控制频率（例如发一次等1秒），这里随动即可。
    }

    closesocket(connectSocket);
    WSACleanup();
    return 0;
}
