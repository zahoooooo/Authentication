#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <cstdlib>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <mutex>
#include <atomic>
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

std::atomic<int> GLOBAL_STRATEGY(1);

const uint8_t PRE_SHARED_KEY[32] = { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,
                                     0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20 };
const uint8_t FIXED_NONCE[16] = { 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99 };

#pragma pack(push, 1)
struct AuthPacket {
    int algorithm_id; 
    uint8_t ciphertext[64];
    uint8_t tag[16];
};
#pragma pack(pop)

// 负责连接 Python 获取实时网络态势
void python_sync_thread() {
    SOCKET connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(9999);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

    while (connect(connectSocket, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == SOCKET_ERROR) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
    std::cout << "[Python Sync] -> 成功接通 Python IDS 中央决策系统！\n";

    while(true) {
        char heartbeat = 0x01;
        if (send(connectSocket, &heartbeat, 1, 0) == SOCKET_ERROR) break;
        int strategy = 1;
        if (recv(connectSocket, (char*)&strategy, sizeof(strategy), 0) > 0) {
            GLOBAL_STRATEGY = strategy;
        } else {
            break;
        }
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
    closesocket(connectSocket);
}

// 核心解密验证函数
bool verify_client(const AuthPacket& packet) {
    uint8_t ad[32] = {0}; 
    uint8_t dt[64] = {0}; // 用于存放解密出的临时明文
    bool verify = false;
    
    switch(packet.algorithm_id) {
        case 11: {
            std::cout << "  - ASCON-128a (通用)... ";
            std::array<uint8_t, 16> k_arr; std::memcpy(k_arr.data(), PRE_SHARED_KEY, 16);
            std::array<uint8_t, 16> n_arr; std::memcpy(n_arr.data(), FIXED_NONCE, 16);
            ascon_aead128::ascon_aead128_t ctx_dec(k_arr, n_arr);
            (void)ctx_dec.absorb_data(std::span<const uint8_t>(ad, 32));
            (void)ctx_dec.finalize_data();
            (void)ctx_dec.decrypt_ciphertext(std::span<const uint8_t>(packet.ciphertext, 64), std::span<uint8_t>(dt, 64));
            auto status = ctx_dec.finalize_decrypt(std::span<const uint8_t, 16>(packet.tag, 16));
            verify = (status == ascon_aead128::ascon_aead128_status_t::decryption_success_as_tag_matches);
            break;
        }
        case 12:
            std::cout << "  - Xoodyak (长报文高吞吐)... ";
            verify = xoodyak::decrypt(PRE_SHARED_KEY, FIXED_NONCE, packet.tag, ad, 32, packet.ciphertext, dt, 64);
            break;
        case 13:
            std::cout << "  - TinyJAMBU-128 (一般情况高吞吐)... ";
            verify = tinyjambu_128::decrypt(PRE_SHARED_KEY, FIXED_NONCE, packet.tag, ad, 32, packet.ciphertext, dt, 64);
            break;

        case 21:
            std::cout << "  - ISAP-A-128a (抗SCA、物理攻击)... ";
            verify = isap_a_128a::decrypt(PRE_SHARED_KEY, FIXED_NONCE, packet.tag, ad, 32, packet.ciphertext, dt, 64);
            break;
        case 22:
            std::cout << "  - ISAP-K-128a (Keccak核、安全冗余)... ";
            verify = isap_k_128a::decrypt(PRE_SHARED_KEY, FIXED_NONCE, packet.tag, ad, 32, packet.ciphertext, dt, 64);
            break;
        case 23:
            std::cout << "  - TinyJAMBU-256 (256-bit高密钥强度)... ";
            verify = tinyjambu_256::decrypt(PRE_SHARED_KEY, FIXED_NONCE, packet.tag, ad, 32, packet.ciphertext, dt, 64);
            break;

        case 31:
            std::cout << "  - Sparkle (软件支持强)... ";
            verify = schwaemm128_128::decrypt(PRE_SHARED_KEY, FIXED_NONCE, packet.tag, ad, 32, packet.ciphertext, dt, 64);
            break;
        case 32:
            std::cout << "  - Elephant (极致小面积)... ";
            verify = dumbo::decrypt(PRE_SHARED_KEY, FIXED_NONCE, packet.tag, ad, 32, packet.ciphertext, dt, 64);
            break;
        case 33:
            std::cout << "  - GIFT-COFB (硬件兼容性强)... ";
            verify = gift_cofb::decrypt(PRE_SHARED_KEY, FIXED_NONCE, packet.tag, ad, 32, packet.ciphertext, dt, 64);
            break;

        default:
            std::cerr << "  - [未知算法ID]\n";
            return false;
    }
    
    std::cout << (verify ? "认证通过" : "认证拒绝") << "\n";
    return verify;
}

int main() {
    SetConsoleOutputCP(65001);
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // 后台开启线程同步 AI 决策
    std::thread t_sync(python_sync_thread);
    t_sync.detach();

    // 本机 8888 启动，专门受阻验证物理终端
    SOCKET server_fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8888);

    bind(server_fd, (struct sockaddr*)&address, sizeof(address));
    listen(server_fd, 3);
    std::cout << ">> Authenticator (验证中枢) 已启动，端口 8888 等待终端汇入...\n";

    SOCKET new_socket;
    int addrlen = sizeof(address);

    while((new_socket = accept(server_fd, (struct sockaddr*)&address, &addrlen)) != INVALID_SOCKET) {
        std::cout << ">> 新的 IoT 客户端连接建立！\n";
        
        while(true) {
            // 每阁3秒下发一次当前全局策略，要求客户端以此协议加密返回身份包
            int strategy = GLOBAL_STRATEGY.load();
            if(send(new_socket, (char*)&strategy, sizeof(strategy), 0) == SOCKET_ERROR) break;

            std::cout << "\n----------------------------------------\n";
            std::cout << "[调度] 已向该终端下发安全层级令: " << strategy << "\n";

            int successes = 0;
            // 终端每次被激活必须连续发来3颗验证子弹
            for(int i=0; i<3; ++i) {
                AuthPacket pkt;
                if(recv(new_socket, (char*)&pkt, sizeof(AuthPacket), 0) <= 0) goto disconnect;
                
                if (verify_client(pkt)) {
                    successes++;
                }
            }

            std::cout << ">> 结果: " << successes << "/3 个子算法认证通过 => ";
            if (successes >= 2) std::cout << "[成功] 终端身份鉴权无误！身份真实且无破损。\n";
            else std::cout << "[失败] 终端遭到伪造或遭到中间人密文篡改！断开请求！\n";

            std::this_thread::sleep_for(std::chrono::seconds(3));
        }
    disconnect:
        std::cout << ">> IoT 设备掉线。\n";
        closesocket(new_socket);
    }

    closesocket(server_fd);
    WSACleanup();
    return 0;
}
