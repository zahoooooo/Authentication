#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <cstdlib>
#include <vector>
#include <string>
#include <ctime>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <thread>
#include <chrono>
#include <fstream>
// --- Windows Socket 核心头文件 ---
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

// --- 辅助工具 ---
void generate_random_data(uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) data[i] = static_cast<uint8_t>(std::rand() % 256);
}

std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::string hex_str;
    const char* hex_digits = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        hex_str += hex_digits[(data[i] >> 4) & 0x0F];
        hex_str += hex_digits[data[i] & 0x0F];
    }
    return hex_str;
}
// 为了逻辑清晰，我们重新定义ID:
// 1x -> 高性能, 2x -> 强安全, 3x -> 资源受限
bool run_algorithm(int choice) {
    // 准备通用数据
    uint8_t key[32], nonce[16], tag[16], ad[32], pt[64], ct[64], dt[64];
    generate_random_data(key, 32); 
    generate_random_data(nonce, 16); 
    generate_random_data(ad, 32); 
    generate_random_data(pt, 64);

    bool verify = false;

    switch (choice) {
        // --- 高性能策略 ---
        case 11: 
            std::cout << "  - ASCON-128a (通用)... ";
            {
                std::array<uint8_t, 16> k_arr; std::memcpy(k_arr.data(), key, 16);
                std::array<uint8_t, 16> n_arr; std::memcpy(n_arr.data(), nonce, 16);
                // Encrypt
                ascon_aead128::ascon_aead128_t ctx_enc(k_arr, n_arr);
                (void)ctx_enc.absorb_data(std::span<const uint8_t>(ad, 32));
                (void)ctx_enc.finalize_data();
                (void)ctx_enc.encrypt_plaintext(std::span<const uint8_t>(pt, 64), std::span<uint8_t>(ct, 64));
                (void)ctx_enc.finalize_encrypt(std::span<uint8_t, 16>(tag, 16));
                
                // Decrypt
                ascon_aead128::ascon_aead128_t ctx_dec(k_arr, n_arr);
                (void)ctx_dec.absorb_data(std::span<const uint8_t>(ad, 32));
                (void)ctx_dec.finalize_data();
                (void)ctx_dec.decrypt_ciphertext(std::span<const uint8_t>(ct, 64), std::span<uint8_t>(dt, 64));
                auto status = ctx_dec.finalize_decrypt(std::span<const uint8_t, 16>(tag, 16));
                verify = (status == ascon_aead128::ascon_aead128_status_t::decryption_success_as_tag_matches);
            }
            break;
        case 12:
            std::cout << "  - Xoodyak (长报文高吞吐)... ";
            xoodyak::encrypt(key, nonce, ad, 32, pt, ct, 64, tag);
            verify = xoodyak::decrypt(key, nonce, tag, ad, 32, ct, dt, 64);
            break;
        case 13:
            std::cout << "  - TinyJAMBU-128 (一般情况高吞吐)... ";
            tinyjambu_128::encrypt(key, nonce, ad, 32, pt, ct, 64, tag);
            verify = tinyjambu_128::decrypt(key, nonce, tag, ad, 32, ct, dt, 64);
            break;

        // --- 强安全策略 ---
        case 21:
            std::cout << "  - ISAP-A-128a (抗SCA、物理攻击)... ";
            isap_a_128a::encrypt(key, nonce, ad, 32, pt, ct, 64, tag);
            verify = isap_a_128a::decrypt(key, nonce, tag, ad, 32, ct, dt, 64);
            break;
        case 22:
            std::cout << "  - ISAP-K-128a (Keccak核、安全冗余)... ";
            isap_k_128a::encrypt(key, nonce, ad, 32, pt, ct, 64, tag);
            verify = isap_k_128a::decrypt(key, nonce, tag, ad, 32, ct, dt, 64);
            break;
        case 23:
            std::cout << "  - TinyJAMBU-256 (256-bit高密钥强度)... ";
            {
                uint8_t key_256[32]; 
                generate_random_data(key_256, 32);
                tinyjambu_256::encrypt(key_256, nonce, ad, 32, pt, ct, 64, tag);
                verify = tinyjambu_256::decrypt(key_256, nonce, tag, ad, 32, ct, dt, 64);
            }
            break;

        // --- 资源受限策略 ---
        case 31:
            std::cout << "  - Sparkle (软件支持强)... ";
            schwaemm128_128::encrypt(key, nonce, ad, 32, pt, ct, 64, tag);
            verify = schwaemm128_128::decrypt(key, nonce, tag, ad, 32, ct, dt, 64);
            break;
        case 32:
            std::cout << "  - Elephant (极致小面积)... ";
            dumbo::encrypt(key, nonce, ad, 32, pt, ct, 64, tag);
            verify = dumbo::decrypt(key, nonce, tag, ad, 32, ct, dt, 64);
            break;
        case 33:
            std::cout << "  - GIFT-COFB (硬件兼容性强)... ";
            gift_cofb::encrypt(key, nonce, ad, 32, pt, ct, 64, tag);
            verify = gift_cofb::decrypt(key, nonce, tag, ad, 32, ct, dt, 64);
            break;

        default:
            std::cerr << "  - [未知算法ID: " << choice << "]\n";
            return false;
    }
    
    std::cout << (verify ? "认证通过" : "认证拒绝") << "\n";
    return verify;
}

void run_high_performance_strategy() {
    std::cout << "\n--- [执行高性能策略] ---\n";
    int successes = 0;
    if (run_algorithm(11)) successes++;
    if (run_algorithm(12)) successes++;
    if (run_algorithm(13)) successes++;
    
    std::cout << ">> 结果: " << successes << "/3 个子算法认证通过 => ";
    if (successes >= 2) std::cout << "[成功] 终端最终认证成功！\n";
    else std::cout << "[失败] 终端最终认证拒绝！\n";
}

void run_high_security_strategy() {
    std::cout << "\n--- [执行强安全策略] ---\n";
    int successes = 0;
    if (run_algorithm(21)) successes++;
    if (run_algorithm(22)) successes++;
    if (run_algorithm(23)) successes++;
    
    std::cout << ">> 结果: " << successes << "/3 个子算法认证通过 => ";
    if (successes >= 2) std::cout << "[成功] 终端最终认证成功！\n";
    else std::cout << "[失败] 终端最终认证拒绝！\n";
}

void run_resource_constrained_strategy() {
    std::cout << "\n--- [执行资源受限策略] ---\n";
    int successes = 0;
    if (run_algorithm(31)) successes++;
    if (run_algorithm(32)) successes++;
    if (run_algorithm(33)) successes++;
    
    std::cout << ">> 结果: " << successes << "/3 个子算法认证通过 => ";
    if (successes >= 2) std::cout << "[成功] 终端最终认证成功！\n";
    else std::cout << "[失败] 终端最终认证拒绝！\n";
}

// --- 策略调度器 ---
void execute_strategy(int strategy_id) {
    switch (strategy_id) {
        case 1:
            run_high_performance_strategy();
            break;
        case 2:
            run_high_security_strategy();
            break;
        case 3:
            run_resource_constrained_strategy();
            break;
        default:
            std::cerr << "收到无效策略 ID: " << strategy_id << "，忽略。\n";
    }
}


int main() {
    SetConsoleOutputCP(65001);
    std::srand((unsigned int)std::time(nullptr));
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    SOCKET connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(9999);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

    std::cout << "正在连接到决策系统...\n";
    while (connect(connectSocket, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == SOCKET_ERROR) {
        std::cout << "连接失败，1秒后重试...\n";
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    std::cout << "已连接！开始工作循环。\n";

    while (true) {
        // 请求服务器最新的策略判定（发送1字节心跳）
        char heartbeat = 0x01;
        if (send(connectSocket, &heartbeat, 1, 0) == SOCKET_ERROR) break;
        
        std::cout << "\n>> 向网关请求当前网络防御策略..." << std::flush;

        int strategy_decision = 0;
        if (recv(connectSocket, (char*)&strategy_decision, sizeof(strategy_decision), 0) > 0) {
            execute_strategy(strategy_decision);
        } else {
            std::cout << "服务器关闭了连接。\n";
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }

    closesocket(connectSocket);
    WSACleanup();
    return 0;
}