#include <iostream>
#include <fstream>
#include <cstring>
#include <array>
#include <vector>
#include <ctime>
#include "auth_api.h"
#include "key_vault.h"
#include "libauth.h" // 引入 lib 接口

void print_to_file(std::ofstream& file, const char* title, AuthPacket& packet) {
    file << "--- [" << title << "] ---\n";
    uint8_t* ptr = reinterpret_cast<uint8_t*>(&packet);
    for (size_t i = 0; i < sizeof(AuthPacket); ++i) {
        char buffer[16];
        std::sprintf(buffer, "0x%02x,", ptr[i]);
        file << buffer;
        if ((i + 1) % 12 == 0) file << "\n";
    }
    file << "\n\n";
}

int main(int argc, char* argv[]) {
    // 1. 初始化模块
    auth_init();
    
    std::ofstream txt_file("payload_samples.txt", std::ios::out | std::ios::trunc);
    if (!txt_file.is_open()) {
        std::cerr << "Error: Could not open payload_samples.txt" << std::endl;
        return -1;
    }

    std::cout << "--- Triple-Auth 批量测试数据生成工具 ---" << std::endl;

    uint8_t plaintext[64];
    std::memset(plaintext, 0xAA, 64);
    
    // 场景 A: 默认组合 (11, 12, 13) - 包含 TinyJAMBU
    int ids_a[3] = {11, 12, 13};
    AuthPacket packet_a;
    std::memset(&packet_a, 0, sizeof(AuthPacket)); // 关键：必须清零
    if (auth_generate_packet(ids_a, plaintext, (char*)&packet_a) == 0) {
        print_to_file(txt_file, "组合 11,12,13 | 正常样本", packet_a);
    }

    // 场景 B: 三组 256-bit key 组合 (13, 23, 33)
    int ids_b[3] = {13, 23, 33};
    AuthPacket packet_b;
    std::memset(&packet_b, 0, sizeof(AuthPacket)); // 关键：必须清零
    if (auth_generate_packet(ids_b, plaintext, (char*)&packet_b) == 0) {
        print_to_file(txt_file, "组合 13,23,33 | 正常样本", packet_b);
    }

    // 场景 C: 高性能组合 (31, 32, 33)
    int ids_c[3] = {31, 32, 33};
    AuthPacket packet_c;
    std::memset(&packet_c, 0, sizeof(AuthPacket)); // 关键：必须清零
    if (auth_generate_packet(ids_c, plaintext, (char*)&packet_c) == 0) {
        print_to_file(txt_file, "组合 31,32,33 | 正常样本", packet_c);
    }

    // 场景 D: 故障样本 (Tag 损坏)
    packet_c.tags[0][0] ^= 0x55; 
    print_to_file(txt_file, "组合 31,32,33 | 损坏样本 (Tag1 被篡改)", packet_c);

    txt_file.close();
    std::cout << "测试数据已生成至: payload_samples.txt" << std::endl;
    std::cout << "你可以直接打开该文件，复制十六进制内容进行服务端测试。" << std::endl;

    return 0;
}
