#include <iostream>
#include <vector>
#include <algorithm>
#include <ctime>
#include <cstring>
#include <iomanip>
#include <string>
#include "libauth.h"
#include "auth_api.h"

// 打印十六进制数据包，方便用户复制到测试工具中
void print_payload_hex(const char* data, size_t len) {
    std::cout << "\n[Client] 已生成身份认证包！" << std::endl;
    std::cout << "[Client] 请复制以下十六进制内容进行验证:\n" << std::endl;
    
    const uint8_t* ptr = reinterpret_cast<const uint8_t*>(data);
    for (size_t i = 0; i < len; ++i) {
        std::printf("0x%02x%s", ptr[i], (i == len - 1 ? "" : ","));
        if ((i + 1) % 12 == 0) std::printf("\n");
    }
    std::printf("\n\n");
}

int main() {
    // 1. 初始化模块 (包含 KeyVault 初始化)
    auth_init();

    std::cout << "========= 客户端交互测试 =========" << std::endl;
    
    // 2. 手动输入算法池
    std::string pool_input;
    std::cout << "请输入允许使用的算法池 (默认: 11,12,13,21,22,23,31,32,33): ";
    std::getline(std::cin, pool_input);
    if (pool_input.empty()) {
        pool_input = "11,12,13,21,22,23,31,32,33";
    }

    int selected_ids[3];
    // 3. 从池中随机选择 3 个算法（客户端使用接口3）
    if (auth_select_algs_from_pool(pool_input.c_str(), selected_ids) != 0) {
        std::cerr << "[Client] 算法池解析失败或算法数量不足 3 个！" << std::endl;
        return -1;
    }

    std::cout << "[Client] 自动选定的 3 个算法组合: " 
              << selected_ids[0] << ", " << selected_ids[1] << ", " << selected_ids[2] << std::endl;

    // 4. 准备业务数据 (64字节)
    uint8_t business_data[64];
    std::memset(business_data, 0xAA, 64); // 模拟填充数据

    // 5. 调用北邮标准接口生成认证包 (接口4)
    char packet_buffer[256]; 
    if (auth_generate_packet(selected_ids, business_data, packet_buffer) == 0) {
        // 6. 打印结果
        print_payload_hex(packet_buffer, AUTH_PACKET_BYTES);
    }

    // --- 演示逻辑：模拟接收服务端返回的重认证信号 ---
    std::cout << "------------------------------------------" << std::endl;
    std::cout << "模拟测试：请输入服务端返回的指令 (直接按回车跳过): ";
    std::string server_cmd;
    std::getline(std::cin, server_cmd);
    
    if (!server_cmd.empty()) {
        int forced_ids[3];
        int action = auth_parse_re_auth_signal(server_cmd.c_str(), forced_ids); // 接口5
        
        if (action == 1) {
            std::cout << "[Client] 收到攻击防御指令！必须切换到算法: " 
                      << forced_ids[0] << "," << forced_ids[1] << "," << forced_ids[2] << std::endl;
            // 此处应调用 auth_generate_packet(forced_ids, ...) 重新发包
        } else if (action == 2) {
            std::cout << "[Client] 收到重试指令！算法配置不匹配，正在重新同步..." << std::endl;
        }
    }

    return 0;
}
