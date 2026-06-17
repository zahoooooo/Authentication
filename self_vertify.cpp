#include <iostream>
#include <cstring>
#include <ctime>
#include "libauth.h"
#include "auth_api.h"
#include "key_vault.h"

int main() {
    std::cout << "========= Auth Module Self-Verification =========" << std::endl;

    // 1. 初始化模块
    auth_init();

    // 2. 模拟客户端生成数据包
    // 获取当前系统时间 (KeyVault 内部也是用这个)
    uint64_t current_time = static_cast<uint64_t>(std::time(nullptr));
    uint8_t plaintext[64] = "This is a secure message from IoT device.";
    AuthPacket packet;

    // 使用算法 11 (Ascon)
    int alg_id = 11;
    std::cout << "[Client] Generating payload with Algorithm " << alg_id << "..." << std::endl;
    
    // 注意：客户端也必须从 KeyVault 取密钥才能对齐
    const uint8_t* client_key = AuthApi::KeyVault::GetInstance().GetCurrentKey(current_time);
    if (!AuthApi::GeneratePayload(client_key, alg_id, plaintext, packet)) {
        std::cerr << "Error: GeneratePayload failed!" << std::endl;
        return -1;
    }

    struct re_auth re_info;
    struct auth_report_msg report;

    // --- 测试场景 1: 正常验证 ---
    std::cout << "\n[Test 1] Normal Authentication..." << std::endl;
    G_ENC_ID = 0x0B0C0D01; // 允许 11, 12, 13; 开启认证
    G_ATTACK_ID = 0;       // 无攻击
    int result = auth_policy_match((char*)&packet, sizeof(AuthPacket), &re_info, &report);
    std::cout << "Result: " << result << " (Expected: 1)" << std::endl;
    if (result == 1) std::cout << "PASS" << std::endl; else std::cout << "FAIL" << std::endl;

    // --- 测试场景 2: 攻击检测 ---
    std::cout << "\n[Test 2] Attack Detection..." << std::endl;
    G_ATTACK_ID = 1;       // 模拟发现 DDOS 攻击
    result = auth_policy_match((char*)&packet, sizeof(AuthPacket), &re_info, &report);
    std::cout << "Result: " << result << " (Expected: 3)" << std::endl;
    std::cout << "Report: " << report.report_msg << std::endl;
    if (result == 3) std::cout << "PASS" << std::endl; else std::cout << "FAIL" << std::endl;

    // --- 测试场景 3: 算法未授权 ---
    std::cout << "\n[Test 3] Algorithm Not Allowed..." << std::endl;
    G_ATTACK_ID = 0;
    G_ENC_ID = 0x15161701; // 只允许 21, 22, 23 (十进制); 但包里是 11
    result = auth_policy_match((char*)&packet, sizeof(AuthPacket), &re_info, &report);
    std::cout << "Result: " << result << " (Expected: 0)" << std::endl;
    std::cout << "Report: " << report.report_msg << std::endl;
    if (result == 0) std::cout << "PASS" << std::endl; else std::cout << "FAIL" << std::endl;

    // --- 测试场景 4: 关闭认证 ---
    std::cout << "\n[Test 4] Authentication Disabled..." << std::endl;
    G_ENC_ID = 0x0B0C0D00; // 控制位为 0
    result = auth_policy_match((char*)&packet, sizeof(AuthPacket), &re_info, &report);
    std::cout << "Result: " << result << " (Expected: 1)" << std::endl;
    if (result == 1) std::cout << "PASS" << std::endl; else std::cout << "FAIL" << std::endl;

    return 0;
}