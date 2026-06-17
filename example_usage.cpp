#include "auth_api.h"
#include "key_vault.h"
#include <iostream>
#include <vector>
#include <ctime>
#include <thread>
#include <chrono>

int main() {
    std::cout << "========= IoT Authentication API Test =========" << std::endl;

    std::cout << "[System] Initializing 8192 Key Vault..." << std::endl;
    AuthApi::KeyVault::GetInstance().Initialize(0x12345678);
    std::cout << "[System] Vault initialized!" << std::endl;

    uint64_t current_time = std::time(nullptr);
    std::cout << "\n[System] Current Timestamp: " << current_time << " seconds" << std::endl;

    std::cout << "\n--- IoT Client ---" << std::endl;
    uint8_t original_message[64] = "Hello Multimodal Network! Here is sensor data.";
    int chosen_algorithms[3] = {11, 12, 13}; 
    
    AuthPacket network_payload;
    std::cout << "[IoT] Creating payload with Algorithm IDs: "
              << chosen_algorithms[0] << "," << chosen_algorithms[1] << "," << chosen_algorithms[2]
              << "..." << std::endl;
    
    bool is_generated = AuthApi::GeneratePayloadWithVault(
        current_time,       
        chosen_algorithms,  
        original_message,   
        network_payload     
    );

    if (is_generated) {
        std::cout << "[IoT] Payload generated successfully! Sending to Gateway..." << std::endl;
    } else {
        std::cout << "[IoT] Failed to generate payload (Unknown ID?)." << std::endl;
        return -1;
    }

    std::cout << "\n   >>> [Network] Data in transit... >>>" << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(1000)); 

    std::cout << "\n--- Gateway Server ---" << std::endl;
    uint8_t decrypted_buffer[64] = {0};

    uint64_t server_time = current_time + 3; 
    std::cout << "[Gateway] Packet received! Server Time: " << server_time << " seconds" << std::endl;

    std::cout << "[Gateway] Retrieving key by slot and verifying Math Tag..." << std::endl;
    bool verify_success = AuthApi::VerifyPayloadWithVault(
        server_time,        
        chosen_algorithms,  
        network_payload,    
        decrypted_buffer    
    );

    if (verify_success) {
        std::cout << "[Secure] Authentication PASS! Origin holds valid Vault Key." << std::endl;
        std::cout << "[Gateway] Decrypted App Data: " << (char*)decrypted_buffer << std::endl;
    } else {
        std::cout << "[Alert] Packet Rejected! Fake tag or expired timestamp (>30mins)." << std::endl;
    }

    return 0;
}
