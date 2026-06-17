#include <iostream>
#include <cstdlib>
#include <array>
#include <vector>
#include <string>
#include <ctime>
#include <cstdint>  // 用于uint8_t定义

// 各算法头文件（根据实际include路径引用）
// Ascon
#include "ascon/include/ascon/aead/ascon_aead128.hpp"     // Ascon AEAD
#include "ascon/include/ascon/aead/duplex.hpp"            // Ascon Duplex mode
#include "ascon/include/ascon/permutation/ascon.hpp"      // Ascon Permutation
#include "ascon/include/ascon/utils/common.hpp"           // Ascon Common utilities
#include "ascon/include/ascon/utils/force_inline.hpp"     // Ascon Force inline utilities

#include "Sparkle/include/schwaemm.hpp"                  // Sparkle (Schwaemm实现)
#include "Xoodyak/include/xoodyak.hpp"                   // Xoodyak
#include "Photon-Beetle/include/photon_beetle.hpp"       // Photon-Beetle
// TinyJAMBU
#include "TinyJAMBU/include/tinyjambu.hpp"               // TinyJAMBU
#include "TinyJAMBU/include/tinyjambu_192.hpp"           // TinyJAMBU_192
#include "TinyJAMBU/include/permute.hpp"                 // permute

#include "Elephant/include/dumbo.hpp"                    // Elephant (Dumbo)
#include "ISAP/include/isap_a_128a.hpp"                  // ISAP-A-128A
#include "GIFT-COFB/include/aead.hpp"                    // GIFT-COFB
#include "Romulus/include/romulusn.hpp"                  // Romulus-N

// 工具函数：生成随机数据
template <typename T>
void generate_random_data(T& data) {
    for (auto& byte : data) {
        byte = static_cast<uint8_t>(std::rand() % 256);
    }
}

void generate_random_data(uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        data[i] = static_cast<uint8_t>(std::rand() % 256);
    }
}

// 字节转十六进制字符串
std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::string hex_str;
    const char* hex_digits = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        hex_str += hex_digits[(data[i] >> 4) & 0x0F];
        hex_str += hex_digits[data[i] & 0x0F];
    }
    return hex_str;
}

template <typename T>
std::string bytes_to_hex_string(const T& data) {
    return bytes_to_hex(data.data(), data.size());
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "用法: " << argv[0] << " [1-9]\n";
        std::cerr << "1: Ascon\n2: Sparkle\n3: Xoodyak\n4: Photon-Beetle\n5: TinyJAMBU\n";
        std::cerr << "6: Elephant\n7: ISAP\n8: GIFT-COFB\n9: Romulus\n";
        return EXIT_FAILURE;
    }

    int choice = std::atoi(argv[1]);
    if (choice < 1 || choice > 9) {
        std::cerr << "请输入1-9之间的数字\n";
        return EXIT_FAILURE;
    }

    std::srand(std::time(nullptr));  // 初始化随机数生成器

    switch (choice) {
        case 1: {  // Ascon (对应ascon/examples/ascon_aead128.cpp)
            constexpr size_t KEY_LEN = 16;  // Ascon-128 key size is 16 bytes
            constexpr size_t NONCE_LEN = 16; // Ascon-128 nonce size is 16 bytes
            constexpr size_t TAG_LEN = 16;   // Ascon-128 tag size is 16 bytes
            constexpr size_t AD_LEN = 32;    // 原示例关联数据长度
            constexpr size_t PT_LEN = 64;    // 原示例明文长度

            uint8_t key[KEY_LEN];
            uint8_t nonce[NONCE_LEN];
            uint8_t tag[TAG_LEN];
            uint8_t ad[AD_LEN];
            uint8_t plaintext[PT_LEN];
            uint8_t ciphertext[PT_LEN];
            uint8_t decrypted[PT_LEN];

            generate_random_data(key, KEY_LEN);
            generate_random_data(nonce, NONCE_LEN);
            generate_random_data(ad, AD_LEN);
            generate_random_data(plaintext, PT_LEN);

            std::array<uint8_t, KEY_LEN> key_arr;
            std::array<uint8_t, NONCE_LEN> nonce_arr;

            std::copy(key, key + KEY_LEN, key_arr.begin());
            std::copy(nonce, nonce + NONCE_LEN, nonce_arr.begin());

            // 使用 Ascon AEAD128 的正确 API
            ascon_aead128::ascon_aead128_t ascon_enc(key_arr, nonce_arr);
            ascon_enc.absorb_data(ad);
            ascon_enc.finalize_data();
            ascon_enc.encrypt_plaintext(plaintext, ciphertext);
            ascon_enc.finalize_encrypt(tag);
            
            // 解密部分
            ascon_aead128::ascon_aead128_t ascon_dec(key_arr, nonce_arr);
            ascon_dec.absorb_data(ad);
            ascon_dec.finalize_data();
            ascon_dec.decrypt_ciphertext(ciphertext, decrypted);
            auto status = ascon_dec.finalize_decrypt(tag);
            bool verify = (status == ascon_aead128::ascon_aead128_status_t::decryption_success_as_tag_matches);

            std::cout << "Ascon AEAD128\n";
            std::cout << "Key       : " << bytes_to_hex(key, KEY_LEN) << "\n";
            std::cout << "Nonce     : " << bytes_to_hex(nonce, NONCE_LEN) << "\n";
            std::cout << "Associated Data : " << bytes_to_hex(ad, AD_LEN) << "\n";
            std::cout << "Plain Text : " << bytes_to_hex(plaintext, PT_LEN) << "\n";
            std::cout << "Encrypted Text : " << bytes_to_hex(ciphertext, PT_LEN) << "\n";
            std::cout << "Authentication Tag : " << bytes_to_hex(tag, TAG_LEN) << "\n";
            std::cout << "Decrypted Text : " << bytes_to_hex(decrypted, PT_LEN) << "\n";
            std::cout << "Verification : " << (verify ? "Success" : "Failed") << "\n";
            break;
        }

        case 2: {  // Sparkle (Schwaemm算法)
            constexpr size_t KEY_LEN = 16;   // Schwaemm128-128密钥长度
            constexpr size_t NONCE_LEN = 16; // 随机数长度
            constexpr size_t TAG_LEN = 16;   // 标签长度
            constexpr size_t AD_LEN = 32;    // 关联数据长度
            constexpr size_t PT_LEN = 64;    // 明文长度

            uint8_t key[KEY_LEN];
            uint8_t nonce[NONCE_LEN];
            uint8_t tag[TAG_LEN];
            uint8_t ad[AD_LEN];
            uint8_t plaintext[PT_LEN];
            uint8_t ciphertext[PT_LEN];
            uint8_t decrypted[PT_LEN];

            generate_random_data(key, KEY_LEN);
            generate_random_data(nonce, NONCE_LEN);
            generate_random_data(ad, AD_LEN);
            generate_random_data(plaintext, PT_LEN);

            // 使用Schwaemm的正确API
            schwaemm128_128::encrypt(key, nonce, ad, AD_LEN, plaintext, ciphertext, PT_LEN, tag);
            bool verify = schwaemm128_128::decrypt(key, nonce, tag, ad, AD_LEN, ciphertext, decrypted, PT_LEN);

            std::cout << "Sparkle (Schwaemm128-128) AEAD\n";
            std::cout << "Key       : " << bytes_to_hex(key, KEY_LEN) << "\n";
            std::cout << "Nonce     : " << bytes_to_hex(nonce, NONCE_LEN) << "\n";
            std::cout << "Associated Data : " << bytes_to_hex(ad, AD_LEN) << "\n";
            std::cout << "Plain Text : " << bytes_to_hex(plaintext, PT_LEN) << "\n";
            std::cout << "Encrypted Text : " << bytes_to_hex(ciphertext, PT_LEN) << "\n";
            std::cout << "Authentication Tag : " << bytes_to_hex(tag, TAG_LEN) << "\n";
            std::cout << "Decrypted Text : " << bytes_to_hex(decrypted, PT_LEN) << "\n";
            std::cout << "Verification : " << (verify ? "Success" : "Failed") << "\n";
            break;
        }

        case 3: {  // Xoodyak (对应Xoodyak/example/xoodyak_aead.cpp)
            constexpr size_t KEY_LEN = 16;   // Xoodyak密钥长度
            constexpr size_t NONCE_LEN = 16; // 随机数长度
            constexpr size_t TAG_LEN = 16;   // 标签长度
            constexpr size_t AD_LEN = 32;    // 关联数据长度
            constexpr size_t PT_LEN = 64;    // 明文长度

            uint8_t key[KEY_LEN];
            uint8_t nonce[NONCE_LEN];
            uint8_t tag[TAG_LEN];
            uint8_t ad[AD_LEN];
            uint8_t plaintext[PT_LEN];
            uint8_t ciphertext[PT_LEN];
            uint8_t decrypted[PT_LEN];

            generate_random_data(key, KEY_LEN);
            generate_random_data(nonce, NONCE_LEN);
            generate_random_data(ad, AD_LEN);
            generate_random_data(plaintext, PT_LEN);

            // 使用Xoodyak的正确API (根据example/xoodyak_aead.cpp)
            xoodyak::encrypt(key, nonce, ad, AD_LEN, plaintext, ciphertext, PT_LEN, tag);
            bool verify = xoodyak::decrypt(key, nonce, tag, ad, AD_LEN, ciphertext, decrypted, PT_LEN);

            std::cout << "Xoodyak AEAD\n";
            std::cout << "Key       : " << bytes_to_hex(key, KEY_LEN) << "\n";
            std::cout << "Nonce     : " << bytes_to_hex(nonce, NONCE_LEN) << "\n";
            std::cout << "Associated Data : " << bytes_to_hex(ad, AD_LEN) << "\n";
            std::cout << "Plain Text : " << bytes_to_hex(plaintext, PT_LEN) << "\n";
            std::cout << "Encrypted Text : " << bytes_to_hex(ciphertext, PT_LEN) << "\n";
            std::cout << "Authentication Tag : " << bytes_to_hex(tag, TAG_LEN) << "\n";
            std::cout << "Decrypted Text : " << bytes_to_hex(decrypted, PT_LEN) << "\n";
            std::cout << "Verification : " << (verify ? "Success" : "Failed") << "\n";
            break;
        }
        case 4: {  // Photon-Beetle (对应Photon-Beetle/example/aead.cpp)
            constexpr size_t KEY_LEN = 16;   // 密钥长度
            constexpr size_t NONCE_LEN = 16; // 随机数长度
            constexpr size_t TAG_LEN = 16;   // 标签长度
            constexpr size_t AD_LEN = 32;    // 关联数据长度
            constexpr size_t PT_LEN = 64;    // 明文长度

            uint8_t key[KEY_LEN];
            uint8_t nonce[NONCE_LEN];
            uint8_t tag[TAG_LEN];
            uint8_t ad[AD_LEN];
            uint8_t plaintext[PT_LEN];
            uint8_t ciphertext[PT_LEN];
            uint8_t decrypted[PT_LEN];

            generate_random_data(key, KEY_LEN);
            generate_random_data(nonce, NONCE_LEN);
            generate_random_data(ad, AD_LEN);
            generate_random_data(plaintext, PT_LEN);

            // 使用Photon-Beetle的正确API (根据检索到的代码)
            // 使用RATE=16的版本，即Photon-Beetle-AEAD[128]
            photon_beetle::encrypt<16>(key, nonce, ad, AD_LEN, plaintext, ciphertext, PT_LEN, tag);
            bool verify = photon_beetle::decrypt<16>(key, nonce, tag, ad, AD_LEN, ciphertext, decrypted, PT_LEN);

            std::cout << "Photon-Beetle AEAD\n";
            std::cout << "Key       : " << bytes_to_hex(key, KEY_LEN) << "\n";
            std::cout << "Nonce     : " << bytes_to_hex(nonce, NONCE_LEN) << "\n";
            std::cout << "Associated Data : " << bytes_to_hex(ad, AD_LEN) << "\n";
            std::cout << "Plain Text : " << bytes_to_hex(plaintext, PT_LEN) << "\n";
            std::cout << "Encrypted Text : " << bytes_to_hex(ciphertext, PT_LEN) << "\n";
            std::cout << "Authentication Tag : " << bytes_to_hex(tag, TAG_LEN) << "\n";
            std::cout << "Decrypted Text : " << bytes_to_hex(decrypted, PT_LEN) << "\n";
            std::cout << "Verification : " << (verify ? "Success" : "Failed") << "\n";
            break;
        }

        case 5: {  // TinyJAMBU (对应TinyJAMBU/example/tinyjambu_192.cpp)
            constexpr size_t KEY_LEN = 24;   // 192位密钥
            constexpr size_t NONCE_LEN = 12; // 随机数长度
            constexpr size_t TAG_LEN = 8;    // 标签长度
            constexpr size_t AD_LEN = 32;    // 关联数据长度
            constexpr size_t PT_LEN = 64;    // 明文长度

            uint8_t key[KEY_LEN];
            uint8_t nonce[NONCE_LEN];
            uint8_t tag[TAG_LEN];
            uint8_t ad[AD_LEN];
            uint8_t plaintext[PT_LEN];
            uint8_t ciphertext[PT_LEN];
            uint8_t decrypted[PT_LEN];

            generate_random_data(key, KEY_LEN);
            generate_random_data(nonce, NONCE_LEN);
            generate_random_data(ad, AD_LEN);
            generate_random_data(plaintext, PT_LEN);

            // 使用TinyJAMBU-192的正确API
            tinyjambu_192::encrypt(key, nonce, ad, AD_LEN, plaintext, ciphertext, PT_LEN, tag);
            bool verify = tinyjambu_192::decrypt(key, nonce, tag, ad, AD_LEN, ciphertext, decrypted, PT_LEN);

            std::cout << "TinyJAMBU-192 AEAD\n";
            std::cout << "Key       : " << bytes_to_hex(key, KEY_LEN) << "\n";
            std::cout << "Nonce     : " << bytes_to_hex(nonce, NONCE_LEN) << "\n";
            std::cout << "Associated Data : " << bytes_to_hex(ad, AD_LEN) << "\n";
            std::cout << "Plain Text : " << bytes_to_hex(plaintext, PT_LEN) << "\n";
            std::cout << "Encrypted Text : " << bytes_to_hex(ciphertext, PT_LEN) << "\n";
            std::cout << "Authentication Tag : " << bytes_to_hex(tag, TAG_LEN) << "\n";
            std::cout << "Decrypted Text : " << bytes_to_hex(decrypted, PT_LEN) << "\n";
            std::cout << "Verification : " << (verify ? "Success" : "Failed") << "\n";
            break;
        }

        case 6: {  // Elephant (对应Elephant/example/dumbo.cpp)
            constexpr size_t KEY_LEN = 16;   // 密钥长度
            constexpr size_t NONCE_LEN = 12; // 随机数长度
            constexpr size_t TAG_LEN = 8;    // 标签长度
            constexpr size_t AD_LEN = 32;    // 关联数据长度
            constexpr size_t PT_LEN = 64;    // 明文长度

            uint8_t key[KEY_LEN];
            uint8_t nonce[NONCE_LEN];
            uint8_t tag[TAG_LEN];
            uint8_t ad[AD_LEN];
            uint8_t plaintext[PT_LEN];
            uint8_t ciphertext[PT_LEN];
            uint8_t decrypted[PT_LEN];

            generate_random_data(key, KEY_LEN);
            generate_random_data(nonce, NONCE_LEN);
            generate_random_data(ad, AD_LEN);
            generate_random_data(plaintext, PT_LEN);

            // 使用Dumbo的正确API，注意参数顺序
            dumbo::encrypt(key, nonce, ad, AD_LEN, plaintext, ciphertext, PT_LEN, tag);
            bool verify = dumbo::decrypt(key, nonce, tag, ad, AD_LEN, ciphertext, decrypted, PT_LEN);

            std::cout << "Elephant (Dumbo) AEAD\n";
            std::cout << "Key       : " << bytes_to_hex(key, KEY_LEN) << "\n";
            std::cout << "Nonce     : " << bytes_to_hex(nonce, NONCE_LEN) << "\n";
            std::cout << "Associated Data : " << bytes_to_hex(ad, AD_LEN) << "\n";
            std::cout << "Plain Text : " << bytes_to_hex(plaintext, PT_LEN) << "\n";
            std::cout << "Encrypted Text : " << bytes_to_hex(ciphertext, PT_LEN) << "\n";
            std::cout << "Authentication Tag : " << bytes_to_hex(tag, TAG_LEN) << "\n";
            std::cout << "Decrypted Text : " << bytes_to_hex(decrypted, PT_LEN) << "\n";
            std::cout << "Verification : " << (verify ? "Success" : "Failed") << "\n";
            break;
        }

        case 7: {  // ISAP (对应ISAP/example/isap_a_128a.cpp)
            constexpr size_t KEY_LEN = 16;   // 密钥长度
            constexpr size_t NONCE_LEN = 16; // 随机数长度
            constexpr size_t TAG_LEN = 16;   // 标签长度
            constexpr size_t AD_LEN = 32;    // 关联数据长度
            constexpr size_t PT_LEN = 64;    // 明文长度

            uint8_t key[KEY_LEN];
            uint8_t nonce[NONCE_LEN];
            uint8_t tag[TAG_LEN];
            uint8_t ad[AD_LEN];
            uint8_t plaintext[PT_LEN];
            uint8_t ciphertext[PT_LEN];
            uint8_t decrypted[PT_LEN];

            generate_random_data(key, KEY_LEN);
            generate_random_data(nonce, NONCE_LEN);
            generate_random_data(ad, AD_LEN);
            generate_random_data(plaintext, PT_LEN);

            // 原示例加密解密流程（ISAP-A-128A）
            isap_a_128a::encrypt(key, nonce, ad, AD_LEN, plaintext, ciphertext, PT_LEN, tag);
            bool verify = isap_a_128a::decrypt(key, nonce, tag, ad, AD_LEN, ciphertext, decrypted, PT_LEN);

            std::cout << "ISAP-A-128A AEAD\n";
            std::cout << "Key       : " << bytes_to_hex(key, KEY_LEN) << "\n";
            std::cout << "Nonce     : " << bytes_to_hex(nonce, NONCE_LEN) << "\n";
            std::cout << "Associated Data : " << bytes_to_hex(ad, AD_LEN) << "\n";
            std::cout << "Plain Text : " << bytes_to_hex(plaintext, PT_LEN) << "\n";
            std::cout << "Encrypted Text : " << bytes_to_hex(ciphertext, PT_LEN) << "\n";
            std::cout << "Authentication Tag : " << bytes_to_hex(tag, TAG_LEN) << "\n";
            std::cout << "Decrypted Text : " << bytes_to_hex(decrypted, PT_LEN) << "\n";
            std::cout << "Verification : " << (verify ? "Success" : "Failed") << "\n";
            break;
        }

        case 8: {  // GIFT-COFB (对应GIFT-COFB/example/gift_cofb.cpp)
            constexpr size_t KEY_LEN = 16;   // 密钥长度
            constexpr size_t NONCE_LEN = 12; // 随机数长度
            constexpr size_t TAG_LEN = 16;   // 标签长度
            constexpr size_t AD_LEN = 32;    // 关联数据长度
            constexpr size_t PT_LEN = 64;    // 明文长度

            uint8_t key[KEY_LEN];
            uint8_t nonce[NONCE_LEN];
            uint8_t tag[TAG_LEN];
            uint8_t ad[AD_LEN];
            uint8_t plaintext[PT_LEN];
            uint8_t ciphertext[PT_LEN];
            uint8_t decrypted[PT_LEN];

            generate_random_data(key, KEY_LEN);
            generate_random_data(nonce, NONCE_LEN);
            generate_random_data(ad, AD_LEN);
            generate_random_data(plaintext, PT_LEN);

            // 原示例加密解密流程
            gift_cofb::encrypt(key, nonce, ad, AD_LEN, plaintext, ciphertext, PT_LEN, tag);
            bool verify = gift_cofb::decrypt(key, nonce, tag, ad, AD_LEN, ciphertext, decrypted, PT_LEN);

            std::cout << "GIFT-COFB AEAD\n";
            std::cout << "Key       : " << bytes_to_hex(key, KEY_LEN) << "\n";
            std::cout << "Nonce     : " << bytes_to_hex(nonce, NONCE_LEN) << "\n";
            std::cout << "Associated Data : " << bytes_to_hex(ad, AD_LEN) << "\n";
            std::cout << "Plain Text : " << bytes_to_hex(plaintext, PT_LEN) << "\n";
            std::cout << "Encrypted Text : " << bytes_to_hex(ciphertext, PT_LEN) << "\n";
            std::cout << "Authentication Tag : " << bytes_to_hex(tag, TAG_LEN) << "\n";
            std::cout << "Decrypted Text : " << bytes_to_hex(decrypted, PT_LEN) << "\n";
            std::cout << "Verification : " << (verify ? "Success" : "Failed") << "\n";
            break;
        }

        case 9: {  // Romulus (对应Romulus/example/romulusn.cpp)
            constexpr size_t KEY_LEN = 16;   // 密钥长度
            constexpr size_t NONCE_LEN = 12; // 随机数长度
            constexpr size_t TAG_LEN = 16;   // 标签长度
            constexpr size_t AD_LEN = 32;    // 关联数据长度
            constexpr size_t PT_LEN = 64;    // 明文长度

            uint8_t key[KEY_LEN];
            uint8_t nonce[NONCE_LEN];
            uint8_t tag[TAG_LEN];
            uint8_t ad[AD_LEN];
            uint8_t plaintext[PT_LEN];
            uint8_t ciphertext[PT_LEN];
            uint8_t decrypted[PT_LEN];

            generate_random_data(key, KEY_LEN);
            generate_random_data(nonce, NONCE_LEN);
            generate_random_data(ad, AD_LEN);
            generate_random_data(plaintext, PT_LEN);

            // 原示例加密解密流程（Romulus-N）
            romulusn::encrypt(key, nonce, ad, AD_LEN, plaintext, ciphertext, PT_LEN, tag);
            bool verify = romulusn::decrypt(key, nonce, tag, ad, AD_LEN, ciphertext, decrypted, PT_LEN);

            std::cout << "Romulus-N AEAD\n";
            std::cout << "Key       : " << bytes_to_hex(key, KEY_LEN) << "\n";
            std::cout << "Nonce     : " << bytes_to_hex(nonce, NONCE_LEN) << "\n";
            std::cout << "Associated Data : " << bytes_to_hex(ad, AD_LEN) << "\n";
            std::cout << "Plain Text : " << bytes_to_hex(plaintext, PT_LEN) << "\n";
            std::cout << "Encrypted Text : " << bytes_to_hex(ciphertext, PT_LEN) << "\n";
            std::cout << "Authentication Tag : " << bytes_to_hex(tag, TAG_LEN) << "\n";
            std::cout << "Decrypted Text : " << bytes_to_hex(decrypted, PT_LEN) << "\n";
            std::cout << "Verification : " << (verify ? "Success" : "Failed") << "\n";
            break;
        }

        default:
            std::cerr << "无效选择\n";
            return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}