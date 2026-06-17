#ifndef AUTH_API_H
#define AUTH_API_H

#include <cstdint>
#include <cstddef>

// 认证包统一参数：为了支持 Schwaemm192-192 / Schwaemm256-256 这类 24/32 字节 Tag，
// 每层 Tag 存储扩展到 32 字节；短 Tag 算法只使用前 N 字节，其余为 0。
#define AUTH_LAYER_COUNT 3
#define AUTH_CIPHERTEXT_BYTES 64
#define AUTH_MAX_TAG_BYTES 32
#define AUTH_MAX_NONCE_BYTES 32
#define AUTH_PACKET_BYTES (4 + AUTH_LAYER_COUNT * AUTH_CIPHERTEXT_BYTES + AUTH_LAYER_COUNT * AUTH_MAX_TAG_BYTES)

#pragma pack(push, 1)
struct AuthPacket {
    int policy_id;                                       // 策略标识，编码当前三个算法 ID
    uint8_t ciphertexts[AUTH_LAYER_COUNT][AUTH_CIPHERTEXT_BYTES]; // 并行模式：每个算法各自加密同一份 64 字节业务数据
    uint8_t tags[AUTH_LAYER_COUNT][AUTH_MAX_TAG_BYTES];  // 三个算法生成的认证标签，最长 32 字节
};
#pragma pack(pop)

namespace AuthApi {

    extern const uint8_t FIXED_NONCE[AUTH_MAX_NONCE_BYTES];

    #define AUTH_TRACE_MAX_STEPS 8

    struct AuthCryptoTraceStep {
        int logical_layer;       // 0/1/2，对应算法链路中的第几层
        int alg_id;
        int direction;           // 1=encrypt, 0=decrypt, -1=skipped
        int status;              // 1=成功，0=失败，-1=未执行/跳过
        uint64_t worker_thread_hash; // 执行该算法的工作线程标识哈希，仅用于测试 trace 展示
        uint8_t input[AUTH_CIPHERTEXT_BYTES];
        uint8_t output[AUTH_CIPHERTEXT_BYTES];
        uint8_t tag[AUTH_MAX_TAG_BYTES];
    };

    struct AuthCryptoTrace {
        int valid;               // 1=有可读 trace
        int operation;           // 1=generate/encrypt，0=verify/decrypt
        int step_count;
        AuthCryptoTraceStep steps[AUTH_TRACE_MAX_STEPS];
    };

    bool VerifyPayload(const uint8_t* shared_key, const int alg_ids[AUTH_LAYER_COUNT], const AuthPacket& packet, uint8_t* decrypted_text_out = nullptr, uint8_t (*calculated_tags_out)[AUTH_MAX_TAG_BYTES] = nullptr);
    bool GeneratePayload(const uint8_t* shared_key, const int alg_ids[AUTH_LAYER_COUNT], const uint8_t* plaintext, AuthPacket& out_packet);
    bool GeneratePayloadWithVault(uint64_t current_timestamp, const int alg_ids[AUTH_LAYER_COUNT], const uint8_t* plaintext, AuthPacket& out_packet);
    bool VerifyPayloadWithVault(uint64_t current_timestamp, const int alg_ids[AUTH_LAYER_COUNT], const AuthPacket& packet, uint8_t* decrypted_text_out = nullptr, uint8_t (*calculated_tags_out)[AUTH_MAX_TAG_BYTES] = nullptr);

    const AuthCryptoTrace& GetLastCryptoTrace();

} // namespace AuthApi

#endif // AUTH_API_H
