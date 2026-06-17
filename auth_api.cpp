#include "auth_api.h"
#include "key_vault.h"
#include <cstring>
#include <iostream>
#include <array>
#include <span>
#include <thread>
#include <functional>

// 算法头文件
#include "TinyJAMBU/include/tinyjambu_128.hpp"
#include "TinyJAMBU/include/tinyjambu_192.hpp"
#include "TinyJAMBU/include/tinyjambu_256.hpp"
#include "Sparkle/include/schwaemm128_128.hpp"
#include "Sparkle/include/schwaemm192_192.hpp"
#include "Sparkle/include/schwaemm256_256.hpp"
#include "LEA-CCM/ccm.h"

namespace AuthApi {

const uint8_t FIXED_NONCE[AUTH_MAX_NONCE_BYTES] = {
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,
    0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,
    0x10,0x21,0x32,0x43,0x54,0x65,0x76,0x87,
    0x98,0xA9,0xBA,0xCB,0xDC,0xED,0xFE,0x0F
};

// --- 内部核心逻辑：执行单个算法的加解密/校验 ---

static uint8_t dummy_data[1] = {0};
static thread_local AuthCryptoTrace G_LAST_TRACE = {};

const AuthCryptoTrace& GetLastCryptoTrace() {
    return G_LAST_TRACE;
}

static void ResetTrace(int operation) {
    std::memset(&G_LAST_TRACE, 0, sizeof(G_LAST_TRACE));
    G_LAST_TRACE.valid = 1;
    G_LAST_TRACE.operation = operation;
}

static void AddTraceStep(int logical_layer,
                         int alg_id,
                         int direction,
                         int status,
                         const uint8_t* input,
                         const uint8_t* output,
                         const uint8_t* tag,
                         uint64_t worker_thread_hash = 0) {
    if (G_LAST_TRACE.step_count >= AUTH_TRACE_MAX_STEPS) return;
    AuthCryptoTraceStep& step = G_LAST_TRACE.steps[G_LAST_TRACE.step_count++];
    step.logical_layer = logical_layer;
    step.alg_id = alg_id;
    step.direction = direction;
    step.status = status;
    step.worker_thread_hash = worker_thread_hash;
    if (input) std::memcpy(step.input, input, AUTH_CIPHERTEXT_BYTES);
    if (output) std::memcpy(step.output, output, AUTH_CIPHERTEXT_BYTES);
    if (tag) std::memcpy(step.tag, tag, AUTH_MAX_TAG_BYTES);
}

struct ParallelLayerResult {
    bool ok = false;
    uint64_t worker_thread_hash = 0;
    uint8_t input[AUTH_CIPHERTEXT_BYTES] = {};
    uint8_t output[AUTH_CIPHERTEXT_BYTES] = {};
    uint8_t tag[AUTH_MAX_TAG_BYTES] = {};
};

static uint64_t CurrentThreadHash() {
    return static_cast<uint64_t>(std::hash<std::thread::id>{}(std::this_thread::get_id()));
}

static bool LeaCcmProcess(bool encrypt, int key_bits, const uint8_t* key, const uint8_t* tag_in_out,
                          const uint8_t* ad, size_t ad_len, const uint8_t* pt_in_ct_out,
                          size_t data_len, uint8_t* out_buf) {
    // LEA-CCM uses 12-byte nonce and 16-byte tag in this subsystem.
    return lea_ccm::lea_ccm_process(
        encrypt, key_bits, key, FIXED_NONCE, ad, ad_len,
        pt_in_ct_out, data_len, out_buf, const_cast<uint8_t*>(tag_in_out));
}

static bool InternalProcess(bool encrypt, int id, const uint8_t* key, const uint8_t* tag_in_out, const uint8_t* ad, size_t ad_len, const uint8_t* pt_in_ct_out, size_t data_len, uint8_t* out_buf) {
    // 安全保护：如果长度为0但指针为空，指向哑数据防止算法库崩溃
    const uint8_t* safe_ad = (ad_len > 0) ? ad : dummy_data;
    const uint8_t* safe_pt = (data_len > 0) ? pt_in_ct_out : dummy_data;
    uint8_t* safe_out = (data_len > 0) ? out_buf : dummy_data;

    switch(id) {
        case 11:
            if (encrypt) { tinyjambu_128::encrypt(key, FIXED_NONCE, safe_ad, ad_len, safe_pt, safe_out, data_len, (uint8_t*)tag_in_out); return true; }
            else { return tinyjambu_128::decrypt(key, FIXED_NONCE, tag_in_out, safe_ad, ad_len, safe_pt, safe_out, data_len); }
        case 12:
            if (encrypt) { tinyjambu_192::encrypt(key, FIXED_NONCE, safe_ad, ad_len, safe_pt, safe_out, data_len, (uint8_t*)tag_in_out); return true; }
            else { return tinyjambu_192::decrypt(key, FIXED_NONCE, tag_in_out, safe_ad, ad_len, safe_pt, safe_out, data_len); }
        case 13:
            if (encrypt) { tinyjambu_256::encrypt(key, FIXED_NONCE, safe_ad, ad_len, safe_pt, safe_out, data_len, (uint8_t*)tag_in_out); return true; }
            else { return tinyjambu_256::decrypt(key, FIXED_NONCE, tag_in_out, safe_ad, ad_len, safe_pt, safe_out, data_len); }
        case 21:
            if (encrypt) { schwaemm128_128::encrypt(key, FIXED_NONCE, safe_ad, ad_len, safe_pt, safe_out, data_len, (uint8_t*)tag_in_out); return true; }
            else { return schwaemm128_128::decrypt(key, FIXED_NONCE, tag_in_out, safe_ad, ad_len, safe_pt, safe_out, data_len); }
        case 22:
            if (encrypt) { schwaemm192_192::encrypt(key, FIXED_NONCE, safe_ad, ad_len, safe_pt, safe_out, data_len, (uint8_t*)tag_in_out); return true; }
            else { return schwaemm192_192::decrypt(key, FIXED_NONCE, tag_in_out, safe_ad, ad_len, safe_pt, safe_out, data_len); }
        case 23:
            if (encrypt) { schwaemm256_256::encrypt(key, FIXED_NONCE, safe_ad, ad_len, safe_pt, safe_out, data_len, (uint8_t*)tag_in_out); return true; }
            else { return schwaemm256_256::decrypt(key, FIXED_NONCE, tag_in_out, safe_ad, ad_len, safe_pt, safe_out, data_len); }
        case 31:
            return LeaCcmProcess(encrypt, 128, key, tag_in_out, safe_ad, ad_len, safe_pt, data_len, safe_out);
        case 32:
            return LeaCcmProcess(encrypt, 192, key, tag_in_out, safe_ad, ad_len, safe_pt, data_len, safe_out);
        case 33:
            return LeaCcmProcess(encrypt, 256, key, tag_in_out, safe_ad, ad_len, safe_pt, data_len, safe_out);
        default: return false;
    }
}

static bool RunParallelEncrypt(const uint8_t* shared_key,
                               const int alg_ids[AUTH_LAYER_COUNT],
                               const uint8_t* plaintext,
                               uint8_t ciphertexts[AUTH_LAYER_COUNT][AUTH_CIPHERTEXT_BYTES],
                               uint8_t tags[AUTH_LAYER_COUNT][AUTH_MAX_TAG_BYTES],
                               bool record_trace) {
    uint8_t ad_empty[32] = {0};
    std::memset(ciphertexts, 0, AUTH_LAYER_COUNT * AUTH_CIPHERTEXT_BYTES);
    std::memset(tags, 0, AUTH_LAYER_COUNT * AUTH_MAX_TAG_BYTES);

    ParallelLayerResult results[AUTH_LAYER_COUNT];
    std::thread workers[AUTH_LAYER_COUNT];

    for (int i = 0; i < AUTH_LAYER_COUNT; ++i) {
        workers[i] = std::thread([&, i]() {
            results[i].worker_thread_hash = CurrentThreadHash();
            std::memcpy(results[i].input, plaintext, AUTH_CIPHERTEXT_BYTES);
            results[i].ok = InternalProcess(true, alg_ids[i], shared_key, tags[i], ad_empty, sizeof(ad_empty),
                                            plaintext, AUTH_CIPHERTEXT_BYTES, ciphertexts[i]);
            if (!results[i].ok) {
                std::memset(ciphertexts[i], 0, AUTH_CIPHERTEXT_BYTES);
                std::memset(tags[i], 0, AUTH_MAX_TAG_BYTES);
            }
            std::memcpy(results[i].output, ciphertexts[i], AUTH_CIPHERTEXT_BYTES);
            std::memcpy(results[i].tag, tags[i], AUTH_MAX_TAG_BYTES);
        });
    }

    bool all_ok = true;
    for (int i = 0; i < AUTH_LAYER_COUNT; ++i) {
        workers[i].join();
        if (!results[i].ok) all_ok = false;
    }

    if (record_trace) {
        for (int i = 0; i < AUTH_LAYER_COUNT; ++i) {
            AddTraceStep(i, alg_ids[i], 1, results[i].ok ? 1 : 0,
                         results[i].input, results[i].output, results[i].tag,
                         results[i].worker_thread_hash);
        }
    }
    return all_ok;
}

static bool RunParallelDecrypt(const uint8_t* shared_key,
                               const int alg_ids[AUTH_LAYER_COUNT],
                               const uint8_t ciphertexts[AUTH_LAYER_COUNT][AUTH_CIPHERTEXT_BYTES],
                               const uint8_t tags[AUTH_LAYER_COUNT][AUTH_MAX_TAG_BYTES],
                               uint8_t plaintexts_out[AUTH_LAYER_COUNT][AUTH_CIPHERTEXT_BYTES],
                               bool layer_ok_out[AUTH_LAYER_COUNT],
                               bool record_trace) {
    uint8_t ad_empty[32] = {0};
    std::memset(plaintexts_out, 0, AUTH_LAYER_COUNT * AUTH_CIPHERTEXT_BYTES);
    for (int i = 0; i < AUTH_LAYER_COUNT; ++i) layer_ok_out[i] = false;

    ParallelLayerResult results[AUTH_LAYER_COUNT];
    std::thread workers[AUTH_LAYER_COUNT];

    for (int i = 0; i < AUTH_LAYER_COUNT; ++i) {
        workers[i] = std::thread([&, i]() {
            results[i].worker_thread_hash = CurrentThreadHash();
            std::memcpy(results[i].input, ciphertexts[i], AUTH_CIPHERTEXT_BYTES);
            std::memcpy(results[i].tag, tags[i], AUTH_MAX_TAG_BYTES);
            results[i].ok = InternalProcess(false, alg_ids[i], shared_key, tags[i], ad_empty, sizeof(ad_empty),
                                            ciphertexts[i], AUTH_CIPHERTEXT_BYTES, plaintexts_out[i]);
            if (!results[i].ok) {
                std::memset(plaintexts_out[i], 0, AUTH_CIPHERTEXT_BYTES);
            }
            std::memcpy(results[i].output, plaintexts_out[i], AUTH_CIPHERTEXT_BYTES);
        });
    }

    bool all_ok = true;
    for (int i = 0; i < AUTH_LAYER_COUNT; ++i) {
        workers[i].join();
        layer_ok_out[i] = results[i].ok;
        if (!results[i].ok) all_ok = false;
    }

    if (record_trace) {
        for (int i = 0; i < AUTH_LAYER_COUNT; ++i) {
            AddTraceStep(i, alg_ids[i], 0, results[i].ok ? 1 : 0,
                         results[i].input, results[i].output, results[i].tag,
                         results[i].worker_thread_hash);
        }
    }
    return all_ok;
}

// --- 公开接口：三算法并行加密 / 并行解密逻辑 ---

bool VerifyPayload(const uint8_t* shared_key, const int alg_ids[AUTH_LAYER_COUNT], const AuthPacket& packet, uint8_t* decrypted_text_out, uint8_t (*calculated_tags_out)[AUTH_MAX_TAG_BYTES]) {
    ResetTrace(0);

    uint8_t plaintexts[AUTH_LAYER_COUNT][AUTH_CIPHERTEXT_BYTES] = {};
    bool layer_ok[AUTH_LAYER_COUNT] = {};
    bool decrypt_all_ok = RunParallelDecrypt(shared_key, alg_ids, packet.ciphertexts, packet.tags, plaintexts, layer_ok, true);

    int reference_layer = -1;
    uint8_t reference_plaintext[AUTH_CIPHERTEXT_BYTES] = {};
    for (int i = 0; i < AUTH_LAYER_COUNT; ++i) {
        if (layer_ok[i]) {
            reference_layer = i;
            std::memcpy(reference_plaintext, plaintexts[i], AUTH_CIPHERTEXT_BYTES);
            break;
        }
    }

    if (reference_layer < 0) {
        if (calculated_tags_out) {
            std::memset(calculated_tags_out, 0, AUTH_LAYER_COUNT * AUTH_MAX_TAG_BYTES);
        }
        return false;
    }

    bool plaintexts_match = true;
    for (int i = 0; i < AUTH_LAYER_COUNT; ++i) {
        if (!layer_ok[i] || std::memcmp(plaintexts[i], reference_plaintext, AUTH_CIPHERTEXT_BYTES) != 0) {
            plaintexts_match = false;
            break;
        }
    }

    uint8_t reencrypted[AUTH_LAYER_COUNT][AUTH_CIPHERTEXT_BYTES] = {};
    uint8_t recalculated_tags[AUTH_LAYER_COUNT][AUTH_MAX_TAG_BYTES] = {};
    bool reencrypt_ok = RunParallelEncrypt(shared_key, alg_ids, reference_plaintext, reencrypted, recalculated_tags, false);
    if (!reencrypt_ok) {
        if (calculated_tags_out) {
            std::memset(calculated_tags_out, 0, AUTH_LAYER_COUNT * AUTH_MAX_TAG_BYTES);
        }
        return false;
    }

    if (calculated_tags_out) {
        std::memcpy(calculated_tags_out, recalculated_tags, AUTH_LAYER_COUNT * AUTH_MAX_TAG_BYTES);
    }

    bool ciphertexts_match = true;
    bool tags_match = true;
    for (int i = 0; i < AUTH_LAYER_COUNT; ++i) {
        if (std::memcmp(reencrypted[i], packet.ciphertexts[i], AUTH_CIPHERTEXT_BYTES) != 0) {
            ciphertexts_match = false;
        }
        if (std::memcmp(recalculated_tags[i], packet.tags[i], AUTH_MAX_TAG_BYTES) != 0) {
            tags_match = false;
        }
    }

    if (decrypted_text_out) {
        std::memcpy(decrypted_text_out, reference_plaintext, AUTH_CIPHERTEXT_BYTES);
    }
    return decrypt_all_ok && plaintexts_match && ciphertexts_match && tags_match;
}

bool GeneratePayload(const uint8_t* shared_key, const int alg_ids[AUTH_LAYER_COUNT], const uint8_t* plaintext, AuthPacket& out_packet) {
    std::memset(&out_packet, 0, sizeof(AuthPacket));
    ResetTrace(1);

    return RunParallelEncrypt(shared_key, alg_ids, plaintext, out_packet.ciphertexts, out_packet.tags, true);
}

bool GeneratePayloadWithVault(uint64_t current_timestamp, const int alg_ids[AUTH_LAYER_COUNT], const uint8_t* plaintext, AuthPacket& out_packet) {
    const uint8_t* key = KeyVault::GetInstance().GetCurrentKey(current_timestamp);
    if (!key) return false;
    return GeneratePayload(key, alg_ids, plaintext, out_packet);
}

bool VerifyPayloadWithVault(uint64_t current_timestamp, const int alg_ids[AUTH_LAYER_COUNT], const AuthPacket& packet, uint8_t* decrypted_text_out, uint8_t (*calculated_tags_out)[AUTH_MAX_TAG_BYTES]) {
    auto tolerant_keys = KeyVault::GetInstance().GetTolerantKeys(current_timestamp);
    for (const uint8_t* candidate_key : tolerant_keys) {
        if (VerifyPayload(candidate_key, alg_ids, packet, decrypted_text_out, calculated_tags_out)) {
            return true;
        }
    }
    return false;
}

} // namespace AuthApi

// -----------------------------------------------------------------------------
// LEA-CCM is embedded into this translation unit intentionally.
// The deployment build command used by the integration system compiles only:
//   libauth.cpp key_vault.cpp auth_api.cpp
// Keeping these includes here makes LEA-CCM behave like the other header-based
// algorithm implementations in this project: no extra .cpp file is required on
// the compiler command line.
// -----------------------------------------------------------------------------
#include "LEA-CCM/lea.cpp"
#include "LEA-CCM/ccm.cpp"
