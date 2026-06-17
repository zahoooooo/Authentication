#include "libauth.h"
#include "auth_api.h"
#include "key_vault.h"
#include <cstring>
#include <cctype>
#include <cstdio>
#include <iostream>
#include <stdlib.h>
#include <array>
#include <ctime>
#include <iomanip>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <random>
#include <arpa/inet.h>

// --- 全局变量模式 (内部管理) ---
uint32_t G_ENC_ID = 0x0B0C0D01;
int G_ATTACK_ID = 0;
int G_HIGH_LOAD_ID = 0;
std::vector<int> G_ALLOWED_ALGS_POOL = {11, 12, 13, 21, 22, 23, 31, 32, 33};
int G_MANDATORY_ALGS[3] = {0, 0, 0};
uint64_t G_FIXED_TIMESTAMP = 0;

static const int G_DEFAULT_ALGS[3] = {12, 22, 32}; // 正常模式：三组 192 位算法
static const int G_SECURE_ALGS[3]  = {13, 23, 33}; // 攻击模式：三组 256 位算法
static const int G_FAST_ALGS[3]    = {11, 21, 31}; // 高负载模式：三组 128 位算法

// 辅助函数：根据 ID 获取算法名称
const char* get_algorithm_name(uint8_t id) {
    switch(id) {
        case 11: return "TinyJAMBU-128";
        case 12: return "TinyJAMBU-192";
        case 13: return "TinyJAMBU-256";
        case 21: return "SCHWAEMM128-128";
        case 22: return "SCHWAEMM192-192";
        case 23: return "SCHWAEMM256-256";
        case 31: return "LEA-CCM-128";
        case 32: return "LEA-CCM-192";
        case 33: return "LEA-CCM-256";
        default: return "Unknown";
    }
}

static void set_mandatory_algs(const int algs[3]) {
    G_MANDATORY_ALGS[0] = algs[0];
    G_MANDATORY_ALGS[1] = algs[1];
    G_MANDATORY_ALGS[2] = algs[2];
}

static void clear_mandatory_algs() {
    G_MANDATORY_ALGS[0] = 0;
    G_MANDATORY_ALGS[1] = 0;
    G_MANDATORY_ALGS[2] = 0;
}

static bool same_algs(const int a[3], const int b[3]) {
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2];
}

static std::string make_force_algs_signal(const int algs[3]) {
    std::ostringstream oss;
    oss << "CMD_FORCE_ALGS:" << algs[0] << "," << algs[1] << "," << algs[2];
    return oss.str();
}

static std::string make_retry_config_mismatch_signal(const int algs[3]) {
    std::ostringstream oss;
    oss << "CMD_RETRY_CONFIG_MISMATCH:" << algs[0] << "," << algs[1] << "," << algs[2];
    return oss.str();
}

static bool is_known_algorithm_id(int id) {
    switch (id) {
        case 11: case 12: case 13:
        case 21: case 22: case 23:
        case 31: case 32: case 33:
            return true;
        default:
            return false;
    }
}

// Parse algorithm id lists in a tolerant way.
// Supported examples:
//   "11,21,31"
//   "11 21 31"
//   "11, 21, 31"
//   "11;21;31"
// This is important because test_tool_repro may input the pool with spaces,
// while the re-auth signal normally uses commas.
static std::vector<int> parse_algorithm_id_list(const std::string& text, bool unique_only = true) {
    std::string normalized;
    normalized.reserve(text.size());

    for (char c : text) {
        unsigned char uc = static_cast<unsigned char>(c);
        if (std::isdigit(uc) || c == '-' || c == '+') {
            normalized.push_back(c);
        } else {
            normalized.push_back(' ');
        }
    }

    std::vector<int> ids;
    std::stringstream ss(normalized);
    int id = 0;
    while (ss >> id) {
        if (!is_known_algorithm_id(id)) {
            continue;
        }
        if (unique_only && std::find(ids.begin(), ids.end(), id) != ids.end()) {
            continue;
        }
        ids.push_back(id);
    }
    return ids;
}

static bool parse_three_alg_ids(const std::string& ids_str, int out_ids[3]) {
    if (!out_ids) return false;
    std::vector<int> ids = parse_algorithm_id_list(ids_str, true);
    if (ids.size() < 3) return false;
    out_ids[0] = ids[0];
    out_ids[1] = ids[1];
    out_ids[2] = ids[2];
    return true;
}

static bool is_full_algorithm_pool(const std::vector<int>& pool) {
    static const int all_algs[AUTH_ALGORITHM_SECURITY_COUNT] = {11, 12, 13, 21, 22, 23, 31, 32, 33};
    for (int id : all_algs) {
        if (std::find(pool.begin(), pool.end(), id) == pool.end()) {
            return false;
        }
    }
    return true;
}

static bool select_random_algs_from_pool_vector(const std::vector<int>& source_pool, int selected_ids[3]) {
    if (!selected_ids) return false;

    std::vector<int> pool;
    for (int id : source_pool) {
        if (std::find(pool.begin(), pool.end(), id) == pool.end()) {
            pool.push_back(id);
        }
    }
    if (pool.size() < 3) return false;

    static std::mt19937 g(static_cast<uint32_t>(std::time(nullptr)));
    std::shuffle(pool.begin(), pool.end(), g);
    selected_ids[0] = pool[0];
    selected_ids[1] = pool[1];
    selected_ids[2] = pool[2];
    return true;
}

static std::string make_mode_signal_for_algs(const int algs[3]) {
    if (same_algs(algs, G_SECURE_ALGS)) return "CMD_ATTACK_MODE";
    if (same_algs(algs, G_FAST_ALGS)) return "CMD_HIGH_LOAD";
    if (same_algs(algs, G_DEFAULT_ALGS)) return "CMD_NORMAL_MODE";
    return make_force_algs_signal(algs);
}

static void write_re_auth_signal(struct re_auth *re_auth_info, const std::string& signal) {
    if (!re_auth_info) return;
    re_auth_info->auth_len = static_cast<unsigned int>(signal.size());
    std::strncpy(re_auth_info->auth_data, signal.c_str(), sizeof(re_auth_info->auth_data) - 1);
    re_auth_info->auth_data[sizeof(re_auth_info->auth_data) - 1] = '\0';
}

// 算法客观参数表：只保留 family/key/nonce/tag。
// 不包含推荐、评分、等级、优势/限制说明或中文展示文案。
static const auth_algorithm_security_info G_ALGORITHM_SECURITY_TABLE[AUTH_ALGORITHM_SECURITY_COUNT] = {
    {11, "TinyJAMBU-128",  "TinyJAMBU", 128,  96,  64},
    {12, "TinyJAMBU-192",  "TinyJAMBU", 192,  96,  64},
    {13, "TinyJAMBU-256",  "TinyJAMBU", 256,  96,  64},

    {21, "SCHWAEMM128-128", "SCHWAEMM", 128, 128, 128},
    {22, "SCHWAEMM192-192", "SCHWAEMM", 192, 192, 192},
    {23, "SCHWAEMM256-256", "SCHWAEMM", 256, 256, 256},

    {31, "LEA-CCM-128", "LEA-CCM", 128, 96, 128},
    {32, "LEA-CCM-192", "LEA-CCM", 192, 96, 128},
    {33, "LEA-CCM-256", "LEA-CCM", 256, 96, 128}
};

static const auth_algorithm_security_info* find_algorithm_security_info(int id) {
    for (int i = 0; i < AUTH_ALGORITHM_SECURITY_COUNT; ++i) {
        if (G_ALGORITHM_SECURITY_TABLE[i].alg_id == id) {
            return &G_ALGORITHM_SECURITY_TABLE[i];
        }
    }
    return nullptr;
}

static int get_algorithm_tag_bits(int id) {
    const auto* info = find_algorithm_security_info(id);
    return info ? info->tag_bits : AUTH_MAX_TAG_BYTES * 8;
}

// 辅助函数：拼接三个算法的名称
std::string format_alg_combo(int a, int b, int c) {
    return std::string(get_algorithm_name(a)) + "+" + get_algorithm_name(b) + "+" + get_algorithm_name(c);
}


std::string format_alg_combo_ids(int a, int b, int c) {
    return "[" + std::to_string(a) + "," + std::to_string(b) + "," + std::to_string(c) + "]";
}

// --- 老系统 GLIBC 2.14 兼容补丁 ---
extern "C" void* aligned_alloc(size_t alignment, size_t size) {
    void* ptr = NULL;
    if (posix_memalign(&ptr, alignment, size) != 0) { return NULL; }
    return ptr;
}

extern "C" {


static std::string json_escape(const char* input) {
    std::ostringstream escaped;
    if (!input) return "";
    for (const unsigned char* p = reinterpret_cast<const unsigned char*>(input); *p; ++p) {
        switch (*p) {
            case '"': escaped << "\\\""; break;
            case '\\': escaped << "\\\\"; break;
            case '\b': escaped << "\\b"; break;
            case '\f': escaped << "\\f"; break;
            case '\n': escaped << "\\n"; break;
            case '\r': escaped << "\\r"; break;
            case '\t': escaped << "\\t"; break;
            default:
                if (*p < 0x20) {
                    char buf[7];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", *p);
                    escaped << buf;
                } else {
                    escaped << static_cast<char>(*p);
                }
        }
    }
    return escaped.str();
}


int auth_get_algorithm_security_info(struct auth_algorithm_security_info *out_infos, int max_count) {
    if (!out_infos || max_count <= 0) {
        return AUTH_ALGORITHM_SECURITY_COUNT;
    }
    int count = std::min(max_count, AUTH_ALGORITHM_SECURITY_COUNT);
    for (int i = 0; i < count; ++i) {
        out_infos[i] = G_ALGORITHM_SECURITY_TABLE[i];
    }
    return count;
}

const char* auth_get_algorithm_security_json() {
    static std::string json;
    std::ostringstream oss;
    oss << "[";
    for (int i = 0; i < AUTH_ALGORITHM_SECURITY_COUNT; ++i) {
        const auto& item = G_ALGORITHM_SECURITY_TABLE[i];
        if (i > 0) oss << ",";
        oss << "{"
            << "\"alg_id\":" << item.alg_id << ","
            << "\"name\":\"" << json_escape(item.name) << "\"," 
            << "\"family\":\"" << json_escape(item.family) << "\"," 
            << "\"key_bits\":" << item.key_bits << ","
            << "\"nonce_bits\":" << item.nonce_bits << ","
            << "\"tag_bits\":" << item.tag_bits
            << "}";
    }
    oss << "]";
    json = oss.str();
    return json.c_str();
}

int auth_init() {
    AuthApi::KeyVault::GetInstance().Initialize(0x12345678);
    std::cout << "[Auth Module] init success (receiver mode). key seed ready." << std::endl;
    std::cout << "[Auth Module] policy mode: trust sender policy id." << std::endl;
    std::cout << "[Auth Module] worker mode: parallel_3_threads_only (no fork/process workers)." << std::endl;
    return 0;
}

void auth_set_allowed_algs(const char* pool_str) {
    if (!pool_str) return;

    std::vector<int> parsed_pool = parse_algorithm_id_list(std::string(pool_str), true);

    G_ALLOWED_ALGS_POOL.clear();
    G_ALLOWED_ALGS_POOL.insert(G_ALLOWED_ALGS_POOL.end(), parsed_pool.begin(), parsed_pool.end());
    clear_mandatory_algs();
    G_ATTACK_ID = 0;
    G_HIGH_LOAD_ID = 0;

    std::cout << "[Auth Module] allowed algorithm pool updated; mandatory modes cleared: ";
    for (size_t i = 0; i < G_ALLOWED_ALGS_POOL.size(); ++i) {
        if (i) std::cout << ",";
        std::cout << G_ALLOWED_ALGS_POOL[i];
    }
    if (G_ALLOWED_ALGS_POOL.empty()) {
        std::cout << "<empty>";
    }
    std::cout << std::endl;
}

void auth_set_attack_mode(int mode, struct re_auth *re_auth_info) {
    G_ATTACK_ID = mode;
    if (mode != 0) {
        std::cout << "[Auth Module] attack mode enabled; require 256-bit algorithms (13,23,33); pool unchanged" << std::endl;
        G_HIGH_LOAD_ID = 0;
        set_mandatory_algs(G_SECURE_ALGS);
        write_re_auth_signal(re_auth_info, "CMD_ATTACK_MODE");
    } else {
        std::cout << "[Auth Module] attack mode disabled" << std::endl;
        if (re_auth_info) { re_auth_info->auth_len = 0; re_auth_info->auth_data[0] = '\0'; }
        G_ATTACK_ID = 0;
        if (G_HIGH_LOAD_ID == 0) clear_mandatory_algs();
    }
}

void auth_set_high_load_mode(int mode, struct re_auth *re_auth_info) {
    G_HIGH_LOAD_ID = mode;
    if (mode != 0) {
        std::cout << "[Auth Module] high-load mode enabled; require 128-bit algorithms (11,21,31); pool unchanged" << std::endl;
        G_ATTACK_ID = 0;
        set_mandatory_algs(G_FAST_ALGS);
        write_re_auth_signal(re_auth_info, "CMD_HIGH_LOAD");
    } else {
        std::cout << "[Auth Module] high-load mode disabled" << std::endl;
        if (re_auth_info) { re_auth_info->auth_len = 0; re_auth_info->auth_data[0] = '\0'; }
        G_HIGH_LOAD_ID = 0;
        if (G_ATTACK_ID == 0) clear_mandatory_algs();
    }
}

void auth_set_normal_mode(struct re_auth *re_auth_info) {
    std::cout << "[Auth Module] normal mode restored; require 192-bit algorithms (12,22,32); pool unchanged" << std::endl;
    G_ATTACK_ID = 0;
    G_HIGH_LOAD_ID = 0;
    set_mandatory_algs(G_DEFAULT_ALGS);
    write_re_auth_signal(re_auth_info, "CMD_NORMAL_MODE");
}

void auth_set_timestamp(uint64_t ts) {
    G_FIXED_TIMESTAMP = ts;
    if (ts != 0) std::cout << "[Auth Module] timestamp locked at: " << ts << " (anti-replay temporarily disabled)" << std::endl;
    else std::cout << "[Auth Module] timestamp restored to realtime mode (anti-replay enabled)" << std::endl;
}


static uint16_t read_be16(const uint8_t* p) {
    return (static_cast<uint16_t>(p[0]) << 8) | static_cast<uint16_t>(p[1]);
}

static std::string json_escape_str(const std::string& in) {
    std::ostringstream oss;
    for (unsigned char c : in) {
        switch (c) {
            case '"': oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            case '\b': oss << "\\b"; break;
            case '\f': oss << "\\f"; break;
            case '\n': oss << "\\n"; break;
            case '\r': oss << "\\r"; break;
            case '\t': oss << "\\t"; break;
            default:
                if (c < 0x20) {
                    oss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c)
                        << std::dec << std::setfill(' ');
                } else {
                    oss << static_cast<char>(c);
                }
        }
    }
    return oss.str();
}

static std::string bytes_to_hex_string(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

static std::string printable_preview(const uint8_t* data, size_t len) {
    std::string out;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = data[i];
        if (c == 0) break;
        if (c >= 32 && c <= 126) out.push_back(static_cast<char>(c));
        else out.push_back('.');
    }
    return out;
}

static std::string pretty_json_for_decode_msg(const std::string& in) {
    std::string out;
    out.reserve(in.size() + 256);
    int indent = 0;
    bool in_string = false;
    bool escape = false;

    auto newline = [&]() {
        out.push_back('\n');
        out.append(static_cast<size_t>(indent) * 2, ' ');
    };

    for (char c : in) {
        if (in_string) {
            out.push_back(c);
            if (escape) {
                escape = false;
            } else if (c == '\\') {
                escape = true;
            } else if (c == '"') {
                in_string = false;
            }
            continue;
        }

        switch (c) {
            case '"':
                in_string = true;
                out.push_back(c);
                break;
            case '{':
            case '[':
                out.push_back(c);
                ++indent;
                newline();
                break;
            case '}':
            case ']':
                if (indent > 0) --indent;
                newline();
                out.push_back(c);
                break;
            case ',':
                out.push_back(c);
                newline();
                break;
            case ':':
                out += ": ";
                break;
            default:
                if (!std::isspace(static_cast<unsigned char>(c))) out.push_back(c);
                break;
        }
    }
    return out;
}

static const char* trace_direction_name(int direction) {
    if (direction == 1) return "encrypt";
    if (direction == 0) return "decrypt";
    return "skipped";
}

static const char* trace_status_name(int status) {
    if (status == 1) return "ok";
    if (status == 0) return "fail";
    return "skipped";
}

static int trace_status_for_layer(const AuthApi::AuthCryptoTrace& trace, int logical_layer) {
    if (!trace.valid) return -2;
    for (int i = 0; i < trace.step_count && i < AUTH_TRACE_MAX_STEPS; ++i) {
        const auto& step = trace.steps[i];
        if (step.logical_layer == logical_layer) {
            return step.status;
        }
    }
    return -2;
}

static std::string build_crypto_trace_json(const AuthApi::AuthCryptoTrace& trace) {
    std::ostringstream oss;
    if (!trace.valid) {
        oss << "null";
        return oss.str();
    }

    oss << "{";
    oss << "\"operation\":\"" << (trace.operation == 1 ? "generate_parallel_encrypt" : "verify_parallel_decrypt") << "\",";
    oss << "\"execution_mode\":\"parallel_3_threads\",";
    oss << "\"step_count\":" << trace.step_count << ",";
    oss << "\"steps\":[";
    for (int i = 0; i < trace.step_count && i < AUTH_TRACE_MAX_STEPS; ++i) {
        const auto& step = trace.steps[i];
        if (i > 0) oss << ",";
        int tag_bytes = (get_algorithm_tag_bits(step.alg_id) + 7) / 8;
        if (tag_bytes < 0) tag_bytes = 0;
        if (tag_bytes > AUTH_MAX_TAG_BYTES) tag_bytes = AUTH_MAX_TAG_BYTES;
        oss << "{";
        oss << "\"trace_index\":" << i << ",";
        oss << "\"logical_layer\":" << (step.logical_layer + 1) << ",";
        oss << "\"alg_id\":" << step.alg_id << ",";
        oss << "\"algorithm_name\":\"" << json_escape(get_algorithm_name(step.alg_id)) << "\",";
        oss << "\"direction\":\"" << trace_direction_name(step.direction) << "\",";
        oss << "\"status\":\"" << trace_status_name(step.status) << "\",";
        oss << "\"worker_thread_hash\":\"" << std::hex << step.worker_thread_hash << std::dec << "\",";
        oss << "\"input_hex\":\"" << bytes_to_hex_string(step.input, AUTH_CIPHERTEXT_BYTES) << "\",";
        oss << "\"output_hex\":\"" << bytes_to_hex_string(step.output, AUTH_CIPHERTEXT_BYTES) << "\",";
        oss << "\"tag_hex\":\"" << bytes_to_hex_string(step.tag, static_cast<size_t>(tag_bytes)) << "\"";
        oss << "}";
    }
    oss << "]}";
    return oss.str();
}

struct ParsedIpv6AuthPacket {
    const uint8_t* auth_payload = nullptr;
    unsigned int auth_len = 0;
    bool has_ethernet = false;
    bool has_ipv6 = false;
    unsigned int ethernet_offset = 0;
    unsigned int ipv6_offset = 0;
    unsigned int auth_offset = 0;
    unsigned int ipv6_payload_length = 0;
    int ipv6_next_header = -1;
    int ipv6_hop_limit = -1;
    char src_ip[INET6_ADDRSTRLEN] = {0};
    char dst_ip[INET6_ADDRSTRLEN] = {0};
    std::string input_format;
    std::string error;
};

static ParsedIpv6AuthPacket parse_ipv6_auth_input(const uint8_t* data, unsigned int data_len) {
    ParsedIpv6AuthPacket parsed;
    if (!data) {
        parsed.error = "null data pointer";
        return parsed;
    }
    unsigned int offset = 0;
    if (data_len >= 14) {
        uint16_t ether_type = read_be16(data + 12);
        if (ether_type == 0x86dd) {
            parsed.has_ethernet = true;
            parsed.ethernet_offset = 0;
            offset = 14;
        }
    }

    if (data_len >= offset + 40 && ((data[offset] >> 4) == 6)) {
        parsed.has_ipv6 = true;
        parsed.ipv6_offset = offset;
        parsed.ipv6_payload_length = read_be16(data + offset + 4);
        parsed.ipv6_next_header = data[offset + 6];
        parsed.ipv6_hop_limit = data[offset + 7];
        inet_ntop(AF_INET6, data + offset + 8, parsed.src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, data + offset + 24, parsed.dst_ip, INET6_ADDRSTRLEN);
        if (parsed.ipv6_next_header != 200) {
            std::ostringstream oss;
            oss << "IPv6 NextHeader is not auth value 200, actual=" << parsed.ipv6_next_header;
            parsed.error = oss.str();
            return parsed;
        }
        if (parsed.ipv6_payload_length < AUTH_PACKET_BYTES) {
            std::ostringstream oss;
            oss << "IPv6 payload too short, payload_len=" << parsed.ipv6_payload_length
                << " need=" << AUTH_PACKET_BYTES;
            parsed.error = oss.str();
            return parsed;
        }
        if (data_len < offset + 40 + AUTH_PACKET_BYTES) {
            std::ostringstream oss;
            oss << "input too short, len=" << data_len
                << " need=" << (offset + 40 + AUTH_PACKET_BYTES);
            parsed.error = oss.str();
            return parsed;
        }
        parsed.auth_offset = offset + 40;
        parsed.auth_payload = data + parsed.auth_offset;
        parsed.auth_len = AUTH_PACKET_BYTES;
        parsed.input_format = parsed.has_ethernet ? "ethernet_ipv6_auth_payload" : "ipv6_auth_payload";
        return parsed;
    }

    if (data_len >= offset + AUTH_PACKET_BYTES) {
        parsed.auth_offset = offset;
        parsed.auth_payload = data + offset;
        parsed.auth_len = AUTH_PACKET_BYTES;
        parsed.input_format = parsed.has_ethernet ? "ethernet_auth_payload" : "auth_payload";
        return parsed;
    }

    std::ostringstream oss;
    oss << "unable to parse as IPv6+AuthPacket or raw AuthPacket, len=" << data_len
        << " need=" << (offset + AUTH_PACKET_BYTES);
    parsed.error = oss.str();
    return parsed;
}

static std::string build_ipv6_auth_decode_json(
    const ParsedIpv6AuthPacket& parsed,
    unsigned int raw_len,
    const AuthPacket* packet,
    const uint8_t* decrypted_plaintext,
    bool has_decrypted_plaintext,
    int result,
    const auth_report_msg* report_msg,
    bool has_auth_result,
    const auth_audit_info* audit_info
) {
    (void)parsed;
    (void)raw_len;
    (void)decrypted_plaintext;
    (void)has_decrypted_plaintext;
    (void)result;
    (void)report_msg;
    (void)has_auth_result;

    // 对外 decode_msg 只保留并行模式下每个算法最终解密出的业务报文摘要，
    // 以及每个算法的 Tag 对比结论。
    // 逐层输入/输出密文等调试细节仍通过 auth_get_last_crypto_trace_json() 单独打印。
    std::ostringstream oss;
    oss << "{";
    oss << "\"decrypt_results\":[";

    const AuthApi::AuthCryptoTrace& trace = AuthApi::GetLastCryptoTrace();
    uint32_t policy_id = packet ? static_cast<uint32_t>(packet->policy_id) : 0;
    int alg_ids[AUTH_LAYER_COUNT] = {
        static_cast<int>((policy_id >> 24) & 0xFF),
        static_cast<int>((policy_id >> 16) & 0xFF),
        static_cast<int>((policy_id >> 8) & 0xFF)
    };

    for (int layer = 0; layer < AUTH_LAYER_COUNT; ++layer) {
        if (layer > 0) oss << ",";
        int alg_id = alg_ids[layer];
        const AuthApi::AuthCryptoTraceStep* step = nullptr;
        if (trace.valid) {
            for (int i = 0; i < trace.step_count && i < AUTH_TRACE_MAX_STEPS; ++i) {
                if (trace.steps[i].logical_layer == layer && trace.steps[i].direction == 0) {
                    step = &trace.steps[i];
                    break;
                }
            }
        }

        int tag_bytes = (get_algorithm_tag_bits(alg_id) + 7) / 8;
        if (tag_bytes < 0) tag_bytes = 0;
        if (tag_bytes > AUTH_MAX_TAG_BYTES) tag_bytes = AUTH_MAX_TAG_BYTES;

        bool ok = step && step->status == 1;
        std::string recv_tag_hex;
        std::string calc_tag_hex;
        bool tag_match = false;
        if (audit_info) {
            recv_tag_hex = audit_info->layers[layer].recv_tag_hex;
            calc_tag_hex = audit_info->layers[layer].calc_tag_hex;
            tag_match = (audit_info->layers[layer].status == 1);
        } else if (packet) {
            recv_tag_hex = bytes_to_hex_string(packet->tags[layer], static_cast<size_t>(tag_bytes));
        }

        oss << "{";
        oss << "\"layer\":" << (layer + 1) << ",";
        oss << "\"alg_id\":" << alg_id << ",";
        oss << "\"algorithm_name\":\"" << json_escape(get_algorithm_name(alg_id)) << "\",";
        oss << "\"recv_tag_hex\":\"" << recv_tag_hex << "\",";
        oss << "\"calc_tag_hex\":\"" << calc_tag_hex << "\",";
        oss << "\"tag_match\":" << (tag_match ? "true" : "false") << ",";
        oss << "\"status\":\"" << (ok ? "ok" : "fail") << "\",";
        oss << "\"auth_content\":";
        if (ok) {
            std::string auth_content = printable_preview(step->output, AUTH_CIPHERTEXT_BYTES);
            oss << "\"" << json_escape_str(auth_content) << "\"";
        } else {
            oss << "null";
        }
        oss << "}";
    }

    oss << "]}";
    return oss.str();
}

static void write_decode_msg(auth_decode_msg* decode_msg, const std::string& msg) {
    if (!decode_msg) return;
    std::string pretty = pretty_json_for_decode_msg(msg);
    std::memset(decode_msg->decode_msg, 0, AUTH_DECODE_MSG_BYTES);
    std::snprintf(decode_msg->decode_msg, AUTH_DECODE_MSG_BYTES, "%s", pretty.c_str());
}

int auth_policy_match(char *data, unsigned int data_len, struct re_auth *re_auth_info, struct auth_report_msg *report_msg, struct auth_audit_info *audit_info) {
    if (!data) {
        if (report_msg) strncpy(report_msg->report_msg, "ERROR: null data pointer", 255);
        return 0;
    }

    if (audit_info) {
        std::memset(audit_info, 0, sizeof(struct auth_audit_info));
        for(int i=0; i<3; i++) audit_info->layers[i].status = -1;
    }

    if (data_len < sizeof(AuthPacket)) {
        if (report_msg) strncpy(report_msg->report_msg, "ERROR: data too short", 255);
        return 0;
    }

    AuthPacket packet;
    std::memcpy(&packet, data, sizeof(AuthPacket));

    uint32_t policy_id = (uint32_t)packet.policy_id;
    int alg_ids[3];
    alg_ids[0] = (policy_id >> 24) & 0xFF;
    alg_ids[1] = (policy_id >> 16) & 0xFF;
    alg_ids[2] = (policy_id >> 8) & 0xFF;
    uint8_t control_byte = policy_id & 0xFF;

    if (control_byte == 0) {
        if (report_msg) { report_msg->flag = 0; report_msg->is_attack = 0; strncpy(report_msg->report_msg, "AUTH_DISABLED", 255); }
        return 1;
    }

    // --- 强制执行指令检查 ---
    if (G_MANDATORY_ALGS[0] != 0) {
        if (alg_ids[0] != G_MANDATORY_ALGS[0] || alg_ids[1] != G_MANDATORY_ALGS[1] || alg_ids[2] != G_MANDATORY_ALGS[2]) {
            if (report_msg) {
                report_msg->flag = 3;
                report_msg->is_attack = 1;
                std::string client_algs = format_alg_combo(alg_ids[0], alg_ids[1], alg_ids[2]);
                std::string target_algs = format_alg_combo(G_MANDATORY_ALGS[0], G_MANDATORY_ALGS[1], G_MANDATORY_ALGS[2]);
                snprintf(report_msg->report_msg, 255, "BLOCKED: mandatory algorithm mismatch; current:%s required:%s", client_algs.c_str(), target_algs.c_str());
            }
            if (re_auth_info) {
                write_re_auth_signal(re_auth_info, make_mode_signal_for_algs(G_MANDATORY_ALGS));
            }
            return 3;
        } else {
            std::cout << "[Auth Module] mandatory algorithm response accepted; mandatory mode cleared." << std::endl;
            clear_mandatory_algs();
            G_ATTACK_ID = 0;
            G_HIGH_LOAD_ID = 0;
        }
    }

    // 4. 实时攻击/高负载标识检查
    if ((G_ATTACK_ID != 0 || G_HIGH_LOAD_ID != 0) && G_MANDATORY_ALGS[0] == 0) {
        const int* target = (G_ATTACK_ID != 0) ? G_SECURE_ALGS : G_FAST_ALGS;
        set_mandatory_algs(target);
        if (report_msg) {
            report_msg->flag = 3;
            report_msg->is_attack = (G_ATTACK_ID != 0) ? 1 : 0;
            std::string client_algs = format_alg_combo(alg_ids[0], alg_ids[1], alg_ids[2]);
            std::string target_algs = format_alg_combo(target[0], target[1], target[2]);
            const char* reason = (G_ATTACK_ID != 0) ? "ATTACK_MODE: require 256-bit algorithms" : "HIGH_LOAD_MODE: require 128-bit algorithms";
            snprintf(report_msg->report_msg, 255, "%s current:%s required:%s", reason, client_algs.c_str(), target_algs.c_str());
        }
        if (re_auth_info) {
            write_re_auth_signal(re_auth_info, make_mode_signal_for_algs(G_MANDATORY_ALGS));
        }
        return 3;
    }

    // 4.5 检查算法合法性
    bool algs_ok = true;
    for (int i = 0; i < 3; i++) {
        bool found = false;
        for (int allowed : G_ALLOWED_ALGS_POOL) { if (alg_ids[i] == allowed) { found = true; break; } }
        if (!found) { algs_ok = false; break; }
    }

    if (!algs_ok) {
        int retry_algs[3] = {0, 0, 0};
        bool has_retry_algs = select_random_algs_from_pool_vector(G_ALLOWED_ALGS_POOL, retry_algs);

        if (report_msg) {
            report_msg->flag = 3;
            report_msg->is_attack = 0;
            std::string client_algs = format_alg_combo(alg_ids[0], alg_ids[1], alg_ids[2]);
            std::string server_pool = "";
            for (size_t i = 0; i < G_ALLOWED_ALGS_POOL.size(); ++i) {
                server_pool += get_algorithm_name(G_ALLOWED_ALGS_POOL[i]);
                if (i < G_ALLOWED_ALGS_POOL.size() - 1) server_pool += ",";
            }
            if (has_retry_algs) {
                std::string retry_combo = format_alg_combo(retry_algs[0], retry_algs[1], retry_algs[2]);
                snprintf(report_msg->report_msg, 255, "POLICY_MISMATCH:%s not in pool[%s];retry_algs:%s",
                         client_algs.c_str(), server_pool.c_str(), retry_combo.c_str());
            } else {
                snprintf(report_msg->report_msg, 255, "POLICY_MISMATCH:%s not in pool[%s]", client_algs.c_str(), server_pool.c_str());
            }
        }
        if (re_auth_info) {
            if (has_retry_algs) {
                write_re_auth_signal(re_auth_info, make_retry_config_mismatch_signal(retry_algs));
            } else {
                write_re_auth_signal(re_auth_info, "CMD_RETRY_CONFIG_MISMATCH");
            }
        }
        return 3;
    }

    // 5. 核心验证
    uint8_t calc_tags[AUTH_LAYER_COUNT][AUTH_MAX_TAG_BYTES];
    uint8_t decrypted_text[64];
    std::memset(calc_tags, 0, sizeof(calc_tags));
    std::memset(decrypted_text, 0, sizeof(decrypted_text));

    uint64_t verify_time = (G_FIXED_TIMESTAMP != 0) ? G_FIXED_TIMESTAMP : static_cast<uint64_t>(std::time(nullptr));
    bool verified = AuthApi::VerifyPayloadWithVault(verify_time, alg_ids, packet, decrypted_text, calc_tags);
    const AuthApi::AuthCryptoTrace& verify_trace = AuthApi::GetLastCryptoTrace();

    // 6. 填充审计信息
    if (audit_info) {
        for (int i = 0; i < 3; ++i) {
            audit_info->layers[i].alg_id = alg_ids[i];
            int tag_bits = get_algorithm_tag_bits(alg_ids[i]);
            int tag_bytes = (tag_bits + 7) / 8;
            if (tag_bytes < 0) tag_bytes = 0;
            if (tag_bytes > AUTH_MAX_TAG_BYTES) tag_bytes = AUTH_MAX_TAG_BYTES;
            audit_info->layers[i].tag_len_bits = tag_bits;
            audit_info->layers[i].tag_len_bytes = tag_bytes;
            std::memcpy(audit_info->layers[i].recv_tag, packet.tags[i], AUTH_MAX_TAG_BYTES);
            std::memcpy(audit_info->layers[i].calc_tag, calc_tags[i], AUTH_MAX_TAG_BYTES);
            std::string recv_hex = bytes_to_hex_string(packet.tags[i], static_cast<size_t>(tag_bytes));
            std::string calc_hex = bytes_to_hex_string(calc_tags[i], static_cast<size_t>(tag_bytes));
            std::snprintf(audit_info->layers[i].recv_tag_hex, sizeof(audit_info->layers[i].recv_tag_hex), "%s", recv_hex.c_str());
            std::snprintf(audit_info->layers[i].calc_tag_hex, sizeof(audit_info->layers[i].calc_tag_hex), "%s", calc_hex.c_str());
            int traced_status = trace_status_for_layer(verify_trace, i);
            if (traced_status != -2) {
                audit_info->layers[i].status = traced_status;
            } else {
                audit_info->layers[i].status = (std::memcmp(packet.tags[i], calc_tags[i], AUTH_MAX_TAG_BYTES) == 0) ? 1 : 0;
            }
        }
    }

    // 7. 严格判定逻辑
    bool all_layers_ok = true;
    if (audit_info) {
        for (int i = 0; i < 3; i++) { if (audit_info->layers[i].status != 1) { all_layers_ok = false; break; } }
    }

    if (verified && all_layers_ok) {
        if (report_msg) {
            report_msg->flag = 0;
            std::string alg_str = format_alg_combo(alg_ids[0], alg_ids[1], alg_ids[2]);
            snprintf(report_msg->report_msg, 255, "AUTH_SUCCESS:%s", alg_str.c_str());
        }
        return 1;
    } else {
        if (report_msg) {
            report_msg->flag = 1;
            std::string alg_str = format_alg_combo(alg_ids[0], alg_ids[1], alg_ids[2]);
            if (!all_layers_ok) {
                snprintf(report_msg->report_msg, 255,
                    "TAG_MISMATCH:%s L1:%s L2:%s L3:%s",
                    alg_str.c_str(),
                    audit_info ? (audit_info->layers[0].status == 1 ? "OK" : "FAIL") : "?",
                    audit_info ? (audit_info->layers[1].status == 1 ? "OK" : "FAIL") : "?",
                    audit_info ? (audit_info->layers[2].status == 1 ? "OK" : "FAIL") : "?");
            } else {
                snprintf(report_msg->report_msg, 255, "DECRYPT_VERIFY_FAILED:%s", alg_str.c_str());
            }
        }
        return 0;
    }
}


int auth_policy_match_ipv6_packet(
    char *data,
    unsigned int data_len,
    struct re_auth *re_auth_info,
    struct auth_report_msg *report_msg,
    struct auth_audit_info *audit_info,
    struct auth_decode_msg *decode_msg
) {
    ParsedIpv6AuthPacket parsed = parse_ipv6_auth_input(reinterpret_cast<const uint8_t*>(data), data_len);
    if (!parsed.error.empty()) {
        if (report_msg) {
            report_msg->flag = 1;
            report_msg->is_attack = 0;
            std::snprintf(report_msg->report_msg, sizeof(report_msg->report_msg), "PACKET_PARSE_FAILED:%s", parsed.error.c_str());
        }
        write_decode_msg(decode_msg, "{\"decrypt_results\":[]}");
        return 0;
    }

    AuthPacket packet;
    std::memset(&packet, 0, sizeof(packet));
    std::memcpy(&packet, parsed.auth_payload, sizeof(packet));

    auth_audit_info local_audit;
    std::memset(&local_audit, 0, sizeof(local_audit));
    for (int i = 0; i < AUTH_LAYER_COUNT; ++i) local_audit.layers[i].status = -1;
    auth_audit_info* audit_for_decode = audit_info ? audit_info : &local_audit;

    int result = auth_policy_match(
        reinterpret_cast<char*>(const_cast<uint8_t*>(parsed.auth_payload)),
        parsed.auth_len,
        re_auth_info,
        report_msg,
        audit_for_decode
    );

    uint8_t decrypted_plaintext[AUTH_CIPHERTEXT_BYTES];
    uint8_t ignored_tags[AUTH_LAYER_COUNT][AUTH_MAX_TAG_BYTES];
    std::memset(decrypted_plaintext, 0, sizeof(decrypted_plaintext));
    std::memset(ignored_tags, 0, sizeof(ignored_tags));

    uint32_t policy_id = static_cast<uint32_t>(packet.policy_id);
    int alg_ids[3] = {
        static_cast<int>((policy_id >> 24) & 0xFF),
        static_cast<int>((policy_id >> 16) & 0xFF),
        static_cast<int>((policy_id >> 8) & 0xFF)
    };
    uint64_t verify_time = (G_FIXED_TIMESTAMP != 0) ? G_FIXED_TIMESTAMP : static_cast<uint64_t>(std::time(nullptr));
    bool has_decrypted_plaintext = AuthApi::VerifyPayloadWithVault(verify_time, alg_ids, packet, decrypted_plaintext, ignored_tags);

    std::string json = build_ipv6_auth_decode_json(parsed, data_len, &packet,
        decrypted_plaintext, has_decrypted_plaintext, result, report_msg, true, audit_for_decode);
    write_decode_msg(decode_msg, json);
    return result;
}

int auth_select_algs_from_pool(const char* auth_type, int selected_ids[3]) {
    if (!auth_type) return -1;
    std::vector<int> pool = parse_algorithm_id_list(std::string(auth_type), true);
    if (pool.size() < 3) {
        std::cerr << "[Auth Error] algorithm pool has fewer than 3 IDs (" << pool.size() << ")" << std::endl;
        return -1;
    }

    if (is_full_algorithm_pool(pool)) {
        // 正式场景：9 个算法全选时，进入三档算法策略，默认使用 192 位组合。
        selected_ids[0] = G_DEFAULT_ALGS[0];
        selected_ids[1] = G_DEFAULT_ALGS[1];
        selected_ids[2] = G_DEFAULT_ALGS[2];
        return 0;
    }

    // 第三方算法池测试场景：算法池未全选时，从当前池中随机选择 3 个可用算法。
    if (!select_random_algs_from_pool_vector(pool, selected_ids)) {
        std::cerr << "[Auth Error] algorithm pool has fewer than 3 usable IDs" << std::endl;
        return -1;
    }
    return 0;
}

int auth_generate_packet(int ids[3], const uint8_t* plaintext, char* out_data) {
    AuthPacket packet;
    std::memset(&packet, 0, sizeof(AuthPacket));
    uint64_t now = std::time(nullptr);
    if (!AuthApi::GeneratePayloadWithVault(now, ids, plaintext, packet)) { return -1; }
    uint32_t policy_id = (static_cast<uint32_t>(ids[0]) << 24) |
                         (static_cast<uint32_t>(ids[1]) << 16) |
                         (static_cast<uint32_t>(ids[2]) << 8) | 0x01;
    packet.policy_id = (int)policy_id;
    std::memcpy(out_data, &packet, sizeof(AuthPacket));
    return 0;
}

const char* auth_get_last_crypto_trace_json() {
    static std::string json;
    json = pretty_json_for_decode_msg(build_crypto_trace_json(AuthApi::GetLastCryptoTrace()));
    return json.c_str();
}

int auth_parse_re_auth_signal(const char* payload, int out_fixed_ids[3]) {
    if (!payload) return 0;
    std::string data(payload);
    auto fill_ids = [&](const int algs[3]) -> int {
        if (!out_fixed_ids) return 0;
        out_fixed_ids[0] = algs[0];
        out_fixed_ids[1] = algs[1];
        out_fixed_ids[2] = algs[2];
        return 1;
    };

    if (data.find("CMD_ATTACK_MODE") == 0 || data.find("CMD_SECURITY_HIGH") == 0) {
        return fill_ids(G_SECURE_ALGS);
    }
    if (data.find("CMD_HIGH_LOAD") == 0 || data.find("CMD_LOAD_HIGH") == 0 || data.find("CMD_EFFICIENCY_HIGH") == 0) {
        return fill_ids(G_FAST_ALGS);
    }
    if (data.find("CMD_NORMAL_MODE") == 0 || data.find("CMD_DEFAULT_MODE") == 0) {
        return fill_ids(G_DEFAULT_ALGS);
    }

    if (data.find("CMD_FORCE_ALGS:") == 0) {
        if (!out_fixed_ids) return 0;
        int ids[3] = {0, 0, 0};
        if (!parse_three_alg_ids(data.substr(15), ids)) return 0;
        out_fixed_ids[0] = ids[0];
        out_fixed_ids[1] = ids[1];
        out_fixed_ids[2] = ids[2];
        return 1;
    }

    if (data.find("CMD_RETRY_CONFIG_MISMATCH:") == 0) {
        if (!out_fixed_ids) return 0;
        int ids[3] = {0, 0, 0};
        if (!parse_three_alg_ids(data.substr(26), ids)) return 0;
        out_fixed_ids[0] = ids[0];
        out_fixed_ids[1] = ids[1];
        out_fixed_ids[2] = ids[2];
        return 1;
    }

    if (data.find("CMD_RETRY_CONFIG_MISMATCH") == 0) return 2;
    return 0;
}

} // extern "C"
