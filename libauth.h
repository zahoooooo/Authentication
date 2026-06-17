#ifndef LIBAUTH_H
#define LIBAUTH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// 发起重新认证时所需要发送的数据及长度，目前留空
struct re_auth {
    unsigned int auth_len;
    char auth_data[1416]; 
};

// 所需结构体，该结构体作用是传出要上报的日志内容
struct auth_report_msg {
    unsigned int flag;
    int is_attack;
    char report_msg[256];
};

// 设置当前允许的算法池 (如 "11,12,13,21")，供服务端校验合法性（服务端使用）
void auth_set_allowed_algs(const char* pool);

// 设置是否存在攻击：1-开启攻击模式(要求切换到 13,23,33), 0-关闭
void auth_set_attack_mode(int mode,struct re_auth *re_auth_info);

// 设置是否存在高负载：1-开启高负载模式(要求切换到 11,21,31), 0-关闭
void auth_set_high_load_mode(int mode,struct re_auth *re_auth_info);

// 恢复正常模式：要求切换到默认 12,22,32
void auth_set_normal_mode(struct re_auth *re_auth_info);

// 设置固定时间戳用于验证 (演示用)：传入 0 使用实时时间，传入具体值则锁定该时间
void auth_set_timestamp(uint64_t ts);

// 每一层认证的详细信息 (用于前端对比视图)
struct auth_layer_info {
    int alg_id;
    uint8_t recv_tag[32];       // 固定 32 字节 Tag 槽，短 Tag 算法后续补 0
    uint8_t calc_tag[32];       // 固定 32 字节 Tag 槽，短 Tag 算法后续补 0
    int tag_len_bits;           // 本层算法有效 Tag 长度，单位 bit
    int tag_len_bytes;          // 本层算法有效 Tag 长度，单位 byte
    char recv_tag_hex[65];      // 仅包含有效 Tag 部分的十六进制字符串，不包含补零区
    char calc_tag_hex[65];      // 仅包含有效 Tag 部分的十六进制字符串，不包含补零区
    int status; // 1-通过, 0-失败, -1-未执行
};

// 完整的认证审计数据
struct auth_audit_info {
    struct auth_layer_info layers[3];
};

// IPv6 + AuthPacket 解包结果字符串。
// 并行模式下只输出每个算法最终解密出的业务报文摘要，以及对应 alg_id/name/recv_tag_hex/calc_tag_hex/tag_match。
#define AUTH_DECODE_MSG_BYTES 4096
struct auth_decode_msg {
    char decode_msg[AUTH_DECODE_MSG_BYTES];
};


// 算法参数信息：供大系统前端一次性获取 9 个算法/变体的客观参数。
// 只包含 family/key/nonce/tag 等参数，不包含推荐、评分、等级或主观说明。
#define AUTH_ALGORITHM_SECURITY_COUNT 9
#define AUTH_LAYER_COUNT 3
#define AUTH_CIPHERTEXT_BYTES 64
#define AUTH_MAX_TAG_BYTES 32
#define AUTH_PACKET_BYTES (4 + AUTH_LAYER_COUNT * AUTH_CIPHERTEXT_BYTES + AUTH_LAYER_COUNT * AUTH_MAX_TAG_BYTES)

struct auth_algorithm_security_info {
    int alg_id;            // Algorithm ID: 11/12/13/21/22/23/31/32/33
    char name[48];         // Algorithm name
    char family[32];       // Algorithm family: TinyJAMBU / SCHWAEMM / LEA-CCM
    int key_bits;          // Key length in bits
    int nonce_bits;        // Nonce length in bits
    int tag_bits;          // Effective authentication tag length in bits
};

// 接口6：返回算法客观参数表。
// out_infos: 调用方提供的数组；max_count 至少为 AUTH_ALGORITHM_SECURITY_COUNT 时可取全量。
// 返回值：实际写入的条目数；out_infos 为空或 max_count <= 0 时返回总条目数。
int auth_get_algorithm_security_info(struct auth_algorithm_security_info *out_infos, int max_count);

// 接口7：返回前端可直接解析的 JSON 字符串，包含全部 9 个算法客观参数。
// 返回的指针由库内部静态缓存维护，调用方不要 free；如需长期保存请自行拷贝。
const char* auth_get_algorithm_security_json();

// 接口1：初始化认证模块的数据结构
int auth_init();

//认证端调用
// 接口2：实时接收IPV6多模态数据包，解析并进行身份认证
// data: 传入 AUTH_PACKET_BYTES 字节的认证包 (AuthPacket)，当前为 292 字节
// data_len: 传入 AUTH_PACKET_BYTES
// re_auth_info: 传出重新认证所需的数据及长度
// report_msg: 传出要上报的日志内容
// audit_info: 传出审计详情 (包含每一层 Tag 对比)
// 返回值: 1-验证通过, 0-验证失败, 3-触发重认证(查看 report_msg->is_attack 区分原因)
int auth_policy_match(
    char *data, 
    unsigned int data_len, 
    struct re_auth *re_auth_info,
    struct auth_report_msg *report_msg,
    struct auth_audit_info *audit_info
);

// 接口2扩展：接收完整 IPv6 包 / 裸 AuthPacket / 带以太网头的抓包数据，
// 自动解出内部 AuthPacket 后执行认证，并把解包结果写入 decode_msg。
// 兼容输入格式：
//   1) AuthPacket 裸数据，长度 AUTH_PACKET_BYTES；
//   2) IPv6 Header + AuthPacket；
//   3) Ethernet Header + IPv6 Header + AuthPacket。
// 返回值同 auth_policy_match: 1-通过, 0-失败, 3-触发重认证/策略处理。
int auth_policy_match_ipv6_packet(
    char *data,
    unsigned int data_len,
    struct re_auth *re_auth_info,
    struct auth_report_msg *report_msg,
    struct auth_audit_info *audit_info,
    struct auth_decode_msg *decode_msg
);

// 接口3：从给定的算法池字符串中随机选择3个不重复的算法（客户端使用）
// auth_type: 算法池字符串，如 "11,12,13,21,22,23,31,32,33"
// selected_ids: 输出数组，优先选择默认 192 组合 12,22,32；若池中不包含该组合，则从池中选3个可用算法
// 返回值: 0-成功, -1-算法池不足3个或解析失败
int auth_select_algs_from_pool(const char* auth_type, int selected_ids[3]);

// 接口4：客户端调用，生成加密认证包
// ids: 传入3个算法ID
// plaintext: 传入64字节业务数据
// out_data: 输出 AUTH_PACKET_BYTES 字节的加密包 (AuthPacket)，当前为 292 字节
int auth_generate_packet(int ids[3], const uint8_t* plaintext, char* out_data);

// 接口5：客户端调用，解析服务端传回的重认证信号
// payload: 服务端返回的 re_auth_info->auth_data
// out_fixed_ids: 如果是强制切换算法，传出 3 个固定 ID
// 返回值: 1-强制切换算法并重发, 2-仅简单重发, 0-解析失败或无需操作
int auth_parse_re_auth_signal(const char* payload, int out_fixed_ids[3]);

// 调试接口：返回最近一次 auth_generate_packet 或 auth_policy_match/auth_policy_match_ipv6_packet
// 的三算法并行加密/解密步骤 JSON。返回的指针由库内部静态缓存维护，调用方不要 free。
const char* auth_get_last_crypto_trace_json();

#ifdef __cplusplus
}
#endif

#endif // LIBAUTH_H
