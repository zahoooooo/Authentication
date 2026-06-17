#include "key_vault.h"
#include <random>

namespace AuthApi {

KeyVault& KeyVault::GetInstance() {
    static KeyVault instance;
    return instance;
}

void KeyVault::Initialize(uint64_t seed) {
    std::mt19937_64 rng(seed);
    
    for (size_t i = 0; i < NUM_KEYS; ++i) {
        for (size_t j = 0; j < KEY_SIZE; ++j) {
            keys_[i][j] = static_cast<uint8_t>(rng() & 0xFF);
        }
    }
    initialized_ = true;
}

size_t KeyVault::GetIndexFromSlot(uint64_t slot) const {
    uint64_t hash = slot;
    hash ^= (hash >> 33);
    hash *= 0xff51afd7ed558ccd;
    hash ^= (hash >> 33);
    hash *= 0xc4ceb9fe1a85ec53;
    hash ^= (hash >> 33);
    
    return static_cast<size_t>(hash % NUM_KEYS);
}

const uint8_t* KeyVault::GetCurrentKey(uint64_t current_timestamp) const {
    if (!initialized_) {
        return nullptr; // 不再抛出异常，返回空指针供上层处理
    }
    uint64_t slot = current_timestamp / TIME_SLOT_SECONDS;
    size_t index = GetIndexFromSlot(slot);
    return keys_[index].data();
}

std::vector<const uint8_t*> KeyVault::GetTolerantKeys(uint64_t current_timestamp) const {
    std::vector<const uint8_t*> result;
    if (!initialized_) {
        return result; // 返回空列表
    }
    
    uint64_t current_slot = current_timestamp / TIME_SLOT_SECONDS;
    
    result.push_back(keys_[GetIndexFromSlot(current_slot)].data());
    
    if (current_slot > 0) {
        result.push_back(keys_[GetIndexFromSlot(current_slot - 1)].data());
    }
    
    result.push_back(keys_[GetIndexFromSlot(current_slot + 1)].data());
    
    return result;
}

} // namespace AuthApi
