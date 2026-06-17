#ifndef KEY_VAULT_H
#define KEY_VAULT_H

#include <cstdint>
#include <array>
#include <vector>

namespace AuthApi {

class KeyVault {
public:
    static constexpr size_t NUM_KEYS = 8192;
    static constexpr size_t KEY_SIZE = 32;
    static constexpr uint64_t TIME_SLOT_SECONDS = 600;

    static KeyVault& GetInstance();

    void Initialize(uint64_t seed);

    const uint8_t* GetCurrentKey(uint64_t current_timestamp) const;

    std::vector<const uint8_t*> GetTolerantKeys(uint64_t current_timestamp) const;

private:
    KeyVault() = default;
    ~KeyVault() = default;

    KeyVault(const KeyVault&) = delete;
    KeyVault& operator=(const KeyVault&) = delete;

    std::array<std::array<uint8_t, KEY_SIZE>, NUM_KEYS> keys_;
    bool initialized_ = false;

    size_t GetIndexFromSlot(uint64_t slot) const;
};

} // namespace AuthApi

#endif // KEY_VAULT_H
