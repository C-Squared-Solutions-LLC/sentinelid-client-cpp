#pragma once
#include <string>
#include <cstdint>

namespace sentinelid::client {

struct DeviceInfo {
    std::string path;
    uint16_t vendor_id;
    uint16_t product_id;
    std::string serial_number;
    std::string product_string;
};

struct DeviceCheckRequest {
    std::string device_id;
    std::string publisher_id;
    std::string game_id;
    std::string alg;
    std::string payload_b64;
    std::string sig_b64;
};

} // namespace sentinelid::client
