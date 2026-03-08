#pragma once
#include "models.hpp"
#include <memory>
#include <string>
#include <vector>

namespace sentinelid::client {

class SentinelDevice {
public:
    ~SentinelDevice();

    // Non-copyable, movable
    SentinelDevice(const SentinelDevice&) = delete;
    SentinelDevice& operator=(const SentinelDevice&) = delete;
    SentinelDevice(SentinelDevice&&) noexcept;
    SentinelDevice& operator=(SentinelDevice&&) noexcept;

    const DeviceInfo& info() const;

    /// List all connected SentinelID USB HID devices.
    static std::vector<DeviceInfo> enumerate();

    /// Open a specific device by its DeviceInfo.
    static SentinelDevice open(const DeviceInfo& info);

    /// Open the first available SentinelID device.
    static SentinelDevice open_first();

    /// Send a check challenge to the device and return a signed DeviceCheckRequest.
    DeviceCheckRequest request_check(const std::string& publisher_id,
                                     const std::string& game_id);

    void close();

private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;

    explicit SentinelDevice(std::unique_ptr<Impl> impl);
};

} // namespace sentinelid::client
