#include "sentinelid/client/device.hpp"

#include <hidapi/hidapi.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace sentinelid::client {

static constexpr uint16_t SENTINEL_VID = 0x2E8A;
static constexpr uint16_t SENTINEL_PID = 0x000A;
static constexpr int REPORT_SIZE = 64;

// Wire protocol constants
static constexpr uint8_t CMD_SIGN_PAYLOAD    = 0x03;
static constexpr uint8_t FLAG_START          = 1 << 0;
static constexpr uint8_t FLAG_END            = 1 << 1;
static constexpr uint8_t FLAG_ERROR          = 1 << 2;
static constexpr uint8_t ERR_BUSY            = 0x01;
static constexpr uint8_t ERR_BAD_STATE       = 0x10;
static constexpr uint8_t ERR_PAYLOAD_TOO_LARGE = 0x11;
static constexpr uint8_t ERR_RATE_LIMIT      = 0x30;
static constexpr uint8_t ERR_ATECC_FAIL      = 0x40;
static constexpr uint8_t ERR_UNKNOWN_CMD     = 0xFF;
static constexpr uint8_t ERR_PROVISION_DENIED = 0xE0;

// Report layout: [report_id=0x00][cmd][flags][seq][payload...]
static constexpr int HDR_CMD   = 1; // offset in HID report (after report ID)
static constexpr int HDR_FLAGS = 2;
static constexpr int HDR_SEQ   = 3;
static constexpr int HDR_DATA  = 4;
static constexpr int MAX_CHUNK = REPORT_SIZE - HDR_DATA;

// ---------------------------------------------------------------------------
// Impl (pimpl)
// ---------------------------------------------------------------------------
struct SentinelDevice::Impl {
    hid_device* handle = nullptr;
    DeviceInfo device_info;

    Impl(hid_device* h, DeviceInfo info)
        : handle(h), device_info(std::move(info)) {}

    ~Impl() {
        if (handle) {
            hid_close(handle);
            handle = nullptr;
        }
    }
};

// ---------------------------------------------------------------------------
// Lifetime
// ---------------------------------------------------------------------------
SentinelDevice::SentinelDevice(std::unique_ptr<Impl> impl)
    : pimpl_(std::move(impl)) {}

SentinelDevice::~SentinelDevice() = default;
SentinelDevice::SentinelDevice(SentinelDevice&&) noexcept = default;
SentinelDevice& SentinelDevice::operator=(SentinelDevice&&) noexcept = default;

const DeviceInfo& SentinelDevice::info() const {
    return pimpl_->device_info;
}

// ---------------------------------------------------------------------------
// Static helpers
// ---------------------------------------------------------------------------
static std::string wcs_to_str(const wchar_t* wcs) {
    if (!wcs) return "";
    std::string out;
    for (; *wcs; ++wcs) {
        out += static_cast<char>(*wcs & 0x7F); // ASCII subset only
    }
    return out;
}

// ---------------------------------------------------------------------------
// enumerate / open / open_first
// ---------------------------------------------------------------------------
std::vector<DeviceInfo> SentinelDevice::enumerate() {
    hid_init();
    auto* devs = hid_enumerate(SENTINEL_VID, SENTINEL_PID);
    std::vector<DeviceInfo> result;
    for (auto* d = devs; d; d = d->next) {
        DeviceInfo info;
        info.path           = d->path ? d->path : "";
        info.vendor_id      = d->vendor_id;
        info.product_id     = d->product_id;
        info.serial_number  = wcs_to_str(d->serial_number);
        info.product_string = wcs_to_str(d->product_string);
        result.push_back(std::move(info));
    }
    hid_free_enumeration(devs);
    return result;
}

SentinelDevice SentinelDevice::open(const DeviceInfo& info) {
    hid_init();
    hid_device* handle = hid_open_path(info.path.c_str());
    if (!handle) {
        throw std::runtime_error("Failed to open SentinelID device at " + info.path);
    }
    hid_set_nonblocking(handle, 0); // blocking reads
    return SentinelDevice(std::make_unique<Impl>(handle, info));
}

SentinelDevice SentinelDevice::open_first() {
    auto devices = enumerate();
    if (devices.empty()) {
        throw std::runtime_error("No SentinelID devices found");
    }
    return open(devices[0]);
}

// ---------------------------------------------------------------------------
// request_check
// ---------------------------------------------------------------------------
DeviceCheckRequest SentinelDevice::request_check(const std::string& publisher_id,
                                                  const std::string& game_id) {
    // Build challenge JSON
    nlohmann::json challenge_json = {
        {"publisher_id", publisher_id},
        {"game_id",      game_id},
    };
    std::string challenge = challenge_json.dump();
    const auto* data      = reinterpret_cast<const uint8_t*>(challenge.data());
    size_t      data_len  = challenge.size();

    // Send framed HID output reports: [0x00][CMD_SIGN_PAYLOAD][flags][seq][data...]
    uint8_t seq = 0;
    for (size_t offset = 0; offset < data_len; offset += MAX_CHUNK, ++seq) {
        uint8_t report[REPORT_SIZE] = {};
        size_t chunk_len = std::min(static_cast<size_t>(MAX_CHUNK), data_len - offset);
        uint8_t flags = 0;
        if (offset == 0)                        flags |= FLAG_START;
        if (offset + chunk_len >= data_len)     flags |= FLAG_END;

        report[0]        = 0x00; // HID report ID
        report[HDR_CMD]  = CMD_SIGN_PAYLOAD;
        report[HDR_FLAGS]= flags;
        report[HDR_SEQ]  = seq;
        std::memcpy(report + HDR_DATA, data + offset, chunk_len);

        if (hid_write(pimpl_->handle, report, REPORT_SIZE) < 0) {
            throw std::runtime_error("Failed to write to SentinelID device");
        }
    }

    // Read framed HID input reports until FLAG_END
    std::vector<uint8_t> response_data;
    while (true) {
        uint8_t report[REPORT_SIZE] = {};
        int bytes_read = hid_read_timeout(pimpl_->handle, report, REPORT_SIZE, 5000);
        if (bytes_read < 0) {
            throw std::runtime_error("Error reading from SentinelID device");
        }
        if (bytes_read == 0) {
            throw std::runtime_error("No response from SentinelID device (timeout)");
        }

        uint8_t flags = report[HDR_FLAGS - 1]; // reports from device have no leading report ID
        if (flags & FLAG_ERROR) {
            uint8_t err = (bytes_read > HDR_DATA - 1) ? report[HDR_DATA - 1] : 0;
            throw std::runtime_error("Device error: 0x" + [&]{
                char buf[8]; std::snprintf(buf, sizeof(buf), "%02X", err); return std::string(buf);
            }());
        }

        // Data starts at HDR_DATA - 1 (no report ID byte on input reports)
        int data_start = HDR_DATA - 1;
        int data_end   = bytes_read;
        while (data_end > data_start && report[data_end - 1] == 0) data_end--;
        response_data.insert(response_data.end(), report + data_start, report + data_end);

        if (flags & FLAG_END) break;
    }

    std::string json_str(response_data.begin(), response_data.end());
    auto resp = nlohmann::json::parse(json_str);

    DeviceCheckRequest req;
    req.device_id    = resp.at("device_id").get<std::string>();
    req.publisher_id = publisher_id;
    req.game_id      = game_id;
    req.alg          = resp.value("alg", "ES256");
    req.payload_b64  = resp.at("payload_b64").get<std::string>();
    req.sig_b64      = resp.at("sig_b64").get<std::string>();
    return req;
}

// ---------------------------------------------------------------------------
// close
// ---------------------------------------------------------------------------
void SentinelDevice::close() {
    if (pimpl_ && pimpl_->handle) {
        hid_close(pimpl_->handle);
        pimpl_->handle = nullptr;
    }
}

} // namespace sentinelid::client
