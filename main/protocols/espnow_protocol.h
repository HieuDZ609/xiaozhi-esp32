#ifndef ESPNOW_PROTOCOL_H
#define ESPNOW_PROTOCOL_H

#include "protocol.h"

#include <esp_now.h>
#include <freertos/FreeRTOS.h>
#include <freertos/event_groups.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#define ESPNOW_PROTOCOL_SERVER_HELLO_EVENT (1 << 0)
#define ESPNOW_PROTOCOL_SEND_DONE_EVENT (1 << 1)

// ESP-NOW v1 datagrams are limited to 250 bytes. Keep 5 bytes of header plus
// a small safety margin and fragment larger logical packets.
#define ESPNOW_FRAGMENT_PAYLOAD_SIZE 240
#define ESPNOW_HEADER_SIZE 5

enum EspNowFrameType : uint8_t {
    kFrameTypeJson = 0x01,   // UTF-8 JSON control message (robot <-> gateway)
    kFrameTypeAudio = 0x02,  // logical audio packet: [ts u32 LE][len u16 LE][opus]
    kFrameTypeError = 0x03,  // gateway -> robot fatal error description
};

struct EspNowFrameHeader {
    uint8_t type;         // EspNowFrameType
    uint8_t seq;          // logical packet sequence number
    uint8_t frag_index;   // 0-based fragment index
    uint8_t frag_total;   // total fragment count (>= 1)
    uint8_t payload_len;  // payload bytes carried by this fragment
} __attribute__((packed));

class EspNowProtocol : public Protocol {
public:
    EspNowProtocol();
    ~EspNowProtocol();

    bool Start() override;
    bool OpenAudioChannel() override;
    void CloseAudioChannel(bool send_goodbye = true) override;
    bool IsAudioChannelOpened() const override;
    bool SendAudio(std::unique_ptr<AudioStreamPacket> packet) override;

private:
    // Alive flag for safe scheduled callbacks - set to false in destructor
    std::shared_ptr<std::atomic<bool>> alive_ = std::make_shared<std::atomic<bool>>(true);

    EventGroupHandle_t event_group_handle_;
    esp_now_peer_info_t peer_info_;
    bool initialized_ = false;
    bool channel_opened_ = false;
    uint8_t send_seq_ = 0;

    struct ReassemblyBuffer {
        bool active = false;
        uint8_t type = 0;
        uint8_t seq = 0;
        uint8_t next_index = 0;
        uint8_t frag_total = 0;
        std::vector<uint8_t> buffer;
    };
    ReassemblyBuffer reassembly_[4];  // indexed by EspNowFrameType

    mutable std::mutex channel_mutex_;
    std::mutex reassembly_mutex_;

    bool SendText(const std::string& text) override;
    bool SendFrames(uint8_t type, const uint8_t* data, size_t len);
    void HandleReceive(const EspNowFrameHeader& header, const uint8_t* payload);
    void OnFragmentComplete(uint8_t type, const std::vector<uint8_t>& data);
    void ParseServerHello(const cJSON* root);
    static bool ParseMac(const char* str, uint8_t mac[6]);

    static void EspNowSendCb(const esp_now_send_info_t* tx_info, esp_now_send_status_t status);
    static void EspNowRecvCb(const esp_now_recv_info_t* esp_now_info, const uint8_t* data,
                             int data_len);

    std::string GetHelloMessage();
};

#endif  // ESPNOW_PROTOCOL_H