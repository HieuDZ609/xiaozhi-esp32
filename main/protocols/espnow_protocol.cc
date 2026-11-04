#include "espnow_protocol.h"

#include "application.h"
#include "assets/lang_config.h"

#include <cJSON.h>
#include <esp_log.h>
#include <esp_wifi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/event_groups.h>

#include <cstdio>
#include <cstring>
#include <new>

#define TAG "ESPNOW"

// Development master keys. The gateway firmware must use the same values.
static const uint8_t kEspNowPmk[16] = {0x58, 0x51, 0x07, 0x6f, 0xd5, 0x2a, 0x9c, 0x3b,
                                       0x1e, 0x44, 0xf0, 0x8d, 0x66, 0x27, 0x91, 0xc0};
static const uint8_t kEspNowLmk[16] = {0x12, 0xf7, 0x44, 0xab, 0x90, 0x3d, 0x59, 0x2e,
                                       0x80, 0x6b, 0xd4, 0x15, 0xa7, 0x39, 0xec, 0x73};

static EspNowProtocol* s_espnow_instance = nullptr;

EspNowProtocol::EspNowProtocol() {
    event_group_handle_ = xEventGroupCreate();
    memset(&peer_info_, 0, sizeof(peer_info_));
    s_espnow_instance = this;
}

EspNowProtocol::~EspNowProtocol() {
    ESP_LOGI(TAG, "EspNowProtocol deinit");

    // Mark as dead first to prevent any pending scheduled tasks from executing
    *alive_ = false;

    if (s_espnow_instance == this) {
        s_espnow_instance = nullptr;
    }

    if (initialized_) {
        esp_now_unregister_recv_cb();
        esp_now_unregister_send_cb();
        esp_now_del_peer(peer_info_.peer_addr);
        esp_now_deinit();
        initialized_ = false;
    }

    if (event_group_handle_ != nullptr) {
        vEventGroupDelete(event_group_handle_);
    }
}

bool EspNowProtocol::ParseMac(const char* str, uint8_t mac[6]) {
    unsigned int values[6] = {0};
    int count = sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x", &values[0], &values[1], &values[2],
                       &values[3], &values[4], &values[5]);
    if (count != 6) {
        return false;
    }
    bool all_zero = true;
    for (int i = 0; i < 6; i++) {
        mac[i] = static_cast<uint8_t>(values[i]);
        if (mac[i] != 0) {
            all_zero = false;
        }
    }
    return !all_zero;
}

bool EspNowProtocol::Start() {
    if (initialized_) {
        return true;
    }

    const char* gateway_mac = CONFIG_ESP_NOW_GATEWAY_MAC;
    if (!ParseMac(gateway_mac, peer_info_.peer_addr)) {
        ESP_LOGE(TAG, "Invalid gateway MAC address: %s", gateway_mac);
        SetError(Lang::Strings::SERVER_NOT_FOUND);
        return false;
    }

    peer_info_.channel = CONFIG_ESP_NOW_CHANNEL;
    peer_info_.ifidx = WIFI_IF_STA;
    peer_info_.encrypt = true;
    memcpy(peer_info_.lmk, kEspNowLmk, ESP_NOW_KEY_LEN);

    esp_err_t err = esp_now_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_now_init failed: %d", err);
        SetError(Lang::Strings::SERVER_NOT_CONNECTED);
        return false;
    }

    err = esp_now_set_pmk(kEspNowPmk);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "esp_now_set_pmk failed: %d", err);
    }

    err = esp_now_register_send_cb(EspNowSendCb);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_now_register_send_cb failed: %d", err);
        esp_now_deinit();
        SetError(Lang::Strings::SERVER_NOT_CONNECTED);
        return false;
    }

    err = esp_now_register_recv_cb(EspNowRecvCb);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_now_register_recv_cb failed: %d", err);
        esp_now_deinit();
        SetError(Lang::Strings::SERVER_NOT_CONNECTED);
        return false;
    }

    err = esp_now_add_peer(&peer_info_);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_now_add_peer failed: %d", err);
        esp_now_deinit();
        SetError(Lang::Strings::SERVER_NOT_CONNECTED);
        return false;
    }

    initialized_ = true;
    ESP_LOGI(TAG, "ESP-NOW initialized, gateway MAC %02x:%02x:%02x:%02x:%02x:%02x",
             peer_info_.peer_addr[0], peer_info_.peer_addr[1], peer_info_.peer_addr[2],
             peer_info_.peer_addr[3], peer_info_.peer_addr[4], peer_info_.peer_addr[5]);
    return true;
}

bool EspNowProtocol::SendFrames(uint8_t type, const uint8_t* data, size_t len) {
    if (!initialized_) {
        ESP_LOGE(TAG, "ESP-NOW not initialized");
        return false;
    }

    const uint8_t seq = ++send_seq_;
    const uint8_t frag_total = len == 0
                                   ? 1
                                   : static_cast<uint8_t>((len + ESPNOW_FRAGMENT_PAYLOAD_SIZE - 1) /
                                                          ESPNOW_FRAGMENT_PAYLOAD_SIZE);

    uint8_t frame[ESPNOW_HEADER_SIZE + ESPNOW_FRAGMENT_PAYLOAD_SIZE];
    auto* header = reinterpret_cast<EspNowFrameHeader*>(frame);
    header->type = type;
    header->seq = seq;

    size_t offset = 0;
    for (uint8_t i = 0; i < frag_total; i++) {
        size_t chunk = len - offset;
        if (chunk > ESPNOW_FRAGMENT_PAYLOAD_SIZE) {
            chunk = ESPNOW_FRAGMENT_PAYLOAD_SIZE;
        }
        header->frag_index = i;
        header->frag_total = frag_total;
        header->payload_len = static_cast<uint8_t>(chunk);
        if (chunk > 0) {
            memcpy(frame + ESPNOW_HEADER_SIZE, data + offset, chunk);
        }

        // Clear any stale send-done bit before this fragment.
        xEventGroupClearBits(event_group_handle_, ESPNOW_PROTOCOL_SEND_DONE_EVENT);
        esp_err_t err = esp_now_send(peer_info_.peer_addr, frame, ESPNOW_HEADER_SIZE + chunk);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "esp_now_send failed: %d (type=%d, frag=%d/%d)", err, type, i,
                     frag_total);
            return false;
        }

        // Pacing: wait for the send callback before sending the next fragment.
        // This keeps fragments of one logical packet back-to-back and avoids
        // filling the ESP-NOW TX queue.
        EventBits_t bits = xEventGroupWaitBits(event_group_handle_, ESPNOW_PROTOCOL_SEND_DONE_EVENT,
                                               pdTRUE, pdFALSE,
                                               pdMS_TO_TICKS(CONFIG_ESP_NOW_SEND_TIMEOUT_MS));
        if (!(bits & ESPNOW_PROTOCOL_SEND_DONE_EVENT)) {
            ESP_LOGW(TAG, "ESP-NOW send ack timeout (type=%d, frag=%d/%d)", type, i, frag_total);
            return false;
        }

        offset += chunk;
    }
    return true;
}

bool EspNowProtocol::SendText(const std::string& text) {
    std::lock_guard<std::mutex> lock(channel_mutex_);
    return SendFrames(kFrameTypeJson, reinterpret_cast<const uint8_t*>(text.data()), text.size());
}

bool EspNowProtocol::SendAudio(std::unique_ptr<AudioStreamPacket> packet) {
    std::lock_guard<std::mutex> lock(channel_mutex_);
    if (packet->payload.size() > UINT16_MAX) {
        ESP_LOGE(TAG, "Audio payload too large: %zu", packet->payload.size());
        return false;
    }

    // Logical audio payload: [timestamp u32 LE][payload_size u16 LE][opus frames].
    std::vector<uint8_t> logical;
    logical.resize(6 + packet->payload.size());
    const uint32_t timestamp = packet->timestamp;
    const uint16_t payload_len = static_cast<uint16_t>(packet->payload.size());
    memcpy(logical.data(), &timestamp, sizeof(timestamp));
    memcpy(logical.data() + 4, &payload_len, sizeof(payload_len));
    memcpy(logical.data() + 6, packet->payload.data(), packet->payload.size());

    return SendFrames(kFrameTypeAudio, logical.data(), logical.size());
}

std::string EspNowProtocol::GetHelloMessage() {
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "hello");
    cJSON_AddNumberToObject(root, "version", 3);
    cJSON_AddStringToObject(root, "transport", "espnow");
    cJSON* features = cJSON_CreateObject();
    cJSON_AddBoolToObject(features, "mcp", true);
    cJSON_AddItemToObject(root, "features", features);
    AddTextFontCapabilities(root);
    cJSON* audio_params = cJSON_CreateObject();
    cJSON_AddStringToObject(audio_params, "format", "opus");
    cJSON_AddNumberToObject(audio_params, "sample_rate", 16000);
    cJSON_AddNumberToObject(audio_params, "channels", 1);
    cJSON_AddNumberToObject(audio_params, "frame_duration", OPUS_FRAME_DURATION_MS);
    cJSON_AddItemToObject(root, "audio_params", audio_params);
    auto* json_str = cJSON_PrintUnformatted(root);
    std::string message(json_str);
    cJSON_free(json_str);
    cJSON_Delete(root);
    return message;
}

bool EspNowProtocol::OpenAudioChannel() {
    if (!initialized_) {
        ESP_LOGE(TAG, "ESP-NOW not initialized");
        SetError(Lang::Strings::SERVER_NOT_CONNECTED);
        return false;
    }

    error_occurred_ = false;
    session_id_.clear();
    xEventGroupClearBits(event_group_handle_, ESPNOW_PROTOCOL_SERVER_HELLO_EVENT);

    if (!SendText(GetHelloMessage())) {
        return false;
    }

    // Wait for the gateway to relay the server hello back to us.
    EventBits_t bits = xEventGroupWaitBits(event_group_handle_, ESPNOW_PROTOCOL_SERVER_HELLO_EVENT,
                                           pdTRUE, pdFALSE, pdMS_TO_TICKS(10000));
    if (!(bits & ESPNOW_PROTOCOL_SERVER_HELLO_EVENT)) {
        ESP_LOGE(TAG, "Failed to receive server hello");
        SetError(Lang::Strings::SERVER_TIMEOUT);
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(channel_mutex_);
        channel_opened_ = true;
    }

    if (on_audio_channel_opened_ != nullptr) {
        on_audio_channel_opened_();
    }
    return true;
}

void EspNowProtocol::CloseAudioChannel(bool send_goodbye) {
    if (!initialized_) {
        return;
    }

    ESP_LOGI(TAG, "Closing audio channel, send_goodbye: %d", send_goodbye);

    // Only send goodbye when the client initiates the close.
    if (send_goodbye) {
        std::string message = "{";
        message += "\"session_id\":\"" + session_id_ + "\",";
        message += "\"type\":\"goodbye\"";
        message += "}";
        SendText(message);
    }

    {
        std::lock_guard<std::mutex> lock(channel_mutex_);
        channel_opened_ = false;
    }

    if (on_audio_channel_closed_ != nullptr) {
        on_audio_channel_closed_();
    }
}

bool EspNowProtocol::IsAudioChannelOpened() const {
    std::lock_guard<std::mutex> lock(channel_mutex_);
    return initialized_ && channel_opened_ && !error_occurred_ && !IsTimeout();
}

void EspNowProtocol::EspNowSendCb(const esp_now_send_info_t* tx_info, esp_now_send_status_t status) {
    (void)tx_info;
    auto* self = s_espnow_instance;
    if (self == nullptr) {
        return;
    }
    if (status != ESP_NOW_SEND_SUCCESS) {
        ESP_LOGW(TAG, "ESP-NOW send failed");
    }
    xEventGroupSetBits(self->event_group_handle_, ESPNOW_PROTOCOL_SEND_DONE_EVENT);
}

void EspNowProtocol::EspNowRecvCb(const esp_now_recv_info_t* esp_now_info, const uint8_t* data,
                                  int data_len) {
    auto* self = s_espnow_instance;
    if (self == nullptr || data == nullptr || data_len < ESPNOW_HEADER_SIZE) {
        return;
    }

    EspNowFrameHeader header;
    memcpy(&header, data, sizeof(header));
    if (header.payload_len > ESPNOW_FRAGMENT_PAYLOAD_SIZE ||
        data_len != ESPNOW_HEADER_SIZE + header.payload_len || header.frag_total == 0 ||
        header.frag_index >= header.frag_total) {
        ESP_LOGW(TAG, "Malformed ESP-NOW frame");
        return;
    }

    self->HandleReceive(header, data + ESPNOW_HEADER_SIZE);
}

void EspNowProtocol::HandleReceive(const EspNowFrameHeader& header, const uint8_t* payload) {
    last_incoming_time_ = std::chrono::steady_clock::now();

    if (header.type >= 4) {
        ESP_LOGW(TAG, "Unknown ESP-NOW frame type: %d", header.type);
        return;
    }

    bool complete = false;
    std::vector<uint8_t> full_data;
    {
        std::lock_guard<std::mutex> lock(reassembly_mutex_);

        ReassemblyBuffer& rb = reassembly_[header.type];
        if (!rb.active || rb.seq != header.seq || rb.type != header.type) {
            rb.active = true;
            rb.type = header.type;
            rb.seq = header.seq;
            rb.next_index = 0;
            rb.frag_total = header.frag_total;
            rb.buffer.clear();
            rb.buffer.reserve(rb.frag_total * ESPNOW_FRAGMENT_PAYLOAD_SIZE);
        }

        if (header.frag_index != rb.next_index) {
            ESP_LOGW(TAG, "ESP-NOW fragment out of order: type=%d seq=%d got=%d expected=%d",
                     header.type, header.seq, header.frag_index, rb.next_index);
            rb.active = false;
            return;
        }

        rb.buffer.insert(rb.buffer.end(), payload, payload + header.payload_len);
        rb.next_index++;

        if (rb.next_index >= rb.frag_total) {
            full_data = std::move(rb.buffer);
            rb.active = false;
            complete = true;
        }
    }

    if (complete) {
        OnFragmentComplete(header.type, full_data);
    }
}

void EspNowProtocol::OnFragmentComplete(uint8_t type, const std::vector<uint8_t>& data) {
    switch (type) {
        case kFrameTypeAudio: {
            if (data.size() < 6) {
                ESP_LOGW(TAG, "Short audio packet: %zu", data.size());
                return;
            }
            uint32_t timestamp = 0;
            uint16_t payload_len = 0;
            memcpy(&timestamp, data.data(), sizeof(timestamp));
            memcpy(&payload_len, data.data() + 4, sizeof(payload_len));
            if (data.size() != static_cast<size_t>(6) + payload_len) {
                ESP_LOGW(TAG, "Audio payload length mismatch: header=%u, received=%zu", payload_len,
                         data.size() - 6);
                return;
            }

            auto packet = std::make_unique<AudioStreamPacket>();
            packet->sample_rate = server_sample_rate_;
            packet->frame_duration = server_frame_duration_;
            packet->timestamp = timestamp;
            packet->payload.assign(data.begin() + 6, data.end());

            last_incoming_time_ = std::chrono::steady_clock::now();
            if (on_incoming_audio_ != nullptr) {
                on_incoming_audio_(std::move(packet));
            }
            break;
        }
        case kFrameTypeError: {
            std::string message(data.begin(), data.end());
            ESP_LOGE(TAG, "Gateway reported error: %s", message.c_str());
            SetError(message);
            break;
        }
        case kFrameTypeJson:
        default: {
            std::string json(reinterpret_cast<const char*>(data.data()), data.size());
            cJSON* root = cJSON_Parse(json.c_str());
            if (root == nullptr) {
                ESP_LOGE(TAG, "Failed to parse json message");
                return;
            }

            bool handled = false;
            auto* type_item = cJSON_GetObjectItem(root, "type");
            if (cJSON_IsString(type_item)) {
                if (strcmp(type_item->valuestring, "hello") == 0) {
                    ParseServerHello(root);
                    handled = true;
                } else if (strcmp(type_item->valuestring, "goodbye") == 0) {
                    auto* session_id = cJSON_GetObjectItem(root, "session_id");
                    if (cJSON_IsString(session_id) && session_id_ == session_id->valuestring) {
                        last_incoming_time_ = std::chrono::steady_clock::now();
                        CloseAudioChannel(false);
                    }
                    handled = true;
                } else if (strcmp(type_item->valuestring, "ping") == 0) {
                    // Gateway keepalive, keep the channel alive.
                    handled = true;
                }
            }

            if (!handled && on_incoming_json_ != nullptr) {
                on_incoming_json_(root);
            }
            cJSON_Delete(root);
            break;
        }
    }
}

void EspNowProtocol::ParseServerHello(const cJSON* root) {
    auto* session_id = cJSON_GetObjectItem(root, "session_id");
    if (cJSON_IsString(session_id)) {
        session_id_ = session_id->valuestring;
        ESP_LOGI(TAG, "Session ID: %s", session_id_.c_str());
    }

    auto* audio_params = cJSON_GetObjectItem(root, "audio_params");
    if (cJSON_IsObject(audio_params)) {
        auto* sample_rate = cJSON_GetObjectItem(audio_params, "sample_rate");
        if (cJSON_IsNumber(sample_rate)) {
            server_sample_rate_ = sample_rate->valueint;
        }
        auto* frame_duration = cJSON_GetObjectItem(audio_params, "frame_duration");
        if (cJSON_IsNumber(frame_duration)) {
            server_frame_duration_ = frame_duration->valueint;
        }
    }

    xEventGroupSetBits(event_group_handle_, ESPNOW_PROTOCOL_SERVER_HELLO_EVENT);
}