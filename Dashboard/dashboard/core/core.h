#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <gdiplus.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <functional>
#include <memory>
#include <mmsystem.h>
#include <mmreg.h>

#ifdef CORE_EXPORTS
#  define CORE_API __declspec(dllexport)
#else
#  define CORE_API __declspec(dllimport)
#endif

static constexpr uint8_t PKT_HANDSHAKE = 0x01;
static constexpr uint8_t PKT_HANDSHAKE_ACK = 0x02;
static constexpr uint8_t PKT_HANDSHAKE_DENY = 0x03;
static constexpr uint8_t PKT_VIDEO_FRAME = 0x04;
static constexpr uint8_t PKT_HEARTBEAT = 0x05;
static constexpr uint8_t PKT_HEARTBEAT_ACK = 0x06;
static constexpr uint8_t PKT_AUDIO_FRAME = 0x12;
static constexpr uint8_t PKT_MOUSE_EVENT = 0x10;
static constexpr uint8_t PKT_KEY_EVENT = 0x11;
static constexpr uint8_t PKT_DISCONNECT = 0xFF;

CORE_API int  Core_GetVideoPort();
CORE_API int  Core_GetInputPort();
CORE_API int  Core_GetAudioPort();
CORE_API void Core_SetVideoPorts(int video, int input, int audio);

namespace AES128 {
    struct AESCtx { uint8_t rk[176]; };
    CORE_API void DeriveKey(const std::string& passphrase, uint8_t key[16]);
    CORE_API void KeyExpansion(const uint8_t* key, uint8_t* rk);
    CORE_API void CTR_XOR(const AESCtx& ctx, uint64_t counter, uint8_t* buf, size_t len);
}

CORE_API void Core_SetupAES(const std::string& passphrase);

CORE_API void Core_DisableAES();

CORE_API void Core_ResetAESCounters();

CORE_API bool Core_IsAESEnabled();

CORE_API void CryptVideoRecv(std::vector<uint8_t>& buf);
CORE_API void CryptInputSend(std::vector<uint8_t>& buf);

struct RecvBandwidthMonitor {
    static constexpr int    FPS_TARGET = 30;
    static constexpr int    FPS_MIN = 28;
    static constexpr double EMA_ALPHA = 0.20;
    static constexpr int    RING_SIZE = FPS_TARGET * 2 + 8;

    double  frame_times[RING_SIZE] = {};
    int     ring_head = 0;
    int     ring_count = 0;

    double  ema_fps = 0.0;
    double  last_fps_sample = 0.0;
    int     frame_tick = 0;

    long long bytes_this_sec = 0;
    long long bytes_last_sec = 0;
    double    bytes_tick = 0.0;

    std::atomic<bool> congested{ false };

    bool      on_frame_received(size_t byte_len, bool newer_queued);
    double    measured_fps()   const { return ema_fps; }
    long long throughput_bps() const { return bytes_last_sec * 8; }
    bool      is_congested()   const { return congested.load(); }
    void      reset();
};

CORE_API void      Core_BwReset();
CORE_API bool      Core_BwOnFrameReceived(size_t byte_len, bool newer_queued);
CORE_API double    Core_BwMeasuredFps();
CORE_API long long Core_BwThroughputBps();
CORE_API bool      Core_BwIsCongested();

CORE_API std::vector<uint8_t> make_packet(uint8_t type,
    const uint8_t* data = nullptr,
    uint32_t len = 0);
CORE_API bool send_packet(SOCKET s, uint8_t type,
    const uint8_t* data = nullptr,
    uint32_t len = 0);
CORE_API bool recv_exact(SOCKET s, uint8_t* buf, int n);
CORE_API bool recv_packet(SOCKET s, uint8_t& type, std::vector<uint8_t>& data);

CORE_API HBITMAP decode_jpeg(const uint8_t* jpg, size_t jpg_len,
    int& out_w, int& out_h);
CORE_API void    blit_bitmap(HDC hdc, HBITMAP hbm,
    int srcW, int srcH,
    int dstX, int dstY,
    int dstW, int dstH);
CORE_API HBITMAP make_remote_cursor_bmp(int size = 24);

struct CORE_API PendingFrame {
    std::vector<uint8_t> jpeg;
    uint32_t cx_n = 0;
    uint32_t cy_n = 0;
};

class CORE_API InputConnection {
public:
    std::string       host;
    SOCKET            sock = INVALID_SOCKET;
    std::atomic<bool> running{ false };
    int               input_port = 55001;

    explicit InputConnection(const std::string& h);

    bool connect(double timeout_sec = 60.0);
    void send_mouse(int16_t x, int16_t y,
        const char* event, const char* button = "");
    void send_key(uint32_t vk, bool pressed);
    void disconnect();
};

class CORE_API VideoConnection {
public:
    std::string host;
    std::string controller_name;
    SOCKET      sock = INVALID_SOCKET;
    std::atomic<bool> running{ false };
    int         video_port = 55000;

    std::function<void(PendingFrame)>  frame_callback;
    std::function<void(std::string)>   status_callback;
    std::function<bool()>              pending_check_callback;

    std::thread recv_thread;

    explicit VideoConnection(const std::string& h, const std::string& name);

    std::pair<bool, std::string> connect_video();
    void recv_loop();
    void disconnect();
};

CORE_API void Core_SetAudioVolume(float v);
CORE_API void Core_AudioStopEvtCreate();
CORE_API void Core_AudioStopEvtSignal();
CORE_API void Core_AudioStopEvtClose();
CORE_API bool Core_AudioStopEvtValid();

CORE_API void AudioPlaybackThread(SOCKET sock);