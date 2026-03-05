#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <objbase.h>
#include <ocidl.h>
#include <ole2.h>
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
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cmath>
#include <fstream>
#include <commdlg.h>
#include <mmsystem.h>
#include <mmreg.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "msimg32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "comdlg32.lib")

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

static int VIDEO_PORT = 55000;
static int INPUT_PORT = 55001;
static int AUDIO_PORT = 55002;

namespace AES128 {
    static const uint8_t SBOX[256] = {
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
    };
    static const uint8_t RCON[11] = { 0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36 };
    static uint8_t gmul(uint8_t a, uint8_t b) {
        uint8_t r = 0;
        for (int i = 0; i < 8; i++) {
            if (b & 1) r ^= a;
            bool hi = (a & 0x80) != 0;
            a <<= 1;
            if (hi) a ^= 0x1b;
            b >>= 1;
        }
        return r;
    }
    struct AESCtx { uint8_t rk[176]; };
    static void KeyExpansion(const uint8_t* key, uint8_t* rk) {
        memcpy(rk, key, 16);
        for (int i = 4; i < 44; i++) {
            uint8_t tmp[4]; memcpy(tmp, &rk[(i - 1) * 4], 4);
            if (i % 4 == 0) {
                uint8_t t = tmp[0];
                tmp[0] = SBOX[tmp[1]] ^ RCON[i / 4];
                tmp[1] = SBOX[tmp[2]];
                tmp[2] = SBOX[tmp[3]];
                tmp[3] = SBOX[t];
            }
            for (int j = 0; j < 4; j++)
                rk[i * 4 + j] = rk[(i - 4) * 4 + j] ^ tmp[j];
        }
    }
    static void AddRoundKey(uint8_t s[16], const uint8_t* rk) { for (int i = 0; i < 16; i++) s[i] ^= rk[i]; }
    static void SubBytes(uint8_t s[16]) { for (int i = 0; i < 16; i++) s[i] = SBOX[s[i]]; }
    static void ShiftRows(uint8_t s[16]) {
        uint8_t t;
        t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
        t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
        t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
    }
    static void MixColumns(uint8_t s[16]) {
        for (int c = 0; c < 4; c++) {
            uint8_t* col = s + c * 4; uint8_t a = col[0], b = col[1], cc = col[2], d = col[3];
            col[0] = gmul(a, 2) ^ gmul(b, 3) ^ cc ^ d; col[1] = a ^ gmul(b, 2) ^ gmul(cc, 3) ^ d;
            col[2] = a ^ b ^ gmul(cc, 2) ^ gmul(d, 3); col[3] = gmul(a, 3) ^ b ^ cc ^ gmul(d, 2);
        }
    }
    static void AES_EncryptBlock(const uint8_t* rk, const uint8_t in[16], uint8_t out[16]) {
        uint8_t s[16]; memcpy(s, in, 16);
        AddRoundKey(s, rk);
        for (int r = 1; r < 10; r++) { SubBytes(s); ShiftRows(s); MixColumns(s); AddRoundKey(s, rk + r * 16); }
        SubBytes(s); ShiftRows(s); AddRoundKey(s, rk + 160);
        memcpy(out, s, 16);
    }
    static void CTR_XOR(const AESCtx& ctx, uint64_t counter, uint8_t* buf, size_t len) {
        uint8_t ctr_block[16] = {};
        size_t offset = 0;
        while (offset < len) {
            uint64_t ctr_be = 0;
            for (int i = 0; i < 8; i++) ctr_be = (ctr_be << 8) | ((counter >> (56 - i * 8)) & 0xFF);
            memset(ctr_block, 0, 8); memcpy(ctr_block + 8, &ctr_be, 8);
            uint8_t ks[16]; AES_EncryptBlock(ctx.rk, ctr_block, ks);
            size_t chunk = (len - offset < 16) ? (len - offset) : 16;
            for (size_t i = 0; i < chunk; i++) buf[offset + i] ^= ks[i];
            offset += chunk; counter++;
        }
    }
    static void DeriveKey(const std::string& passphrase, uint8_t key[16]) {
        memset(key, 0x5A, 16);
        for (size_t i = 0; i < passphrase.size(); i++)
            key[i % 16] ^= (uint8_t)passphrase[i] ^ (uint8_t)(i * 0x9B);
        for (int r = 0; r < 4096; r++)
            for (int b = 0; b < 16; b++)
                key[b] = SBOX[key[b] ^ (uint8_t)r ^ key[(b + 7) % 16]];
    }
}

static AES128::AESCtx   g_aes_ctx;
static bool             g_aes_enabled = false;
static std::atomic<uint64_t> g_aes_inp_send_ctr{ 0 };

static std::atomic<uint64_t> g_aes_vid_recv_ctr{ 0 };

static void CryptVideoRecv(std::vector<uint8_t>& buf) {
    if (!g_aes_enabled || buf.empty()) return;
    uint64_t ctr = g_aes_vid_recv_ctr.fetch_add(1);
    AES128::CTR_XOR(g_aes_ctx, ctr, buf.data(), buf.size());
}
static void CryptInputSend(std::vector<uint8_t>& buf) {
    if (!g_aes_enabled || buf.empty()) return;
    uint64_t ctr = g_aes_inp_send_ctr.fetch_add(1);
    AES128::CTR_XOR(g_aes_ctx, ctr, buf.data(), buf.size());
}


struct RecvBandwidthMonitor {
    static constexpr int    FPS_TARGET = 30;
    static constexpr int    FPS_MIN = 28;  
    static constexpr double EMA_ALPHA = 0.20;
    static constexpr int RING_SIZE = FPS_TARGET * 2 + 8;

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
    bool on_frame_received(size_t byte_len, bool newer_queued)
    {
        double now_s = (double)GetTickCount64() / 1000.0;

        frame_tick++;
        bool warmed_up = (frame_tick >= 60);

        frame_times[ring_head] = now_s;
        ring_head = (ring_head + 1) % RING_SIZE;
        if (ring_count < RING_SIZE) ring_count++;

        int   fps_raw = 0;
        double window = 1.0;
        for (int i = 0; i < ring_count; i++) {
            int idx = (ring_head - 1 - i + RING_SIZE) % RING_SIZE;
            if ((now_s - frame_times[idx]) <= window) fps_raw++;
            else break;
        }

        if ((now_s - last_fps_sample) >= 0.5) {
            double instantaneous = (double)fps_raw;
            if (ema_fps < 0.1) ema_fps = instantaneous; 
            else ema_fps = EMA_ALPHA * instantaneous + (1.0 - EMA_ALPHA) * ema_fps;
            last_fps_sample = now_s;
        }

        bytes_this_sec += (long long)byte_len;
        if ((now_s - bytes_tick) >= 1.0) {
            bytes_last_sec = bytes_this_sec;
            bytes_this_sec = 0;
            bytes_tick = now_s;
        }

        if (warmed_up && ema_fps > 0.5) {
            congested = (ema_fps < FPS_MIN);
        }
        else {
            congested = false;  
        }

        if (warmed_up && newer_queued && congested) {
            return false; 
        }
        return true;      
    }

    double measured_fps() const { return ema_fps; }
    long long throughput_bps() const { return bytes_last_sec * 8; }
    bool is_congested() const { return congested.load(); }

    void reset() {
        ring_head = ring_count = frame_tick = 0;
        ema_fps = last_fps_sample = bytes_tick = 0.0;
        bytes_this_sec = bytes_last_sec = 0;
        congested = false;
    }
};

static RecvBandwidthMonitor g_recv_bw;

static constexpr int ID_BTN_CONNECT = 101;
static constexpr int ID_BTN_DISCONNECT = 102;
static constexpr int ID_BTN_DEBUG = 103;
static constexpr int ID_EDIT_APORT = 120;
static constexpr int ID_BTN_VOLUME = 121;
static constexpr int ID_EDIT_IP = 104;
static constexpr int ID_EDIT_NAME = 105;

static constexpr int ID_EDIT_VPORT = 106;
static constexpr int ID_EDIT_IPORT = 107;
static constexpr int ID_EDIT_PASS = 108;
static constexpr int ID_CHK_INTERNET = 109;
static constexpr int ID_CHK_DEBUG = 110;

static constexpr int ID_BTN_EXPORT = 111;

static constexpr int ID_CHK_STARTUP = 112;

static constexpr int ID_EDIT_IP_GHOST = 113;

static constexpr UINT WM_APP_STATUS = WM_APP + 1;
static constexpr UINT WM_APP_FRAME = WM_APP + 2;
static constexpr UINT WM_APP_DISCONN = WM_APP + 3;
static constexpr UINT WM_APP_CONNECTED = WM_APP + 4;
static constexpr UINT WM_APP_SHOW_SESSION = WM_APP + 5;
static constexpr UINT WM_APP_SHOW_CONNECT = WM_APP + 6;
static constexpr UINT WM_APP_CONN_CANCEL = WM_APP + 7;

static constexpr int ID_OVERLAY_CANCEL = 200;
static constexpr int ID_OVERLAY_TIMER = 1;

static constexpr int ID_OVERLAY_LATE_TIMER = 2;

static inline uint32_t hton32(uint32_t v) { return htonl(v); }
static inline uint32_t ntoh32(uint32_t v) { return ntohl(v); }
static inline uint16_t hton16(uint16_t v) { return htons(v); }

static std::vector<uint8_t> make_packet(uint8_t type, const uint8_t* data = nullptr, uint32_t len = 0)
{
    std::vector<uint8_t> pkt(5 + len);
    pkt[0] = type;
    uint32_t nlen = hton32(len);
    memcpy(&pkt[1], &nlen, 4);
    if (data && len) memcpy(&pkt[5], data, len);
    return pkt;
}

static bool send_packet(SOCKET s, uint8_t type, const uint8_t* data = nullptr, uint32_t len = 0)
{
    auto pkt = make_packet(type, data, len);
    int sent = 0;
    while (sent < (int)pkt.size()) {
        int r = ::send(s, (const char*)pkt.data() + sent, (int)pkt.size() - sent, 0);
        if (r <= 0) return false;
        sent += r;
    }
    return true;
}

static bool recv_exact(SOCKET s, uint8_t* buf, int n)
{
    int got = 0;
    while (got < n) {
        int r = ::recv(s, (char*)buf + got, n - got, 0);
        if (r <= 0) return false;
        got += r;
    }
    return true;
}

static bool recv_packet(SOCKET s, uint8_t& type, std::vector<uint8_t>& data)
{
    uint8_t hdr[5];
    if (!recv_exact(s, hdr, 5)) return false;
    type = hdr[0];
    uint32_t len;
    memcpy(&len, &hdr[1], 4);
    len = ntoh32(len);
    data.resize(len);
    if (len > 0 && !recv_exact(s, data.data(), len)) return false;
    return true;
}

static HBITMAP decode_jpeg(const uint8_t* jpg, size_t jpg_len, int& out_w, int& out_h)
{

    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, jpg_len);
    if (!hg) return NULL;
    void* p = GlobalLock(hg);
    if (!p) { GlobalFree(hg); return NULL; }
    memcpy(p, jpg, jpg_len);
    GlobalUnlock(hg);

    IStream* stream = nullptr;
    if (CreateStreamOnHGlobal(hg, TRUE, &stream) != S_OK) {
        GlobalFree(hg); return NULL;
    }

    Gdiplus::Bitmap* bmp = Gdiplus::Bitmap::FromStream(stream);
    stream->Release();
    if (!bmp || bmp->GetLastStatus() != Gdiplus::Ok) {
        delete bmp; return NULL;
    }

    out_w = (int)bmp->GetWidth();
    out_h = (int)bmp->GetHeight();

    HBITMAP hbm = NULL;
    bmp->GetHBITMAP(Gdiplus::Color(0, 0, 0), &hbm);
    delete bmp;
    return hbm;
}

static void blit_bitmap(HDC hdc, HBITMAP hbm, int srcW, int srcH,
    int dstX, int dstY, int dstW, int dstH)
{
    HDC mdc = CreateCompatibleDC(hdc);
    HGDIOBJ old = SelectObject(mdc, hbm);
    SetStretchBltMode(hdc, HALFTONE);
    StretchBlt(hdc, dstX, dstY, dstW, dstH, mdc, 0, 0, srcW, srcH, SRCCOPY);
    SelectObject(mdc, old);
    DeleteDC(mdc);
}

static HBITMAP make_remote_cursor_bmp(int size = 24)
{

    Gdiplus::Bitmap bmp(size, size, PixelFormat32bppARGB);
    Gdiplus::Graphics g(&bmp);
    g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);

    Gdiplus::PointF arrow[] = {
        {0,0},{0,14},{4,10},{7,17},{9,16},{6,9},{11,9}
    };
    int N = 7;

    Gdiplus::SolidBrush black(Gdiplus::Color(220, 0, 0, 0));
    g.FillPolygon(&black, arrow, N);

    Gdiplus::PointF inner[7];
    for (int i = 0; i < N; i++) {
        float x = arrow[i].X, y = arrow[i].Y;
        inner[i] = { x + 1.0f, y + 1.0f };
    }
    Gdiplus::SolidBrush white(Gdiplus::Color(255, 255, 255, 255));
    g.FillPolygon(&white, inner, N);

    HBITMAP hbm = NULL;
    bmp.GetHBITMAP(Gdiplus::Color(0, 0, 0, 0), &hbm);
    return hbm;
}

class InputConnection {
public:
    std::string host;
    SOCKET sock = INVALID_SOCKET;
    std::atomic<bool> running{ false };

    explicit InputConnection(const std::string& h) : host(h) {}

    int input_port = 55001;

    bool connect(double timeout_sec = 60.0)
    {
        auto deadline = std::chrono::steady_clock::now() +
            std::chrono::duration<double>(timeout_sec);
        while (std::chrono::steady_clock::now() < deadline) {
            SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s == INVALID_SOCKET) return false;

            DWORD tv = 5000;
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));

            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons((u_short)input_port);

            struct addrinfo hints {}, * res = nullptr;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            char portstr[8]; sprintf_s(portstr, "%d", input_port);
            if (getaddrinfo(host.c_str(), portstr, &hints, &res) == 0 && res) {
                addr = *reinterpret_cast<sockaddr_in*>(res->ai_addr);
                addr.sin_port = htons((u_short)input_port);
                freeaddrinfo(res);
            }
            else {
                inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
            }

            if (::connect(s, (sockaddr*)&addr, sizeof(addr)) == 0) {

                tv = 0;
                setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
                BOOL nd = 1;
                setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char*)&nd, sizeof(nd));
                sock = s;
                running = true;
                return true;
            }
            closesocket(s);
            Sleep(500);
        }
        return false;
    }

    void send_mouse(int16_t x, int16_t y, const char* event, const char* button = "")
    {
        if (!running || sock == INVALID_SOCKET) return;
        uint8_t payload[12];

        int16_t nx = (int16_t)hton16((uint16_t)x);
        int16_t ny = (int16_t)hton16((uint16_t)y);
        memcpy(payload + 0, &nx, 2);
        memcpy(payload + 2, &ny, 2);
        char ev4[4] = { ' ',' ',' ',' ' }, bt4[4] = { ' ',' ',' ',' ' };
        strncpy(ev4, event, 4);
        strncpy(bt4, button, 4);
        memcpy(payload + 4, ev4, 4);
        memcpy(payload + 8, bt4, 4);

        std::vector<uint8_t> enc_m(payload, payload + 12);
        CryptInputSend(enc_m);
        send_packet(sock, PKT_MOUSE_EVENT, enc_m.data(), 12);
    }

    void send_key(uint32_t vk, bool pressed)
    {
        if (!running || sock == INVALID_SOCKET) return;
        uint8_t payload[5];
        uint32_t nvk = hton32(vk);
        memcpy(payload, &nvk, 4);
        payload[4] = pressed ? 1 : 0;

        std::vector<uint8_t> enc_k(payload, payload + 5);
        CryptInputSend(enc_k);
        send_packet(sock, PKT_KEY_EVENT, enc_k.data(), 5);
    }

    void disconnect()
    {
        running = false;
        if (sock != INVALID_SOCKET) {
            send_packet(sock, PKT_DISCONNECT);
            closesocket(sock);
            sock = INVALID_SOCKET;
        }
    }
};

struct PendingFrame {
    std::vector<uint8_t> jpeg;
    uint32_t cx_n = 0;
    uint32_t cy_n = 0;
};

class VideoConnection {
public:
    std::string host;
    std::string controller_name;
    SOCKET sock = INVALID_SOCKET;
    std::atomic<bool> running{ false };

    std::function<void(PendingFrame)> frame_callback;
    std::function<void(std::string)>  status_callback;
    std::function<bool()>             pending_check_callback; 

    std::thread recv_thread;

    explicit VideoConnection(const std::string& h, const std::string& name)
        : host(h), controller_name(name) {
    }

    int video_port = 55000;

    std::pair<bool, std::string> connect_video()
    {
        SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return { false,"socket() failed" };

        DWORD tv = 10000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons((u_short)video_port);
        struct addrinfo hints {}, * res = nullptr;
        hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
        char portstr[8]; sprintf_s(portstr, "%d", video_port);
        if (getaddrinfo(host.c_str(), portstr, &hints, &res) == 0 && res) {
            addr = *reinterpret_cast<sockaddr_in*>(res->ai_addr);
            addr.sin_port = htons((u_short)video_port);
            freeaddrinfo(res);
        }
        else {
            inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
        }

        if (::connect(s, (sockaddr*)&addr, sizeof(addr)) != 0) {
            closesocket(s);
            int e = WSAGetLastError();
            if (e == WSAECONNREFUSED) return { false,"Connection refused - is the host program running?" };
            return { false,"Connect failed (WSA " + std::to_string(e) + ")" };
        }
        BOOL nd = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char*)&nd, sizeof(nd));

        std::string name64 = controller_name.substr(0, 64);
        send_packet(s, PKT_HANDSHAKE, (uint8_t*)name64.c_str(), (uint32_t)name64.size());

        tv = 120000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));

        uint8_t ptype; std::vector<uint8_t> pdata;
        if (!recv_packet(s, ptype, pdata)) {
            closesocket(s); return { false,"No response from host" };
        }
        tv = 0;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));

        if (ptype == PKT_HANDSHAKE_ACK) {
            sock = s;
            running = true;
            recv_thread = std::thread(&VideoConnection::recv_loop, this);
            return { true,"Connected" };
        }
        else if (ptype == PKT_HANDSHAKE_DENY) {
            std::string reason(pdata.begin(), pdata.end());
            closesocket(s);
            return { false, reason.empty() ? "Denied by host" : reason };
        }
        else {
            closesocket(s);
            return { false,"Unexpected handshake response" };
        }
    }

    void recv_loop()
    {
        int rcvbuf = 4 * 1024 * 1024;
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&rcvbuf, sizeof(rcvbuf));

        g_recv_bw.reset();

        while (running) {
            uint8_t ptype; std::vector<uint8_t> pdata;
            if (!recv_packet(sock, ptype, pdata)) break;

            if (ptype == PKT_VIDEO_FRAME && pdata.size() > 8) {

                CryptVideoRecv(pdata);
                uint32_t cx_n, cy_n;
                memcpy(&cx_n, pdata.data() + 0, 4); cx_n = ntoh32(cx_n);
                memcpy(&cy_n, pdata.data() + 4, 4); cy_n = ntoh32(cy_n);
                PendingFrame pf;
                pf.jpeg.assign(pdata.begin() + 8, pdata.end());
                pf.cx_n = cx_n;
                pf.cy_n = cy_n;

                bool newer_queued = pending_check_callback
                    ? pending_check_callback() : false;

                bool should_render = g_recv_bw.on_frame_received(
                    pdata.size(), newer_queued);

                if (should_render && frame_callback)
                    frame_callback(std::move(pf));

            }
            else if (ptype == PKT_HEARTBEAT) {
                send_packet(sock, PKT_HEARTBEAT_ACK);
            }
            else if (ptype == PKT_DISCONNECT) {
                if (status_callback) status_callback("Host disconnected");
                break;
            }
        }
        running = false;
        if (status_callback) status_callback("Disconnected");
    }

    void disconnect()
    {
        running = false;
        if (sock != INVALID_SOCKET) {
            send_packet(sock, PKT_DISCONNECT);
            closesocket(sock);
            sock = INVALID_SOCKET;
        }
        if (recv_thread.joinable()) recv_thread.join();
    }
};

static float  g_audio_volume = 1.0f;
static HANDLE g_audio_stop_evt = NULL;

static void AudioPlaybackThread(SOCKET sock)
{
    static constexpr int    NUM = 8;
    static constexpr int    BSIZ = 17640;

    WAVEFORMATEX wfx{};
    wfx.wFormatTag = WAVE_FORMAT_PCM;
    wfx.nChannels = 2;
    wfx.nSamplesPerSec = 44100;
    wfx.wBitsPerSample = 16;
    wfx.nBlockAlign = 4;
    wfx.nAvgBytesPerSec = 44100 * 4;

    HWAVEOUT hwo = NULL;
    bool     waveout_open = false;

    std::vector<std::vector<int16_t>> rawbufs(NUM, std::vector<int16_t>(BSIZ / 2, 0));
    WAVEHDR hdr[NUM]{};
    int nxt = 0;

    DWORD rto = 5000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&rto, sizeof(rto));

    int sndbuf = 256 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&sndbuf, sizeof(sndbuf));

    for (;;) {
        if (g_audio_stop_evt &&
            WaitForSingleObject(g_audio_stop_evt, 0) == WAIT_OBJECT_0) break;

        uint8_t ph[5]; int got = 0;
        while (got < 5) {
            int r = recv(sock, (char*)ph + got, 5 - got, 0);
            if (r <= 0) {
                int err = WSAGetLastError();
                if (err == WSAETIMEDOUT) continue;
                goto aud_done;
            }
            got += r;
        }

        uint8_t  ptype = ph[0];
        uint32_t plen = 0;
        memcpy(&plen, ph + 1, 4);
        plen = ntohl(plen);
        if (plen > 512 * 1024) break;

        std::vector<uint8_t> body(plen);
        got = 0;
        while (got < (int)plen) {
            int r = recv(sock, (char*)body.data() + got, (int)plen - got, 0);
            if (r <= 0) {
                int err = WSAGetLastError();
                if (err == WSAETIMEDOUT) continue;
                goto aud_done;
            }
            got += r;
        }

        if (ptype == PKT_DISCONNECT) break;
        if (ptype != PKT_AUDIO_FRAME || plen <= 4) continue;

        uint32_t pktSR = 44100;
        memcpy(&pktSR, body.data(), 4);
        if (pktSR < 8000 || pktSR > 192000) pktSR = 44100;

        if (!waveout_open) {
            wfx.nSamplesPerSec = pktSR;
            wfx.nAvgBytesPerSec = pktSR * 4;
            if (waveOutOpen(&hwo, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL) != MMSYSERR_NOERROR)
                goto aud_done;
            for (int i = 0; i < NUM; i++) {
                hdr[i].lpData = (LPSTR)rawbufs[i].data();
                hdr[i].dwBufferLength = BSIZ;
                waveOutPrepareHeader(hwo, &hdr[i], sizeof(WAVEHDR));
                hdr[i].dwFlags |= WHDR_DONE;
            }
            waveout_open = true;
        }

        size_t nBytes = plen - 4;
        const int16_t* src = reinterpret_cast<const int16_t*>(body.data() + 4);

        WAVEHDR& wh = hdr[nxt];
        for (int w = 0; w < 200 && !(wh.dwFlags & WHDR_DONE); w++) Sleep(1);
        if (!(wh.dwFlags & WHDR_DONE)) {
            nxt = (nxt + 1) % NUM;
            continue;
        }

        float  vol = g_audio_volume;
        size_t copyBytes = (nBytes < BSIZ) ? nBytes : BSIZ;
        size_t copySamples = copyBytes / 2;
        int16_t* dst = rawbufs[nxt].data();
        for (size_t i = 0; i < copySamples; i++) {
            float s = src[i] * vol;
            dst[i] = (int16_t)(s > 32767.f ? 32767 : s < -32768.f ? -32768 : s);
        }
        wh.dwBufferLength = (DWORD)copyBytes;
        wh.dwFlags &= ~WHDR_DONE;
        waveOutWrite(hwo, &wh, sizeof(WAVEHDR));
        nxt = (nxt + 1) % NUM;
    }
aud_done:
    if (waveout_open && hwo) {
        waveOutReset(hwo);
        for (int i = 0; i < NUM; i++)
            waveOutUnprepareHeader(hwo, &hdr[i], sizeof(WAVEHDR));
        waveOutClose(hwo);
    }
    shutdown(sock, SD_BOTH);
    closesocket(sock);
}

class ControllerApp {
public:
    HWND hwnd = NULL;

    HWND hConnectWnd = NULL;
    HWND hEditIP = NULL;
    HWND hEditName = NULL;
    HWND hBtnConnect = NULL;
    HWND hChkDebug = NULL;

    HWND hConnectStatus = NULL;

    HWND hSessionWnd = NULL;
    HWND hCanvas = NULL;
    HWND hBtnDisconn = NULL;
    HWND hBtnDebug = NULL;
    HWND hStatusBar = NULL;
    HWND hLockLabel = NULL;

    HWND hDebugWin = NULL;
    bool debugVisible = false;

    HWND  hLoadingWnd = NULL;

    HWND  hLoadingLabel = NULL;

    HWND  hLoadingLate = NULL;

    HWND  hLoadingCancel = NULL;

    int   spinAngle = 0;

    std::atomic<bool> g_connect_cancelled{ false };

    void show_loading_overlay();
    void hide_loading_overlay();
    void cancel_connect();
    void tick_spinner();
    void show_late_label();
    void export_settings();
    void show_volume_menu();
    void set_volume_level(int cmd_id);
    void update_ip_placeholder();

    HWND hChkStartup = NULL;

    HWND hIpGhost = NULL;

    std::unique_ptr<VideoConnection> video_conn;
    std::unique_ptr<InputConnection> input_conn;
    std::thread audio_thread;
    HWND        hBtnVolume = NULL;
    int         volumePct = 100;

    std::mutex   frame_mutex;
    std::unique_ptr<PendingFrame> pending_frame;
    std::atomic<bool> frame_scheduled{ false };

    HBITMAP hFrameBmp = NULL;
    int     frameSrcW = 0, frameSrcH = 0;
    double  cursorRatX = 0, cursorRatY = 0;
    double  vCursorX = 0.5, vCursorY = 0.5;
    bool    firstFrame = true;

    HBITMAP hCursorBmp = NULL;
    static constexpr int CURSOR_SIZE = 24;

    bool     cursor_locked = false;
    int      pin_cx = 0, pin_cy = 0;
    HWND     raw_hwnd = NULL;
    std::thread raw_thread;
    std::atomic<bool> raw_running{ false };
    std::atomic<int>  warp_pending{ 0 };

    HHOOK    kb_hook = NULL;

    std::atomic<long> dbg_raw_events{ 0 };
    std::atomic<long> dbg_pkts_sent{ 0 };
    std::atomic<long> dbg_frames{ 0 };
    std::atomic<int>  dbg_last_dx{ 0 };
    std::atomic<int>  dbg_last_dy{ 0 };
    double dbg_fps = 0.0;
    double dbg_fps_time = 0.0;
    long   dbg_frame_tick = 0;

    static constexpr double MOUSE_SPEED = 1.0;

    bool init(HINSTANCE hInst);
    void run();
    void destroy();

    LRESULT handle_message(HWND h, UINT msg, WPARAM wp, LPARAM lp);

    void on_connect();
    void on_disconnect_btn();
    void on_disconnected();
    void create_session_window();
    void destroy_session_window();
    void on_close();
    void set_status(const std::string& s);
    void lock_cursor();
    void unlock_cursor();
    void toggle_debug();
    void update_debug();
    void on_paint_canvas(HDC hdc);
    void on_frame(PendingFrame pf);
    void render_frame();
    void fit_window_to_frame(int rw, int rh);

    void start_listeners();
    void stop_listeners();
    void raw_input_loop();
    void handle_raw_input(LPARAM lp);

    void fwd_key(WPARAM vk, bool pressed);

    static LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
    LRESULT CALLBACK CanvasProc(HWND, UINT, WPARAM, LPARAM);
    static LRESULT CALLBACK DebugProc(HWND, UINT, WPARAM, LPARAM);

private:
    HINSTANCE hInstance = NULL;

    bool show_consent_dialog();
};

static ControllerApp* g_app = nullptr;

static INT_PTR CALLBACK ConsentDlgProc(HWND hDlg, UINT msg, WPARAM wp, LPARAM)
{
    switch (msg) {
    case WM_INITDIALOG: {
        SetWindowText(hDlg, L"Authorization Required");

        int winWidth = 500;
        int winHeight = 550;

        SetWindowPos(hDlg, NULL, 0, 0, winWidth, winHeight, SWP_NOMOVE | SWP_NOZORDER);

        HWND hText = GetDlgItem(hDlg, 101);
        MoveWindow(hText, 20, 20, winWidth - 50, winHeight - 150, TRUE);

        int buttonY = winHeight - 100;

        int btnWidth = 100;
        int btnHeight = 30;

        MoveWindow(GetDlgItem(hDlg, IDOK), (winWidth / 2) - 110, buttonY, btnWidth, btnHeight, TRUE);

        MoveWindow(GetDlgItem(hDlg, IDCANCEL), (winWidth / 2) + 10, buttonY, btnWidth, btnHeight, TRUE);

        return TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK)     EndDialog(hDlg, 1);
        if (LOWORD(wp) == IDCANCEL) EndDialog(hDlg, 0);
        return TRUE;
    }
    return FALSE;
}

struct ConsentResult { bool accepted = false; };
static ConsentResult g_consent;

static LRESULT CALLBACK ConsentWndProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        const wchar_t* txt =
            L"IMPORTANT - READ BEFORE CONTINUING\r\n\r\n"
            L"This tool will:\r\n"
            L"  * Stream the REMOTE machine's screen to this window\r\n"
            L"  * Forward your keyboard and mouse inputs to the remote machine\r\n\r\n"
            L"You MUST have explicit permission from the owner of the remote\r\n"
            L"computer before connecting.\r\n\r\n"
            L"Unauthorised access to computer systems is illegal.\r\n\r\n"
            L"The remote machine will display a visible connection notice\r\n"
            L"and can disconnect at any time.";

        RECT rc;
        GetClientRect(hWnd, &rc);

        int clientW = rc.right - rc.left;
        int clientH = rc.bottom - rc.top;

        int margin = 15;

        int editHeight = clientH - 90;

        HWND hEdit = CreateWindowW(
            L"EDIT", txt,
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY |
            WS_VSCROLL | ES_AUTOVSCROLL,
            margin,
            margin,
            clientW - margin * 2,
            editHeight,
            hWnd, NULL, NULL, NULL);

        SendMessage(hEdit, WM_SETFONT,
            (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);

        int btnContinueW = 230;
        int btnCancelW = 100;
        int btnH = 30;
        int spacing = 15;

        int totalW = btnContinueW + spacing + btnCancelW;
        int startX = (clientW - totalW) / 2;
        int buttonY = clientH - btnH - 20;

        HWND hOK = CreateWindowW(
            L"BUTTON", L"I have permission - Continue",
            WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
            startX,
            buttonY,
            btnContinueW,
            btnH,
            hWnd, (HMENU)IDOK, NULL, NULL);

        SendMessage(hOK, WM_SETFONT,
            (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);

        HWND hCancel = CreateWindowW(
            L"BUTTON", L"Cancel",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            startX + btnContinueW + spacing,
            buttonY,
            btnCancelW,
            btnH,
            hWnd, (HMENU)IDCANCEL, NULL, NULL);

        SendMessage(hCancel, WM_SETFONT,
            (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);

        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wp))
        {
        case IDOK:
            g_consent.accepted = true;
            DestroyWindow(hWnd);
            return 0;

        case IDCANCEL:
            g_consent.accepted = false;
            DestroyWindow(hWnd);
            return 0;
        }
        break;

    case WM_CLOSE:
        g_consent.accepted = false;
        DestroyWindow(hWnd);
        return 0;
    }

    return DefWindowProcW(hWnd, msg, wp, lp);
}

bool ControllerApp::show_consent_dialog()
{
    const wchar_t* cls = L"ConsentDlgCls";

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = ConsentWndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = cls;

    RegisterClassExW(&wc);

    g_consent.accepted = false;

    RECT rc = { 0, 0, 490, 275 };

    DWORD style = WS_POPUP | WS_CAPTION | WS_SYSMENU;
    DWORD exStyle = WS_EX_DLGMODALFRAME | WS_EX_TOPMOST;

    AdjustWindowRectEx(&rc, style, FALSE, exStyle);

    HWND hDlg = CreateWindowExW(
        exStyle,
        cls,
        L"Authorization Required",
        style,
        0, 0,
        rc.right - rc.left,
        rc.bottom - rc.top,
        hwnd,
        NULL,
        hInstance,
        NULL);

    RECT pr; GetWindowRect(hwnd, &pr);
    RECT dr; GetWindowRect(hDlg, &dr);

    int dw = dr.right - dr.left;
    int dh = dr.bottom - dr.top;

    int px = (pr.left + pr.right) / 2;
    int py = (pr.top + pr.bottom) / 2;

    SetWindowPos(hDlg, HWND_TOPMOST,
        px - dw / 2,
        py - dh / 2,
        0, 0,
        SWP_NOSIZE);

    ShowWindow(hDlg, SW_SHOW);
    UpdateWindow(hDlg);

    EnableWindow(hwnd, FALSE);

    MSG msg;
    while (IsWindow(hDlg) && GetMessageW(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    EnableWindow(hwnd, TRUE);
    SetForegroundWindow(hwnd);

    UnregisterClassW(cls, hInstance);

    return g_consent.accepted;
}

static LRESULT CALLBACK CanvasProcStatic(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    if (g_app) return g_app->CanvasProc(h, msg, wp, lp);
    return DefWindowProcW(h, msg, wp, lp);
}

LRESULT ControllerApp::CanvasProc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_LBUTTONDOWN:
        if (video_conn && video_conn->running && !cursor_locked) {
            lock_cursor();

        }
        return 0;

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(h, &ps);
        on_paint_canvas(hdc);
        EndPaint(h, &ps);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

LRESULT CALLBACK ControllerApp::WndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    if (g_app) return g_app->handle_message(h, msg, wp, lp);
    return DefWindowProcW(h, msg, wp, lp);
}

LRESULT ControllerApp::handle_message(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case ID_BTN_CONNECT:    on_connect();        break;
        case ID_BTN_DISCONNECT: on_disconnect_btn(); break;
        case ID_BTN_DEBUG:      toggle_debug();      break;
        case ID_BTN_VOLUME:     show_volume_menu();  break;
        case 501: case 502: case 503: case 504: case 505: case 506:
            set_volume_level(LOWORD(wp)); break;
        case ID_OVERLAY_CANCEL: cancel_connect();    break;
        case ID_BTN_EXPORT:     export_settings();  break;
        case ID_CHK_INTERNET:

            update_ip_placeholder();
            break;
        case ID_EDIT_IP:

            if (HIWORD(wp) == EN_CHANGE) update_ip_placeholder();
            break;
        }
        return 0;

    case WM_APP_CONN_CANCEL:
        hide_loading_overlay();
        EnableWindow(hBtnConnect, TRUE);
        return 0;

    case WM_TIMER:
        if (wp == ID_OVERLAY_TIMER) {
            tick_spinner();
            return 0;
        }
        if (wp == ID_OVERLAY_LATE_TIMER) {
            KillTimer(h, ID_OVERLAY_LATE_TIMER);
            show_late_label();
            return 0;
        }
        break;

    case WM_KEYDOWN:
    case WM_SYSKEYDOWN:
        if (wp == VK_ESCAPE) { unlock_cursor(); return 0; }
        if (wp == VK_F12) { toggle_debug();  return 0; }
        return 0;

    case WM_KEYUP:
    case WM_SYSKEYUP:
        return 0;

    case WM_APP_STATUS: {

        auto* s = reinterpret_cast<std::string*>(lp);
        set_status(*s);
        bool disc = s->find("disconnect") != std::string::npos ||
            s->find("Disconnect") != std::string::npos;
        delete s;
        if (disc) on_disconnected();
        return 0;
    }
    case WM_APP_FRAME:
        render_frame();
        return 0;
    case WM_APP_DISCONN:
        on_disconnected();
        return 0;

    case WM_APP_CONNECTED: {
        SOCKET aud_sock = (SOCKET)wp;
        hide_loading_overlay();
        ShowWindow(hConnectWnd, SW_HIDE);
        create_session_window();
        hwnd = hSessionWnd;

        if (aud_sock != INVALID_SOCKET) {
            if (g_audio_stop_evt) { CloseHandle(g_audio_stop_evt); }
            g_audio_stop_evt = CreateEventW(NULL, TRUE, FALSE, NULL);
            if (audio_thread.joinable()) audio_thread.join();
            audio_thread = std::thread(AudioPlaybackThread, aud_sock);
        }
        return 0;
    }

    case WM_SIZE: {
        RECT rc; GetClientRect(h, &rc);
        int W = rc.right, H = rc.bottom;
        if (h == hSessionWnd && hCanvas && hStatusBar) {

            int barH = 36, sbH = 22;
            SetWindowPos(hStatusBar, NULL, 0, H - sbH, W, sbH, SWP_NOZORDER);
            SetWindowPos(hCanvas, NULL, 0, barH, W, std::max(1, H - barH - sbH), SWP_NOZORDER);
            MoveWindow(hBtnDisconn, 5, 5, 95, 26, TRUE);
            if (hBtnVolume) MoveWindow(hBtnVolume, 106, 5, 72, 26, TRUE);
            MoveWindow(hBtnDebug, 184, 5, 90, 26, TRUE);
            if (hLockLabel) MoveWindow(hLockLabel, 280, 9, W - 285, 18, TRUE);
            InvalidateRect(hCanvas, NULL, FALSE);
        }
        return 0;
    }

    case WM_CLOSE:
        on_close();
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

bool ControllerApp::init(HINSTANCE hInst)
{
    hInstance = hInst;
    g_app = this;

    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

    WNDCLASSEXW wcc{};
    wcc.cbSize = sizeof(wcc);
    wcc.lpfnWndProc = CanvasProcStatic;
    wcc.hInstance = hInst;
    wcc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wcc.lpszClassName = L"RDCanvasCls";
    RegisterClassExW(&wcc);

    WNDCLASSEXW wcConn{};
    wcConn.cbSize = sizeof(wcConn);
    wcConn.lpfnWndProc = WndProc;
    wcConn.hInstance = hInst;
    wcConn.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wcConn.lpszClassName = L"RDConnectCls";
    wcConn.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassExW(&wcConn);

    WNDCLASSEXW wcSess{};
    wcSess.cbSize = sizeof(wcSess);
    wcSess.lpfnWndProc = WndProc;
    wcSess.hInstance = hInst;
    wcSess.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wcSess.lpszClassName = L"RDSessionCls";
    wcSess.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassExW(&wcSess);

    const int CW = 420;

    const int CH = 468;

    DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU;
    DWORD exStyle = 0;

    RECT rc = { 0, 0, CW, CH };
    AdjustWindowRectEx(&rc, style, FALSE, exStyle);

    int winW = rc.right - rc.left;
    int winH = rc.bottom - rc.top;
    int scrW = GetSystemMetrics(SM_CXSCREEN);
    int scrH = GetSystemMetrics(SM_CYSCREEN);

    hConnectWnd = CreateWindowExW(
        exStyle, L"RDConnectCls",
        L"Remote Desktop Controller",
        style | WS_VISIBLE,
        (scrW - winW) / 2, (scrH - winH) / 2,
        winW, winH,
        NULL, NULL, hInst, NULL);

    if (!hConnectWnd) return false;
    hwnd = hConnectWnd;

    HFONT hfNormal = hFont;

    HFONT hfBold = CreateFontW(
        -MulDiv(9, GetDeviceCaps(GetDC(NULL), LOGPIXELSY), 72),
        0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    if (!hfBold) hfBold = hfNormal;

    auto lbl_np = [&](const wchar_t* text, int x, int y, int w, int h,
        bool bold = false)
        {
            HWND hw = CreateWindowW(L"STATIC", text,
                WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
                x, y, w, h, hConnectWnd, NULL, hInst, NULL);
            SendMessage(hw, WM_SETFONT, (WPARAM)(bold ? hfBold : hfNormal), TRUE);
            return hw;
        };
    auto edt = [&](const wchar_t* def, int id, int x, int y, int w, int h,
        DWORD extra = 0)
        {
            HWND hw = CreateWindowW(L"EDIT", def,
                WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | extra,
                x, y, w, h, hConnectWnd, (HMENU)(INT_PTR)id, hInst, NULL);
            SendMessage(hw, WM_SETFONT, (WPARAM)hfNormal, TRUE);
            return hw;
        };

    auto chk = [&](const wchar_t* text, int id, int x, int y, int w, int h)
        {
            HWND hw = CreateWindowW(L"BUTTON", text,
                WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX | BS_NOTIFY,
                x, y, w, h, hConnectWnd, (HMENU)(INT_PTR)id, hInst, NULL);
            SendMessage(hw, WM_SETFONT, (WPARAM)hfNormal, TRUE);
            return hw;
        };

    const int col0 = 16;
    const int col1 = 126;
    const int ctrlW = 270;
    const int rowH = 26;

    int y = 10;

    lbl_np(L"Connection", col0, y, CW - col0 * 2, 17, true);
    y += 20;

    lbl_np(L"Host / IP:", col0, y + 3, col1 - col0 - 4, 17);
    hEditIP = edt(L"", ID_EDIT_IP, col1, y, ctrlW, 22);

    hIpGhost = CreateWindowW(L"STATIC", L"e.g.  192.168.1.10",
        WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX | SS_NOTIFY,
        col1 + 4, y + 4, ctrlW - 8, 16,
        hConnectWnd, (HMENU)(INT_PTR)ID_EDIT_IP_GHOST, hInst, NULL);
    {
        HFONT hfItalic = CreateFontW(
            -MulDiv(8, GetDeviceCaps(GetDC(NULL), LOGPIXELSY), 72),
            0, 0, 0, FW_NORMAL, TRUE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        if (!hfItalic) hfItalic = hfNormal;
        SendMessage(hIpGhost, WM_SETFONT, (WPARAM)hfItalic, TRUE);
    }
    y += rowH;

    lbl_np(L"Your name:", col0, y + 3, col1 - col0 - 4, 17);
    hEditName = edt(L"Controller", ID_EDIT_NAME, col1, y, ctrlW, 22);
    y += rowH + 4;

    CreateWindowW(L"STATIC", L"",
        WS_CHILD | WS_VISIBLE | SS_ETCHEDHORZ,
        col0, y, CW - col0 * 2, 2, hConnectWnd, NULL, hInst, NULL);
    y += 6;
    lbl_np(L"Network Ports", col0, y, CW - col0 * 2, 17, true);
    y += 20;

    lbl_np(L"Video port:", col0, y + 3, col1 - col0 - 4, 17);
    edt(L"55000", ID_EDIT_VPORT, col1, y, 88, 22, ES_NUMBER);
    y += rowH;

    lbl_np(L"Input port:", col0, y + 3, col1 - col0 - 4, 17);
    edt(L"55001", ID_EDIT_IPORT, col1, y, 88, 22, ES_NUMBER);
    y += rowH;

    lbl_np(L"Audio port:", col0, y + 3, col1 - col0 - 4, 17);
    edt(L"55002", ID_EDIT_APORT, col1, y, 88, 22, ES_NUMBER);
    y += rowH;

    chk(L"WAN Discovery  (hostname or public IP)",
        ID_CHK_INTERNET, col1, y, ctrlW, 20);
    y += rowH + 4;

    CreateWindowW(L"STATIC", L"",
        WS_CHILD | WS_VISIBLE | SS_ETCHEDHORZ,
        col0, y, CW - col0 * 2, 2, hConnectWnd, NULL, hInst, NULL);
    y += 6;
    lbl_np(L"Encryption", col0, y, CW - col0 * 2, 17, true);
    y += 20;

    lbl_np(L"Passphrase:", col0, y + 3, col1 - col0 - 4, 17);
    edt(L"", ID_EDIT_PASS, col1, y, ctrlW, 22, ES_PASSWORD);
    y += rowH;

    lbl_np(L"Leave blank to disable encryption.", col1, y, ctrlW, 15);
    y += 20;

    hChkDebug = CreateWindowW(L"BUTTON", L"Show Debug Panel",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        col1, y, ctrlW, 20,
        hConnectWnd, (HMENU)(INT_PTR)ID_CHK_DEBUG, hInst, NULL);
    SendMessage(hChkDebug, WM_SETFONT, (WPARAM)hfNormal, TRUE);
    y += rowH;

    hChkStartup = CreateWindowW(L"BUTTON",
        L"Include Startup",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        col1, y, ctrlW, 20,
        hConnectWnd, (HMENU)(INT_PTR)ID_CHK_STARTUP, hInst, NULL);
    SendMessage(hChkStartup, WM_SETFONT, (WPARAM)hfNormal, TRUE);
    y += rowH + 4;

    {
        const int btnW = 230, btnH = 26;
        HWND hExp = CreateWindowW(L"BUTTON",
            L"Export Settings",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            (CW - btnW) / 2, y, btnW, btnH,
            hConnectWnd, (HMENU)(INT_PTR)ID_BTN_EXPORT, hInst, NULL);
        SendMessage(hExp, WM_SETFONT, (WPARAM)hfNormal, TRUE);
    }
    y += 30 + 6;

    {
        const int btnW = 210, btnH = 34;
        hBtnConnect = CreateWindowW(L"BUTTON", L"Connect to Desktop",
            WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
            (CW - btnW) / 2, y, btnW, btnH,
            hConnectWnd, (HMENU)(INT_PTR)ID_BTN_CONNECT, hInst, NULL);
        SendMessage(hBtnConnect, WM_SETFONT, (WPARAM)hfBold, TRUE);
    }

    hCursorBmp = make_remote_cursor_bmp(CURSOR_SIZE);
    return true;
}

static LRESULT CALLBACK LoadingOverlayProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp)
{

    if (msg == WM_COMMAND && LOWORD(wp) == ID_OVERLAY_CANCEL) {
        if (g_app && g_app->hConnectWnd)
            PostMessage(g_app->hConnectWnd, WM_COMMAND,
                MAKEWPARAM(ID_OVERLAY_CANCEL, BN_CLICKED), (LPARAM)lp);
        return 0;
    }
    if (msg == WM_PAINT)
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);

        RECT rc; GetClientRect(hWnd, &rc);
        int cx = (rc.right - rc.left) / 2;

        HBRUSH bgBrush = CreateSolidBrush(RGB(235, 235, 235));
        FillRect(hdc, &rc, bgBrush);
        DeleteObject(bgBrush);

        if (g_app)
        {
            int spinAngle = g_app->spinAngle;
            int R = 22;

            int cy_spin = 54;

            int dotR = 5;

            for (int seg = 0; seg < 8; seg++)
            {
                double angleDeg = spinAngle + seg * 45.0;
                double angleRad = angleDeg * 3.14159265 / 180.0;
                int dx = (int)(R * cos(angleRad));
                int dy = (int)(R * sin(angleRad));

                int fade = 60 + seg * 25;
                if (fade > 220) fade = 220;
                COLORREF col = RGB(fade, fade, fade);

                HBRUSH dotBrush = CreateSolidBrush(col);
                HPEN   dotPen = CreatePen(PS_SOLID, 1, col);
                HGDIOBJ oldPen = SelectObject(hdc, dotPen);
                HGDIOBJ oldBrush = SelectObject(hdc, dotBrush);

                Ellipse(hdc,
                    cx + dx - dotR, cy_spin + dy - dotR,
                    cx + dx + dotR, cy_spin + dy + dotR);

                SelectObject(hdc, oldPen);
                SelectObject(hdc, oldBrush);
                DeleteObject(dotBrush);
                DeleteObject(dotPen);
            }
        }

        EndPaint(hWnd, &ps);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wp, lp);
}

void ControllerApp::show_loading_overlay()
{
    if (hLoadingWnd) return;

    HINSTANCE hInst = hInstance;
    HFONT hfNormal = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

    const wchar_t* OVCLS = L"RDLoadingOverlay";
    WNDCLASSEXW wco{};
    wco.cbSize = sizeof(wco);
    wco.lpfnWndProc = LoadingOverlayProc;
    wco.hInstance = hInst;
    wco.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wco.hCursor = LoadCursor(NULL, IDC_WAIT);
    wco.lpszClassName = OVCLS;
    RegisterClassExW(&wco);

    RECT cr; GetClientRect(hConnectWnd, &cr);
    int ow = cr.right - cr.left;
    int oh = cr.bottom - cr.top;

    hLoadingWnd = CreateWindowExW(
        0, OVCLS, NULL,
        WS_CHILD | WS_VISIBLE,
        0, 0, ow, oh,
        hConnectWnd, NULL, hInst, NULL);

    if (!hLoadingWnd) return;

    EnumChildWindows(hConnectWnd, [](HWND child, LPARAM) -> BOOL {
        if (child != g_app->hLoadingWnd)
            EnableWindow(child, FALSE);
        return TRUE;
        }, 0);

    int cx = ow / 2;
    hLoadingLabel = CreateWindowW(L"STATIC", L"Connecting...",
        WS_CHILD | WS_VISIBLE | SS_CENTER | SS_NOPREFIX,
        cx - 110, 88, 220, 20,
        hLoadingWnd, NULL, hInst, NULL);
    SendMessage(hLoadingLabel, WM_SETFONT, (WPARAM)hfNormal, TRUE);

    hLoadingLate = CreateWindowW(L"STATIC", L"Still attempting connection...",
        WS_CHILD | SS_CENTER | SS_NOPREFIX,

        cx - 130, 114, 260, 18,
        hLoadingWnd, NULL, hInst, NULL);
    SendMessage(hLoadingLate, WM_SETFONT, (WPARAM)hfNormal, TRUE);

    hLoadingCancel = CreateWindowW(L"BUTTON", L"Cancel",
        WS_CHILD | BS_PUSHBUTTON,

        cx - 50, 140, 100, 28,
        hLoadingWnd, (HMENU)(INT_PTR)ID_OVERLAY_CANCEL, hInst, NULL);
    SendMessage(hLoadingCancel, WM_SETFONT, (WPARAM)hfNormal, TRUE);

    spinAngle = 0;
    g_connect_cancelled = false;

    SetTimer(hConnectWnd, ID_OVERLAY_TIMER, 60, NULL);

    SetTimer(hConnectWnd, ID_OVERLAY_LATE_TIMER, 5000, NULL);

    BringWindowToTop(hLoadingWnd);
    UpdateWindow(hConnectWnd);
}

void ControllerApp::hide_loading_overlay()
{
    KillTimer(hConnectWnd, ID_OVERLAY_TIMER);
    KillTimer(hConnectWnd, ID_OVERLAY_LATE_TIMER);

    if (hLoadingWnd) {
        DestroyWindow(hLoadingWnd);
        hLoadingWnd = NULL;
        hLoadingLabel = NULL;
        hLoadingLate = NULL;
        hLoadingCancel = NULL;
    }

    EnumChildWindows(hConnectWnd, [](HWND child, LPARAM) -> BOOL {
        EnableWindow(child, TRUE);
        return TRUE;
        }, 0);
}

void ControllerApp::tick_spinner()
{
    spinAngle = (spinAngle + 15) % 360;
    if (hLoadingWnd) {

        RECT spinRect = { 0, 20, 999, 85 };
        InvalidateRect(hLoadingWnd, &spinRect, TRUE);
    }
}

void ControllerApp::show_late_label()
{
    if (!hLoadingWnd) return;
    if (hLoadingLate) { ShowWindow(hLoadingLate, SW_SHOW); UpdateWindow(hLoadingLate); }
    if (hLoadingCancel) { ShowWindow(hLoadingCancel, SW_SHOW); UpdateWindow(hLoadingCancel); }
}

void ControllerApp::cancel_connect()
{
    g_connect_cancelled = true;
    hide_loading_overlay();

    EnableWindow(hBtnConnect, TRUE);
    ShowWindow(hConnectWnd, SW_SHOW);
    SetForegroundWindow(hConnectWnd);
}

void ControllerApp::create_session_window()
{
    HINSTANCE hInst = hInstance;
    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

    int scrW = GetSystemMetrics(SM_CXSCREEN);
    int scrH = GetSystemMetrics(SM_CYSCREEN);

    hSessionWnd = CreateWindowExW(0, L"RDSessionCls",
        L"Remote Desktop - Session",
        WS_OVERLAPPEDWINDOW,
        100, 100, scrW / 2, scrH / 2,
        NULL, NULL, hInst, NULL);

    auto btn = [&](const wchar_t* t, int id, int x, int y, int w, int h) {
        HWND hw = CreateWindowW(L"BUTTON", t,
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            x, y, w, h, hSessionWnd, (HMENU)(INT_PTR)id, hInst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)hFont, TRUE);
        return hw;
        };
    auto lbl = [&](const wchar_t* t, int x, int y, int w, int h) {
        HWND hw = CreateWindowW(L"STATIC", t,
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            x, y, w, h, hSessionWnd, NULL, hInst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)hFont, TRUE);
        return hw;
        };

    hBtnDisconn = btn(L"Disconnect", ID_BTN_DISCONNECT, 5, 5, 95, 26);
    hBtnVolume = btn(L"Volume", ID_BTN_VOLUME, 106, 5, 72, 26);
    hBtnDebug = btn(L"Debug (F12)", ID_BTN_DEBUG, 184, 5, 90, 26);
    hLockLabel = lbl(L"Click inside stream to lock cursor  |  ESC to unlock",
        280, 9, 500, 18);

    hCanvas = CreateWindowExW(0, L"RDCanvasCls", NULL,
        WS_CHILD | WS_VISIBLE,
        0, 36, scrW / 2, scrH / 2 - 36 - 22, hSessionWnd, NULL, hInst, NULL);

    const wchar_t* connStatus = g_aes_enabled ? L"Connected  [AES-128-CTR encrypted]" : L"Connected  [Unencrypted]";
    hStatusBar = CreateWindowW(L"STATIC", connStatus,
        WS_CHILD | WS_VISIBLE | SS_LEFT | SS_SUNKEN,
        0, scrH / 2 - 22, scrW / 2, 22, hSessionWnd, NULL, hInst, NULL);
    SendMessage(hStatusBar, WM_SETFONT, (WPARAM)hFont, TRUE);

    if (hChkDebug && SendMessage(hChkDebug, BM_GETCHECK, 0, 0) == BST_CHECKED)
        toggle_debug();

    ShowWindow(hSessionWnd, SW_SHOW);
    UpdateWindow(hSessionWnd);

    RECT rc; GetClientRect(hSessionWnd, &rc);
    SendMessage(hSessionWnd, WM_SIZE, 0, MAKELPARAM(rc.right, rc.bottom));
}

void ControllerApp::run()
{
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

void ControllerApp::destroy()
{
    stop_listeners();
    if (video_conn) { video_conn->disconnect(); video_conn.reset(); }
    if (input_conn) { input_conn->disconnect(); input_conn.reset(); }
    if (hFrameBmp) { DeleteObject(hFrameBmp);  hFrameBmp = NULL; }
    if (hCursorBmp) { DeleteObject(hCursorBmp); hCursorBmp = NULL; }
}

void ControllerApp::set_status(const std::string& s)
{
    if (!hStatusBar) return;
    std::wstring ws(s.begin(), s.end());
    SetWindowTextW(hStatusBar, ws.c_str());
}

void ControllerApp::on_connect()
{
    if (!show_consent_dialog()) return;

    wchar_t ip_buf[128] = {}, name_buf[64] = {}, vport_buf[8] = {}, iport_buf[8] = {}, aport_buf[8] = {}, pass_buf[128] = {};
    GetWindowTextW(hEditIP, ip_buf, 128);
    GetWindowTextW(hEditName, name_buf, 64);

    HWND hVportEdit = GetDlgItem(hConnectWnd, ID_EDIT_VPORT);
    HWND hIportEdit = GetDlgItem(hConnectWnd, ID_EDIT_IPORT);
    HWND hAportEdit = GetDlgItem(hConnectWnd, ID_EDIT_APORT);
    HWND hPassEdit = GetDlgItem(hConnectWnd, ID_EDIT_PASS);
    if (hVportEdit) GetWindowTextW(hVportEdit, vport_buf, 8);
    if (hIportEdit) GetWindowTextW(hIportEdit, iport_buf, 8);
    if (hAportEdit) GetWindowTextW(hAportEdit, aport_buf, 8);
    if (hPassEdit)  GetWindowTextW(hPassEdit, pass_buf, 128);

    int vport = _wtoi(vport_buf);
    int iport = _wtoi(iport_buf);
    int aport = _wtoi(aport_buf);
    if (vport < 1024 || vport > 65535) vport = 55000;
    if (iport < 1024 || iport > 65535) iport = 55001;
    if (aport < 1024 || aport > 65535) aport = 55002;

    VIDEO_PORT = vport;
    INPUT_PORT = iport;
    AUDIO_PORT = aport;

    std::wstring wpass(pass_buf);
    std::string passphrase(wpass.begin(), wpass.end());
    if (!passphrase.empty()) {
        uint8_t key[16];
        AES128::DeriveKey(passphrase, key);
        AES128::KeyExpansion(key, g_aes_ctx.rk);
        g_aes_enabled = true;
    }
    else {
        g_aes_enabled = false;
    }

    g_aes_inp_send_ctr = 0;
    g_aes_vid_recv_ctr = 0;
    g_recv_bw.reset();

    std::wstring wip(ip_buf), wname(name_buf);
    std::string  host(wip.begin(), wip.end());
    std::string  name = wname.empty() ? "Controller"
        : std::string(wname.begin(), wname.end());
    if (host.empty()) {
        MessageBoxW(hConnectWnd, L"Please enter the host IP address or hostname.", L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    HWND hChkInet = GetDlgItem(hConnectWnd, ID_CHK_INTERNET);
    bool over_internet = hChkInet &&
        (SendMessage(hChkInet, BM_GETCHECK, 0, 0) == BST_CHECKED);

    if (over_internet) {
        bool looks_lan = false;

        if (host.size() > 8) {
            if (host.substr(0, 8) == "192.168." ||
                host.substr(0, 3) == "10." ||
                host == "localhost" ||
                host.substr(0, 10) == "172.16." ||
                host.substr(0, 10) == "172.17." ||
                host.substr(0, 10) == "172.18." ||
                host.substr(0, 10) == "172.19." ||
                host.substr(0, 10) == "172.20." ||
                host.substr(0, 10) == "172.31.")
                looks_lan = true;
        }
        else if (host.substr(0, 3) == "10.") {
            looks_lan = true;
        }
        if (looks_lan) {
            int r = MessageBoxW(hConnectWnd,
                L"'Over the Internet' is checked, but the host looks like a LAN IP.\n\n"
                L"For internet connections, enter the host's public IP or hostname\n"
                L"(e.g. mypc.ddns.net). Continue anyway?",
                L"Check Host Address",
                MB_YESNO | MB_ICONWARNING);
            if (r != IDYES) return;
        }
    }

    EnableWindow(hBtnConnect, FALSE);
    show_loading_overlay();

    HWND postTarget = hConnectWnd;

    std::thread([this, host, name, postTarget, vport, iport, aport, over_internet]() {

        auto ic = std::make_unique<InputConnection>(host);
        ic->input_port = iport;

        auto nb_connect = [&](int port) -> SOCKET
            {

                sockaddr_in addr{};
                addr.sin_family = AF_INET;
                addr.sin_port = htons((u_short)port);
                struct addrinfo hints {}, * res = nullptr;
                hints.ai_family = AF_INET;
                hints.ai_socktype = SOCK_STREAM;
                char portstr[8]; sprintf_s(portstr, "%d", port);
                if (getaddrinfo(host.c_str(), portstr, &hints, &res) == 0 && res) {
                    addr = *reinterpret_cast<sockaddr_in*>(res->ai_addr);
                    addr.sin_port = htons((u_short)port);
                    freeaddrinfo(res);
                }
                else {
                    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1)
                        return INVALID_SOCKET;
                }

                SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (s == INVALID_SOCKET) return INVALID_SOCKET;

                u_long nb = 1;
                ioctlsocket(s, FIONBIO, &nb);

                ::connect(s, (sockaddr*)&addr, sizeof(addr));

                int max_slices = over_internet ? 200 : 60;
                for (int slice = 0; slice < max_slices && !g_connect_cancelled; ++slice) {
                    timeval tv{}; tv.tv_usec = 50000;

                    fd_set wset, eset;
                    FD_ZERO(&wset); FD_SET(s, &wset);
                    FD_ZERO(&eset); FD_SET(s, &eset);
                    int r = select(0, NULL, &wset, &eset, &tv);
                    if (r > 0 && FD_ISSET(s, &wset)) {

                        int err = 0; int elen = sizeof(err);
                        getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &elen);
                        if (err != 0) break;

                        u_long bl = 0; ioctlsocket(s, FIONBIO, &bl);
                        BOOL nd = 1;
                        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char*)&nd, sizeof(nd));
                        return s;

                    }
                    if (r < 0 || FD_ISSET(s, &eset)) break;

                }

                closesocket(s);
                return INVALID_SOCKET;
            };

        bool inputOk = false;
        {
            int deadline_sec = over_internet ? 300 : 60;
            auto deadline = std::chrono::steady_clock::now() +
                std::chrono::seconds(deadline_sec);
            while (!g_connect_cancelled &&
                std::chrono::steady_clock::now() < deadline)
            {
                SOCKET s = nb_connect(iport);
                if (g_connect_cancelled) {
                    if (s != INVALID_SOCKET) closesocket(s);
                    break;
                }
                if (s != INVALID_SOCKET) {
                    ic->sock = s;
                    ic->running = true;
                    inputOk = true;
                    break;
                }

                for (int i = 0; i < 10 && !g_connect_cancelled; ++i)
                    Sleep(50);
            }
        }

        if (g_connect_cancelled) return;

        if (!inputOk) {
            PostMessage(postTarget, WM_APP_CONN_CANCEL, 0, 0);
            PostMessage(postTarget, WM_APP_STATUS, 0,
                (LPARAM)new std::string("Failed: could not connect input channel"));
            return;
        }

        if (g_connect_cancelled) { ic->disconnect(); return; }

        auto vc = std::make_unique<VideoConnection>(host, name);
        vc->video_port = vport;

        vc->frame_callback = [this](PendingFrame pf) {
            on_frame(std::move(pf));
            };
        vc->pending_check_callback = [this]() -> bool {
            return frame_scheduled.load();
            };
        vc->status_callback = [this, postTarget](std::string msg) {
            HWND target = hSessionWnd ? hSessionWnd : postTarget;
            PostMessage(target, WM_APP_STATUS, 0,
                (LPARAM)new std::string(msg));
            };

        auto [ok, msg] = vc->connect_video();

        if (g_connect_cancelled) { ic->disconnect(); return; }

        if (!ok) {
            ic->disconnect();
            PostMessage(postTarget, WM_APP_CONN_CANCEL, 0, 0);
            PostMessage(postTarget, WM_APP_STATUS, 0,
                (LPARAM)new std::string("Failed: " + msg));
            return;
        }

        video_conn = std::move(vc);
        input_conn = std::move(ic);

        SOCKET audio_sock = nb_connect(aport);
        PostMessage(postTarget, WM_APP_CONNECTED,
            (WPARAM)(audio_sock != INVALID_SOCKET ? audio_sock : (SOCKET)INVALID_SOCKET), 0);
        }).detach();
}

void ControllerApp::on_disconnected()
{
    unlock_cursor();
    destroy_session_window();

    ShowWindow(hConnectWnd, SW_SHOW);
    SetForegroundWindow(hConnectWnd);
    hwnd = hConnectWnd;

    hide_loading_overlay();

    set_status("Disconnected — ready to reconnect");
    EnableWindow(hBtnConnect, TRUE);
}

void ControllerApp::destroy_session_window()
{
    if (!hSessionWnd) return;

    if (debugVisible) toggle_debug();

    if (video_conn) { video_conn->disconnect(); video_conn.reset(); }
    if (input_conn) { input_conn->disconnect(); input_conn.reset(); }
    if (g_audio_stop_evt) SetEvent(g_audio_stop_evt);
    if (audio_thread.joinable()) audio_thread.join();
    if (g_audio_stop_evt) { CloseHandle(g_audio_stop_evt); g_audio_stop_evt = NULL; }
    {
        std::lock_guard<std::mutex> lk(frame_mutex);
        pending_frame.reset();
        frame_scheduled = false;
    }
    if (hFrameBmp) { DeleteObject(hFrameBmp); hFrameBmp = NULL; }
    firstFrame = true;

    DestroyWindow(hSessionWnd);
    hSessionWnd = NULL;
    hCanvas = NULL;
    hBtnDisconn = NULL;
    hBtnVolume = NULL;
    hBtnDebug = NULL;
    hLockLabel = NULL;

    hStatusBar = hConnectStatus;
}

void ControllerApp::on_disconnect_btn()
{

    on_disconnected();
}

void ControllerApp::on_close()
{
    unlock_cursor();
    if (video_conn) { video_conn->disconnect(); video_conn.reset(); }
    if (input_conn) { input_conn->disconnect(); input_conn.reset(); }
    stop_listeners();
    DestroyWindow(hConnectWnd);
    if (hSessionWnd) DestroyWindow(hSessionWnd);
}

void ControllerApp::on_frame(PendingFrame pf)
{

    {
        std::lock_guard<std::mutex> lk(frame_mutex);
        pending_frame = std::make_unique<PendingFrame>(std::move(pf));
    }
    if (!frame_scheduled.exchange(true)) {
        HWND target = hSessionWnd ? hSessionWnd : hConnectWnd;
        PostMessage(target, WM_APP_FRAME, 0, 0);
    }
}

void ControllerApp::render_frame()
{
    frame_scheduled = false;

    std::unique_ptr<PendingFrame> pf;
    {
        std::lock_guard<std::mutex> lk(frame_mutex);
        pf = std::move(pending_frame);
    }
    if (!pf) return;

    int jw = 0, jh = 0;
    HBITMAP hNew = decode_jpeg(pf->jpeg.data(), pf->jpeg.size(), jw, jh);
    if (!hNew) return;

    if (hFrameBmp) DeleteObject(hFrameBmp);
    hFrameBmp = hNew;
    frameSrcW = jw;
    frameSrcH = jh;
    if (!cursor_locked) {
        cursorRatX = pf->cx_n / 65535.0;
        cursorRatY = pf->cy_n / 65535.0;
    }

    if (firstFrame || (jw > 0 && frameSrcW == jw)) {
        if (jw > 0) fit_window_to_frame(jw, jh);
        firstFrame = false;
    }

    dbg_frames++;
    InvalidateRect(hCanvas, NULL, FALSE);

    {
        std::lock_guard<std::mutex> lk(frame_mutex);
        if (pending_frame && !frame_scheduled.exchange(true)) {
            HWND target = hSessionWnd ? hSessionWnd : hConnectWnd;
            PostMessage(target, WM_APP_FRAME, 0, 0);
        }
    }
}

void ControllerApp::fit_window_to_frame(int rw, int rh)
{
    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);
    int maxW = (int)(sw * 0.90);
    int maxH = (int)(sh * 0.90);

    RECT bar_rc; GetWindowRect(hBtnConnect, &bar_rc);
    int barH = (bar_rc.bottom - bar_rc.top) + 20;
    int sbH = 22;
    int chrome = barH + sbH;

    double scale = std::min({ (double)maxW / rw, (double)(maxH - chrome) / rh, 1.0 });
    int winW = (int)(rw * scale);
    int winH = (int)(rh * scale) + chrome;

    int x = (sw - winW) / 2;
    int y = (sh - winH) / 2;
    HWND fw = hSessionWnd ? hSessionWnd : hwnd;
    SetWindowPos(fw, NULL, x, y, winW, winH, SWP_NOZORDER);
    UpdateWindow(fw);
}

void ControllerApp::on_paint_canvas(HDC hdc)
{
    RECT rc; GetClientRect(hCanvas, &rc);
    int cw = rc.right - rc.left;
    int ch = rc.bottom - rc.top;

    if (!hFrameBmp || cw < 10 || ch < 10) {
        FillRect(hdc, &rc, (HBRUSH)GetStockObject(BLACK_BRUSH));
        return;
    }

    blit_bitmap(hdc, hFrameBmp, frameSrcW, frameSrcH, 0, 0, cw, ch);

    if (hCursorBmp) {
        double drawX = cursor_locked ? vCursorX : cursorRatX;
        double drawY = cursor_locked ? vCursorY : cursorRatY;

        int cx = (int)(drawX * cw);
        int cy = (int)(drawY * ch);

        BLENDFUNCTION bf{};
        bf.BlendOp = AC_SRC_OVER;
        bf.SourceConstantAlpha = 255;
        bf.AlphaFormat = AC_SRC_ALPHA;

        HDC mdc = CreateCompatibleDC(hdc);
        HGDIOBJ old = SelectObject(mdc, hCursorBmp);
        AlphaBlend(hdc, cx, cy, CURSOR_SIZE, CURSOR_SIZE,
            mdc, 0, 0, CURSOR_SIZE, CURSOR_SIZE, bf);
        SelectObject(mdc, old);
        DeleteDC(mdc);
    }
}

void ControllerApp::lock_cursor()
{
    cursor_locked = true;
    SetWindowTextW(hLockLabel, L"CURSOR LOCKED  |  ESC to unlock");

    RECT cr;
    GetWindowRect(hCanvas, &cr);
    pin_cx = (cr.left + cr.right) / 2;
    pin_cy = (cr.top + cr.bottom) / 2;
    warp_pending.fetch_add(1);
    SetCursorPos(pin_cx, pin_cy);

    double refW = frameSrcW > 0 ? (double)frameSrcW : 1920.0;
    double refH = frameSrcH > 0 ? (double)frameSrcH : 1080.0;
    double abs_x = cursorRatX * refW;
    double abs_y = cursorRatY * refH;
    abs_x = std::max(0.0, std::min(refW - 1.0, abs_x));
    abs_y = std::max(0.0, std::min(refH - 1.0, abs_y));
    vCursorX = abs_x / refW;
    vCursorY = abs_y / refH;

    if (input_conn && input_conn->running) {
        int16_t wx = static_cast<int16_t>(std::max(0.0, std::min(refW - 1.0, abs_x)));
        int16_t wy = static_cast<int16_t>(std::max(0.0, std::min(refH - 1.0, abs_y)));
        input_conn->send_mouse(wx, wy, "warp");
    }

    ShowCursor(FALSE);

    start_listeners();
}

static std::atomic<bool> g_hook_ctrl{ false };
static std::atomic<bool> g_hook_shift{ false };
static std::atomic<bool> g_hook_alt{ false };

void ControllerApp::unlock_cursor()
{
    if (!cursor_locked) return;
    cursorRatX = vCursorX;
    cursorRatY = vCursorY;
    cursor_locked = false;
    SetWindowTextW(hLockLabel,
        L"Click inside stream to lock cursor  |  ESC to unlock");
    ShowCursor(TRUE);
    stop_listeners();
    g_hook_ctrl = false;
    g_hook_shift = false;
    g_hook_alt = false;
}

static bool ui_has_focus()
{
    if (!g_app) return false;

    if (g_app->hSessionWnd && IsWindowVisible(g_app->hSessionWnd)) return false;
    HWND f = GetFocus();
    return f == g_app->hEditIP || f == g_app->hEditName;
}

static LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wp, LPARAM lp)
{
    if (nCode == HC_ACTION && g_app && g_app->cursor_locked && g_app->input_conn) {
        KBDLLHOOKSTRUCT* ks = reinterpret_cast<KBDLLHOOKSTRUCT*>(lp);
        bool pressed = (wp == WM_KEYDOWN || wp == WM_SYSKEYDOWN);
        bool released = (wp == WM_KEYUP || wp == WM_SYSKEYUP);
        DWORD vk = ks->vkCode;

        if (vk == VK_CONTROL || vk == VK_LCONTROL || vk == VK_RCONTROL)
            g_hook_ctrl = pressed;
        if (vk == VK_SHIFT || vk == VK_LSHIFT || vk == VK_RSHIFT)
            g_hook_shift = pressed;
        if (vk == VK_MENU || vk == VK_LMENU || vk == VK_RMENU)
            g_hook_alt = pressed;

        if (pressed || released) {

            if (vk == VK_ESCAPE && g_hook_ctrl && g_hook_shift) {
                if (!ui_has_focus()) {
                    g_app->input_conn->send_key(VK_CONTROL, pressed);
                    g_app->input_conn->send_key(VK_SHIFT, pressed);
                    g_app->input_conn->send_key(VK_ESCAPE, pressed);
                }
                return 1;
            }

            if (vk == VK_DELETE && g_hook_ctrl && g_hook_alt) {
                if (!ui_has_focus()) {
                    g_app->input_conn->send_key(VK_CONTROL, pressed);
                    g_app->input_conn->send_key(VK_MENU, pressed);
                    g_app->input_conn->send_key(VK_DELETE, pressed);
                }
                return 1;
            }

            if (vk == VK_TAB && g_hook_alt) {
                if (!ui_has_focus()) {
                    g_app->input_conn->send_key(VK_MENU, pressed);
                    g_app->input_conn->send_key(VK_TAB, pressed);
                }
                return 1;
            }

            if (vk == VK_ESCAPE && pressed) {
                HWND hw = g_app->hSessionWnd ? g_app->hSessionWnd : g_app->hwnd;
                PostMessageW(hw, WM_KEYDOWN, VK_ESCAPE, 0);
                return 1;
            }

            if (vk == VK_F12 && pressed) {
                HWND hw2 = g_app->hSessionWnd ? g_app->hSessionWnd : g_app->hwnd;
                PostMessageW(hw2, WM_COMMAND,
                    MAKEWPARAM(ID_BTN_DEBUG, BN_CLICKED), 0);
                return 1;
            }

            if (vk == VK_LWIN || vk == VK_RWIN) {
                if (!ui_has_focus())
                    g_app->input_conn->send_key(vk, pressed);
                return 1;
            }

            if (!ui_has_focus()) {
                g_app->input_conn->send_key(vk, pressed);
            }
        }
    }
    return CallNextHookEx(NULL, nCode, wp, lp);
}

static LRESULT CALLBACK RawInputWndProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == WM_INPUT && g_app) {
        g_app->handle_raw_input(lp);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wp, lp);
}

void ControllerApp::start_listeners()
{
    if (raw_running) return;
    raw_running = true;
    warp_pending = 0;

    kb_hook = SetWindowsHookExW(WH_KEYBOARD_LL, LowLevelKeyboardProc, NULL, 0);

    raw_thread = std::thread(&ControllerApp::raw_input_loop, this);
}

void ControllerApp::stop_listeners()
{
    if (kb_hook) {
        UnhookWindowsHookEx(kb_hook);
        kb_hook = NULL;
    }

    raw_running = false;
    warp_pending = 0;

    HWND rh = raw_hwnd;
    if (rh) PostMessageW(rh, WM_QUIT, 0, 0);
    if (raw_thread.joinable()) raw_thread.join();
    raw_hwnd = NULL;
}

void ControllerApp::raw_input_loop()
{
    wchar_t CLS[64];
    swprintf_s(CLS, L"RawInputSink_RC_%u", GetCurrentThreadId());

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = RawInputWndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLS;
    RegisterClassExW(&wc);

    HWND hw = CreateWindowExW(0, CLS, NULL, 0,
        0, 0, 0, 0, HWND_MESSAGE, NULL, hInstance, NULL);
    if (!hw) {
        UnregisterClassW(CLS, hInstance);
        return;
    }
    raw_hwnd = hw;

    RAWINPUTDEVICE rid{};
    rid.usUsagePage = 0x01;
    rid.usUsage = 0x02;
    rid.dwFlags = RIDEV_INPUTSINK;
    rid.hwndTarget = hw;
    RegisterRawInputDevices(&rid, 1, sizeof(rid));

    MSG m{};
    while (GetMessageW(&m, NULL, 0, 0) > 0) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }

    rid.dwFlags = RIDEV_REMOVE;
    rid.hwndTarget = NULL;
    RegisterRawInputDevices(&rid, 1, sizeof(rid));
    DestroyWindow(hw);
    raw_hwnd = NULL;
    UnregisterClassW(CLS, hInstance);
}
void ControllerApp::handle_raw_input(LPARAM lp)
{
    if (!cursor_locked || !input_conn) return;

    UINT sz = 0;
    GetRawInputData(reinterpret_cast<HRAWINPUT>(lp),
        RID_INPUT, NULL, &sz, sizeof(RAWINPUTHEADER));
    if (sz == 0) return;

    std::vector<uint8_t> buf(sz);
    if (GetRawInputData(reinterpret_cast<HRAWINPUT>(lp),
        RID_INPUT, buf.data(), &sz, sizeof(RAWINPUTHEADER)) != sz) return;

    RAWINPUT* ri = reinterpret_cast<RAWINPUT*>(buf.data());
    if (ri->header.dwType != RIM_TYPEMOUSE) return;

    RAWMOUSE& rm = ri->data.mouse;

    int dx = rm.lLastX;
    int dy = rm.lLastY;
    if (dx != 0 || dy != 0) {
        if (warp_pending.load() > 0) {
            warp_pending.fetch_sub(1);
        }
        else {
            dbg_raw_events++;
            dbg_last_dx = dx;
            dbg_last_dy = dy;

            int16_t ix = static_cast<int16_t>(
                std::max(-32767, std::min(32767, static_cast<int>(dx * MOUSE_SPEED))));
            int16_t iy = static_cast<int16_t>(
                std::max(-32767, std::min(32767, static_cast<int>(dy * MOUSE_SPEED))));
            if (ix != 0 || iy != 0) {
                input_conn->send_mouse(ix, iy, "rel ");
                dbg_pkts_sent++;

                double refW = frameSrcW > 0 ? (double)frameSrcW : 1920.0;
                double refH = frameSrcH > 0 ? (double)frameSrcH : 1080.0;

                double abs_x = vCursorX * refW;
                double abs_y = vCursorY * refH;
                abs_x += ix;
                abs_y += iy;
                abs_x = std::max(0.0, std::min(refW - 1.0, abs_x));
                abs_y = std::max(0.0, std::min(refH - 1.0, abs_y));
                vCursorX = abs_x / refW;
                vCursorY = abs_y / refH;
            }

            if (hCanvas) {
                RECT cr;
                GetWindowRect(hCanvas, &cr);
                pin_cx = (cr.left + cr.right) / 2;
                pin_cy = (cr.top + cr.bottom) / 2;
            }
            warp_pending.fetch_add(1);
            SetCursorPos(pin_cx, pin_cy);
        }
    }

    USHORT bf = rm.usButtonFlags;
    if (bf & RI_MOUSE_LEFT_BUTTON_DOWN)   input_conn->send_mouse(0, 0, "down", "left");
    if (bf & RI_MOUSE_LEFT_BUTTON_UP)     input_conn->send_mouse(0, 0, "up  ", "left");
    if (bf & RI_MOUSE_RIGHT_BUTTON_DOWN)  input_conn->send_mouse(0, 0, "down", "righ");
    if (bf & RI_MOUSE_RIGHT_BUTTON_UP)    input_conn->send_mouse(0, 0, "up  ", "righ");
    if (bf & RI_MOUSE_MIDDLE_BUTTON_DOWN) input_conn->send_mouse(0, 0, "down", "midd");
    if (bf & RI_MOUSE_MIDDLE_BUTTON_UP)   input_conn->send_mouse(0, 0, "up  ", "midd");

    if (bf & RI_MOUSE_WHEEL) {
        SHORT raw = static_cast<SHORT>(rm.usButtonData);
        int   ticks = raw / WHEEL_DELTA;
        char  sbuf[8];
        snprintf(sbuf, sizeof(sbuf), "%+d", ticks);
        input_conn->send_mouse(0, 0, "scro", sbuf);
    }
}

void ControllerApp::fwd_key(WPARAM vk, bool pressed)
{
    if (!cursor_locked || !input_conn) return;
    if (vk == VK_ESCAPE || vk == VK_F12) return;
    if (ui_has_focus()) return;
    input_conn->send_key(static_cast<uint32_t>(vk), pressed);
}

static HWND hDebugLabels[16] = {};
static HWND hDebugVals[16] = {};
static constexpr int DBG_ROWS = 15;

static const wchar_t* DBG_NAMES[] = {
    L"Cursor locked", L"Warp count", L"Raw events total", L"Mouse pkts sent",
    L"Last dx/dy",    L"Stream FPS",   L"Frames rendered",  L"Pin centre (px)",
    L"Lock rect",     L"Video conn",   L"Input conn",       L"Raw HWND",
    L"Raw thread alive",
    L"Recv FPS (EMA)", L"Throughput"
};

static LRESULT CALLBACK DebugWndProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE: {
        HFONT hf = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, FIXED_PITCH | FF_DONTCARE, L"Consolas");
        int y = 30;
        for (int i = 0; i < DBG_ROWS; i++, y += 18) {
            hDebugLabels[i] = CreateWindowW(L"STATIC", DBG_NAMES[i],
                WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
                5, y, 160, 16, hWnd, NULL, NULL, NULL);
            SendMessage(hDebugLabels[i], WM_SETFONT, (WPARAM)hf, TRUE);
            hDebugVals[i] = CreateWindowW(L"STATIC", L"-",
                WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
                170, y, 220, 16, hWnd, NULL, NULL, NULL);
            SendMessage(hDebugVals[i], WM_SETFONT, (WPARAM)hf, TRUE);
        }
        HWND hReset = CreateWindowW(L"BUTTON", L"Reset counters",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 5, y, 120, 22, hWnd, (HMENU)1, NULL, NULL);
        SendMessage(hReset, WM_SETFONT, (WPARAM)hf, TRUE);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == 1 && g_app) {
            g_app->dbg_raw_events = 0; g_app->dbg_pkts_sent = 0;
            g_app->dbg_frames = 0;    g_app->dbg_fps = 0.0;
        }
        return 0;
    case WM_CLOSE:
        if (g_app) g_app->toggle_debug();
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wp, lp);
}

void ControllerApp::toggle_debug()
{

    if (!hSessionWnd) return;

    if (debugVisible) {
        debugVisible = false;
        if (hDebugWin) { DestroyWindow(hDebugWin); hDebugWin = NULL; }
    }
    else {
        debugVisible = true;
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = DebugWndProc;
        wc.hInstance = hInstance;
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = L"RDDebugCls";
        RegisterClassExW(&wc);

        hDebugWin = CreateWindowExW(WS_EX_TOPMOST, L"RDDebugCls", L"Debug",
            WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
            50, 50, 430, 30 + DBG_ROWS * 18 + 40, NULL, NULL, hInstance, NULL);

        HWND hTitle = CreateWindowW(L"STATIC", L"CONTROLLER DEBUG",
            WS_CHILD | WS_VISIBLE | SS_CENTER | SS_NOPREFIX,
            0, 0, 410, 24, hDebugWin, NULL, NULL, NULL);
        HFONT hf = CreateFontW(14, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, FIXED_PITCH | FF_DONTCARE, L"Consolas");
        SendMessage(hTitle, WM_SETFONT, (WPARAM)hf, TRUE);
        update_debug();
    }
}

void ControllerApp::update_debug()
{
    if (!debugVisible || !hDebugWin) return;

    double now = (double)GetTickCount64() / 1000.0;
    double elapsed = now - dbg_fps_time;
    if (elapsed >= 1.0) {
        dbg_fps = dbg_frame_tick / elapsed;
        dbg_frame_tick = 0;
        dbg_fps_time = now;
    }

    auto sv = [](int i, const std::wstring& s) {
        if (hDebugVals[i]) SetWindowTextW(hDebugVals[i], s.c_str());
        };
    auto b2w = [](bool b) -> std::wstring { return b ? L"True" : L"False"; };
    auto i2w = [](long v) -> std::wstring { return std::to_wstring(v); };

    sv(0, b2w(cursor_locked));
    sv(1, std::to_wstring(warp_pending.load()));
    sv(2, i2w(dbg_raw_events));
    sv(3, i2w(dbg_pkts_sent));
    {
        std::wostringstream ss;
        ss << L"dx=" << dbg_last_dx.load() << L"  dy=" << dbg_last_dy.load();
        sv(4, ss.str());
    }
    {
        std::wostringstream ss; ss << std::fixed << std::setprecision(1) << dbg_fps;
        sv(5, ss.str());
    }
    sv(6, i2w(dbg_frames));
    {
        std::wostringstream ss; ss << L"(" << pin_cx << L", " << pin_cy << L")";
        sv(7, ss.str());
    }
    sv(8, L"(tracked)");
    sv(9, (video_conn && video_conn->running) ? L"connected" : L"none");
    sv(10, (input_conn && input_conn->running) ? L"connected" : L"none");
    sv(11, raw_hwnd ? L"active" : L"None");
    sv(12, b2w(raw_running.load()));

    {
        std::wostringstream ss;
        ss << std::fixed << std::setprecision(1) << g_recv_bw.measured_fps()
            << L" fps" << (g_recv_bw.is_congested() ? L"  [CONGESTED]" : L"");
        sv(13, ss.str());
    }
    {
        std::wostringstream ss;
        long long kbps = g_recv_bw.throughput_bps() / 1000;
        ss << kbps << L" kbps";
        sv(14, ss.str());
    }

    if (debugVisible)
        SetTimer(hDebugWin, 1, 200, [](HWND, UINT, UINT_PTR, DWORD) {
        if (g_app) g_app->update_debug();
            });
}

void ControllerApp::show_volume_menu()
{
    if (!hBtnVolume) return;
    RECT rc; GetWindowRect(hBtnVolume, &rc);
    HMENU hm = CreatePopupMenu();
    static const struct { int pct; const wchar_t* label; } kLevels[] = {
        {100, L"100% – Full"}, {75, L"75%"}, {50, L"50%"},
        {25,  L"25%"}, {10, L"10%"}, {0, L"Mute"}
    };
    for (int i = 0; i < 6; i++) {
        UINT fl = MF_STRING | (volumePct == kLevels[i].pct ? MF_CHECKED : 0);
        AppendMenuW(hm, fl, 501 + i, kLevels[i].label);
    }
    SetForegroundWindow(hwnd);
    TrackPopupMenu(hm, TPM_LEFTALIGN | TPM_TOPALIGN, rc.left, rc.bottom, 0, hwnd, NULL);
    DestroyMenu(hm);
}

void ControllerApp::set_volume_level(int cmd_id)
{
    static const int kPct[] = { 100, 75, 50, 25, 10, 0 };
    int idx = cmd_id - 501;
    if (idx < 0 || idx > 5) return;
    volumePct = kPct[idx];
    g_audio_volume = volumePct / 100.0f;
    wchar_t lbl[20];
    if (volumePct == 0)   swprintf_s(lbl, L"Vol: Mute");
    else if (volumePct == 100) swprintf_s(lbl, L"Volume");
    else                       swprintf_s(lbl, L"Vol: %d%%", volumePct);
    if (hBtnVolume) SetWindowTextW(hBtnVolume, lbl);
}

void ControllerApp::export_settings()
{

    wchar_t vport_buf[8] = {}, iport_buf[8] = {}, aport_buf[8] = {}, pass_buf[128] = {};
    HWND hVp = GetDlgItem(hConnectWnd, ID_EDIT_VPORT);
    HWND hIp = GetDlgItem(hConnectWnd, ID_EDIT_IPORT);
    HWND hAp = GetDlgItem(hConnectWnd, ID_EDIT_APORT);
    HWND hPa = GetDlgItem(hConnectWnd, ID_EDIT_PASS);
    if (hVp) GetWindowTextW(hVp, vport_buf, 8);
    if (hIp) GetWindowTextW(hIp, iport_buf, 8);
    if (hAp) GetWindowTextW(hAp, aport_buf, 8);
    if (hPa) GetWindowTextW(hPa, pass_buf, 128);

    int vport = _wtoi(vport_buf);
    int iport = _wtoi(iport_buf);
    int aport = _wtoi(aport_buf);
    if (vport < 1024 || vport > 65535) vport = 55000;
    if (iport < 1024 || iport > 65535) iport = 55001;
    if (aport < 1024 || aport > 65535) aport = 55002;

    std::wstring wpass(pass_buf);
    std::string  passphrase(wpass.begin(), wpass.end());

    if (vport == iport) {
        MessageBoxW(hConnectWnd,
            L"Video port and Input port must be different before exporting.",
            L"Export Error", MB_OK | MB_ICONWARNING);
        return;
    }

    wchar_t filePath[MAX_PATH] = L"settings.dat";

    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hConnectWnd;
    ofn.lpstrFilter = L"Settings file (*.dat)\0*.dat\0All files (*.*)\0*.*\0";
    ofn.lpstrDefExt = L"dat";
    ofn.lpstrFile = filePath;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = L"Save settings.dat for Host Agent";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;

    if (!GetSaveFileNameW(&ofn)) return;

    char narrowPath[MAX_PATH] = {};
    WideCharToMultiByte(CP_ACP, 0, filePath, -1, narrowPath, MAX_PATH, NULL, NULL);

    std::ofstream f(narrowPath, std::ios::trunc);
    if (!f.is_open()) {
        MessageBoxW(hConnectWnd,
            L"Could not write the file. Check that the destination is writable.",
            L"Export Error", MB_OK | MB_ICONERROR);
        return;
    }

    HWND hChkInet = GetDlgItem(hConnectWnd, ID_CHK_INTERNET);
    bool wan_mode = hChkInet &&
        (SendMessage(hChkInet, BM_GETCHECK, 0, 0) == BST_CHECKED);
    const char* conn_str = wan_mode ? "WAN" : "LAN";

    f << "# Remote Desktop Host Agent - Configuration\n";
    f << "# Generated by Remote Desktop Controller\n";
    f << "# Place this file in the same folder as Client.exe\n";
    f << "#\n";
    f << "video_port = " << vport << "\n";
    f << "input_port = " << iport << "\n";
    f << "audio_port = " << aport << "\n";
    f << "connection = " << conn_str << "\n";

    bool inc_startup = hChkStartup &&
        (SendMessage(hChkStartup, BM_GETCHECK, 0, 0) == BST_CHECKED);
    if (inc_startup)
        f << "startup = true\n";
    else
        f << "# startup = true    (uncomment to register agent in Windows startup)\n";
    if (!passphrase.empty())
        f << "passphrase = " << passphrase << "\n";
    else
        f << "# passphrase =    (encryption disabled - uncomment and set a value to enable)\n";

    f.close();

    std::wstring wconn = wan_mode ? L"WAN (UPnP port forwarding enabled)" : L"LAN (no port forwarding)";
    std::wstring confirm =
        L"settings.dat exported successfully.\n\n"
        L"Place it in the same folder as Client.exe on the host machine.\n\n"
        L"Settings written:\n"
        L"  video_port  = " + std::to_wstring(vport) + L"\n"
        L"  input_port  = " + std::to_wstring(iport) + L"\n"
        L"  connection  = " + wconn + L"\n"
        L"  startup     = " + std::wstring(inc_startup ? L"true" : L"false (commented out)") + L"\n" +
        (passphrase.empty()
            ? L"  passphrase  = (none - encryption disabled)"
            : L"  passphrase  = " + std::wstring(passphrase.begin(), passphrase.end()));

    MessageBoxW(hConnectWnd, confirm.c_str(),
        L"Export Successful", MB_OK | MB_ICONINFORMATION);
}

void ControllerApp::update_ip_placeholder()
{
    if (!hIpGhost || !hEditIP) return;

    HWND hChkInet = GetDlgItem(hConnectWnd, ID_CHK_INTERNET);
    bool wan = hChkInet &&
        (SendMessage(hChkInet, BM_GETCHECK, 0, 0) == BST_CHECKED);

    SetWindowTextW(hIpGhost,
        wan ? L"e.g.  mypc.ddns.net  or  203.0.113.5"
        : L"e.g.  192.168.1.10");

    wchar_t buf[4] = {};
    GetWindowTextW(hEditIP, buf, 4);
    bool empty = (buf[0] == L'\0');
    ShowWindow(hIpGhost, empty ? SW_SHOW : SW_HIDE);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int)
{

    Gdiplus::GdiplusStartupInput gdiplusInput;
    ULONG_PTR gdiplusToken;
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusInput, NULL);

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_WIN95_CLASSES };
    InitCommonControlsEx(&icc);

    ControllerApp app;
    if (!app.init(hInst)) {
        MessageBoxW(NULL, L"Failed to create window.", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }
    app.run();

    WSACleanup();
    Gdiplus::GdiplusShutdown(gdiplusToken);
    return 0;
}
