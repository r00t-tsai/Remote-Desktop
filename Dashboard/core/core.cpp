#define CORE_EXPORTS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
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
#include <mmsystem.h>
#include <mmreg.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "msimg32.lib")
#pragma comment(lib, "ole32.lib")

#include "core.h"

BOOL APIENTRY DllMain(HMODULE, DWORD ul_reason_for_call, LPVOID)
{
    (void)ul_reason_for_call;
    return TRUE;
}

static int s_video_port = 55000;
static int s_input_port = 55001;
static int s_audio_port = 55002;

int  Core_GetVideoPort() { return s_video_port; }
int  Core_GetInputPort() { return s_input_port; }
int  Core_GetAudioPort() { return s_audio_port; }
void Core_SetVideoPorts(int video, int input, int audio)
{
    s_video_port = video;
    s_input_port = input;
    s_audio_port = audio;
}

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

    void KeyExpansion(const uint8_t* key, uint8_t* rk) {
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

    static void AddRoundKey(uint8_t s[16], const uint8_t* rk) {
        for (int i = 0; i < 16; i++) s[i] ^= rk[i];
    }
    static void SubBytes(uint8_t s[16]) {
        for (int i = 0; i < 16; i++) s[i] = SBOX[s[i]];
    }
    static void ShiftRows(uint8_t s[16]) {
        uint8_t t;
        t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
        t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
        t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
    }
    static void MixColumns(uint8_t s[16]) {
        for (int c = 0; c < 4; c++) {
            uint8_t* col = s + c * 4; uint8_t a = col[0], b = col[1], cc = col[2], d = col[3];
            col[0] = gmul(a, 2) ^ gmul(b, 3) ^ cc ^ d;
            col[1] = a ^ gmul(b, 2) ^ gmul(cc, 3) ^ d;
            col[2] = a ^ b ^ gmul(cc, 2) ^ gmul(d, 3);
            col[3] = gmul(a, 3) ^ b ^ cc ^ gmul(d, 2);
        }
    }
    static void AES_EncryptBlock(const uint8_t* rk, const uint8_t in[16], uint8_t out[16]) {
        uint8_t s[16]; memcpy(s, in, 16);
        AddRoundKey(s, rk);
        for (int r = 1; r < 10; r++) { SubBytes(s); ShiftRows(s); MixColumns(s); AddRoundKey(s, rk + r * 16); }
        SubBytes(s); ShiftRows(s); AddRoundKey(s, rk + 160);
        memcpy(out, s, 16);
    }

    void CTR_XOR(const AESCtx& ctx, uint64_t counter, uint8_t* buf, size_t len) {
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

    void DeriveKey(const std::string& passphrase, uint8_t key[16]) {
        memset(key, 0x5A, 16);
        for (size_t i = 0; i < passphrase.size(); i++)
            key[i % 16] ^= (uint8_t)passphrase[i] ^ (uint8_t)(i * 0x9B);
        for (int r = 0; r < 4096; r++)
            for (int b = 0; b < 16; b++)
                key[b] = SBOX[key[b] ^ (uint8_t)r ^ key[(b + 7) % 16]];
    }
}

static AES128::AESCtx        s_aes_ctx;
static bool                  s_aes_enabled = false;
static std::atomic<uint64_t> s_aes_inp_send_ctr{ 0 };
static std::atomic<uint64_t> s_aes_vid_recv_ctr{ 0 };

void Core_SetupAES(const std::string& passphrase)
{
    uint8_t key[16];
    AES128::DeriveKey(passphrase, key);
    AES128::KeyExpansion(key, s_aes_ctx.rk);
    s_aes_enabled = true;
}
void Core_DisableAES() { s_aes_enabled = false; }
void Core_ResetAESCounters() { s_aes_inp_send_ctr = 0; s_aes_vid_recv_ctr = 0; }
bool Core_IsAESEnabled() { return s_aes_enabled; }

void CryptVideoRecv(std::vector<uint8_t>& buf) {
    if (!s_aes_enabled || buf.empty()) return;
    uint64_t ctr = s_aes_vid_recv_ctr.fetch_add(1);
    AES128::CTR_XOR(s_aes_ctx, ctr, buf.data(), buf.size());
}
void CryptInputSend(std::vector<uint8_t>& buf) {
    if (!s_aes_enabled || buf.empty()) return;
    uint64_t ctr = s_aes_inp_send_ctr.fetch_add(1);
    AES128::CTR_XOR(s_aes_ctx, ctr, buf.data(), buf.size());
}

static RecvBandwidthMonitor s_recv_bw;

void      Core_BwReset() { s_recv_bw.reset(); }
bool      Core_BwOnFrameReceived(size_t byte_len, bool newer) { return s_recv_bw.on_frame_received(byte_len, newer); }
double    Core_BwMeasuredFps() { return s_recv_bw.measured_fps(); }
long long Core_BwThroughputBps() { return s_recv_bw.throughput_bps(); }
bool      Core_BwIsCongested() { return s_recv_bw.is_congested(); }

bool RecvBandwidthMonitor::on_frame_received(size_t byte_len, bool newer_queued)
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

void RecvBandwidthMonitor::reset() {
    ring_head = ring_count = frame_tick = 0;
    ema_fps = last_fps_sample = bytes_tick = 0.0;
    bytes_this_sec = bytes_last_sec = 0;
    congested = false;
}

static inline uint32_t hton32(uint32_t v) { return htonl(v); }
static inline uint32_t ntoh32(uint32_t v) { return ntohl(v); }
static inline uint16_t hton16(uint16_t v) { return htons(v); }

std::vector<uint8_t> make_packet(uint8_t type, const uint8_t* data, uint32_t len)
{
    std::vector<uint8_t> pkt(5 + len);
    pkt[0] = type;
    uint32_t nlen = hton32(len);
    memcpy(&pkt[1], &nlen, 4);
    if (data && len) memcpy(&pkt[5], data, len);
    return pkt;
}

bool send_packet(SOCKET s, uint8_t type, const uint8_t* data, uint32_t len)
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

bool recv_exact(SOCKET s, uint8_t* buf, int n)
{
    int got = 0;
    while (got < n) {
        int r = ::recv(s, (char*)buf + got, n - got, 0);
        if (r <= 0) return false;
        got += r;
    }
    return true;
}

bool recv_packet(SOCKET s, uint8_t& type, std::vector<uint8_t>& data)
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

HBITMAP decode_jpeg(const uint8_t* jpg, size_t jpg_len, int& out_w, int& out_h)
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

void blit_bitmap(HDC hdc, HBITMAP hbm, int srcW, int srcH,
    int dstX, int dstY, int dstW, int dstH)
{
    HDC mdc = CreateCompatibleDC(hdc);
    HGDIOBJ old = SelectObject(mdc, hbm);
    SetStretchBltMode(hdc, HALFTONE);
    StretchBlt(hdc, dstX, dstY, dstW, dstH, mdc, 0, 0, srcW, srcH, SRCCOPY);
    SelectObject(mdc, old);
    DeleteDC(mdc);
}

HBITMAP make_remote_cursor_bmp(int size)
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

InputConnection::InputConnection(const std::string& h) : host(h) {}

bool InputConnection::connect(double timeout_sec)
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

void InputConnection::send_mouse(int16_t x, int16_t y,
    const char* event, const char* button)
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

void InputConnection::send_key(uint32_t vk, bool pressed)
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

void InputConnection::disconnect()
{
    running = false;
    if (sock != INVALID_SOCKET) {
        send_packet(sock, PKT_DISCONNECT);
        closesocket(sock);
        sock = INVALID_SOCKET;
    }
}

VideoConnection::VideoConnection(const std::string& h, const std::string& name)
    : host(h), controller_name(name) {
}

std::pair<bool, std::string> VideoConnection::connect_video()
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

void VideoConnection::recv_loop()
{
    int rcvbuf = 4 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&rcvbuf, sizeof(rcvbuf));

    s_recv_bw.reset();

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

            bool should_render = s_recv_bw.on_frame_received(
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

void VideoConnection::disconnect()
{
    running = false;
    if (sock != INVALID_SOCKET) {
        send_packet(sock, PKT_DISCONNECT);
        closesocket(sock);
        sock = INVALID_SOCKET;
    }
    if (recv_thread.joinable()) recv_thread.join();
}

static float  s_audio_volume = 1.0f;
static HANDLE s_audio_stop_evt = NULL;

void Core_SetAudioVolume(float v) { s_audio_volume = v; }
void Core_AudioStopEvtCreate() { s_audio_stop_evt = CreateEventW(NULL, TRUE, FALSE, NULL); }
void Core_AudioStopEvtSignal() { if (s_audio_stop_evt) SetEvent(s_audio_stop_evt); }
void Core_AudioStopEvtClose() { if (s_audio_stop_evt) { CloseHandle(s_audio_stop_evt); s_audio_stop_evt = NULL; } }
bool Core_AudioStopEvtValid() { return s_audio_stop_evt != NULL; }

void AudioPlaybackThread(SOCKET sock)
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
        if (s_audio_stop_evt &&
            WaitForSingleObject(s_audio_stop_evt, 0) == WAIT_OBJECT_0) break;

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

        float  vol = s_audio_volume;
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