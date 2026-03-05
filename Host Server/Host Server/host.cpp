#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "Gdiplus.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(linker, "/SUBSYSTEM:WINDOWS")
#include <winsock2.h>
#include <ws2tcpip.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <windowsx.h>
#include <shellapi.h>
#include <gdiplus.h>
using namespace Gdiplus;
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <avrt.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <natupnp.h>
#include <objbase.h>
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "avrt.lib")

static std::deque<std::string> g_log_queue;
static std::mutex              g_log_mutex;
static std::condition_variable g_log_cv;
static std::atomic<bool>       g_log_running(false);
static std::thread             g_log_thread;

static void LogWorker()
{
    std::ofstream f("remote_host.log", std::ios::app);
    while (g_log_running.load()) {
        std::deque<std::string> batch;
        {
            std::unique_lock<std::mutex> lk(g_log_mutex);
            g_log_cv.wait_for(lk, std::chrono::milliseconds(100),
                [] { return !g_log_queue.empty() || !g_log_running.load(); });
            batch.swap(g_log_queue);
        }
        for (auto& m : batch) if (f.is_open()) f << m;
        if (f.is_open()) f.flush();
    }
    for (auto& m : g_log_queue) if (f.is_open()) f << m;
}
static void LogInit()
{
    g_log_running = true;
    g_log_thread = std::thread(LogWorker);
}
static void LogShutdown()
{
    g_log_running = false;
    g_log_cv.notify_all();
    if (g_log_thread.joinable()) g_log_thread.join();
}
static void Log(const std::string& msg)
{
    std::lock_guard<std::mutex> lk(g_log_mutex);
    g_log_queue.push_back(msg);
    g_log_cv.notify_one();
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
            a <<= 1; if (hi) a ^= 0x1b;
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
        t = s[1];  s[1] = s[5];  s[5] = s[9];  s[9] = s[13]; s[13] = t;
        t = s[2];  s[2] = s[10]; s[10] = t;    t = s[6]; s[6] = s[14]; s[14] = t;
        t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
    }
    static void MixColumns(uint8_t s[16]) {
        for (int c = 0; c < 4; c++) {
            uint8_t* col = s + c * 4;
            uint8_t a = col[0], b = col[1], cc = col[2], d = col[3];
            col[0] = gmul(a, 2) ^ gmul(b, 3) ^ cc ^ d;
            col[1] = a ^ gmul(b, 2) ^ gmul(cc, 3) ^ d;
            col[2] = a ^ b ^ gmul(cc, 2) ^ gmul(d, 3);
            col[3] = gmul(a, 3) ^ b ^ cc ^ gmul(d, 2);
        }
    }
    static void EncryptBlock(const uint8_t* rk, const uint8_t in[16], uint8_t out[16]) {
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
            uint64_t cbe = 0;
            for (int i = 0; i < 8; i++) cbe = (cbe << 8) | ((counter >> (56 - i * 8)) & 0xFF);
            memset(ctr_block, 0, 8);
            memcpy(ctr_block + 8, &cbe, 8);
            uint8_t ks[16]; EncryptBlock(ctx.rk, ctr_block, ks);
            size_t chunk = (len - offset < 16) ? (len - offset) : 16;
            for (size_t i = 0; i < chunk; i++) buf[offset + i] ^= ks[i];
            offset += chunk;
            counter++;
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

static AES128::AESCtx        g_aes_ctx;
static bool                  g_aes_enabled = false;
static std::atomic<uint64_t> g_aes_vid_send_ctr{ 0 };

static std::atomic<uint64_t> g_aes_inp_recv_ctr{ 0 };

static void CryptVideoSend(std::vector<uint8_t>& buf) {
    if (!g_aes_enabled || buf.empty()) return;
    uint64_t ctr = g_aes_vid_send_ctr.fetch_add(1);
    AES128::CTR_XOR(g_aes_ctx, ctr, buf.data(), buf.size());
}

static void CryptInputRecv(std::vector<uint8_t>& buf) {
    if (!g_aes_enabled || buf.empty()) return;
    uint64_t ctr = g_aes_inp_recv_ctr.fetch_add(1);
    AES128::CTR_XOR(g_aes_ctx, ctr, buf.data(), buf.size());
}

struct HostConfig {
    int         video_port = 55000;
    int         input_port = 55001;
    int         audio_port = 55002;
    std::string passphrase;

    bool        wan_mode = false;

    bool        startup = false;

};

static std::string TrimStr(const std::string& s) {
    const char* ws = " \t\r\n";
    size_t a = s.find_first_not_of(ws);
    if (a == std::string::npos) return {};
    size_t b = s.find_last_not_of(ws);
    return s.substr(a, b - a + 1);
}

static bool LoadSettings(HostConfig& cfg, std::string& err)
{

    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    wchar_t* slash = wcsrchr(exePath, L'\\');
    if (slash) *(slash + 1) = L'\0';
    wcscat_s(exePath, L"settings.dat");

    char narrowPath[MAX_PATH] = {};
    WideCharToMultiByte(CP_ACP, 0, exePath, -1, narrowPath, MAX_PATH, NULL, NULL);

    std::ifstream f(narrowPath);
    if (!f.is_open()) {
        err =
            "Settings (settings.dat) was not found next to this program.\n";
        return false;
    }

    bool got_vport = false, got_iport = false;
    int  lineno = 0;
    std::string line;

    while (std::getline(f, line)) {
        lineno++;
        std::string t = TrimStr(line);
        if (t.empty() || t[0] == '#') continue;

        size_t eq = t.find('=');
        if (eq == std::string::npos) {
            err = "settings.dat line " + std::to_string(lineno)
                + ": expected key=value, got: \"" + t + "\"";
            return false;
        }

        std::string key = TrimStr(t.substr(0, eq));
        std::string val = TrimStr(t.substr(eq + 1));

        if (key == "video_port") {
            try { cfg.video_port = std::stoi(val); }
            catch (...) {
                err = "settings.dat line " + std::to_string(lineno)
                    + ": video_port is not a valid number: \"" + val + "\"";
                return false;
            }
            if (cfg.video_port < 1024 || cfg.video_port > 65535) {
                err = "settings.dat line " + std::to_string(lineno)
                    + ": video_port must be between 1024 and 65535";
                return false;
            }
            got_vport = true;
        }
        else if (key == "input_port") {
            try { cfg.input_port = std::stoi(val); }
            catch (...) {
                err = "settings.dat line " + std::to_string(lineno)
                    + ": input_port is not a valid number: \"" + val + "\"";
                return false;
            }
            if (cfg.input_port < 1024 || cfg.input_port > 65535) {
                err = "settings.dat line " + std::to_string(lineno)
                    + ": input_port must be between 1024 and 65535";
                return false;
            }
            got_iport = true;
        }
        else if (key == "audio_port") {
            try { cfg.audio_port = std::stoi(val); }
            catch (...) { err = "settings.dat: audio_port is not a valid number: \"" + val + "\""; return false; }
            if (cfg.audio_port < 1024 || cfg.audio_port > 65535) {
                err = "settings.dat: audio_port must be between 1024 and 65535"; return false;
            }
        }
        else if (key == "passphrase") {
            cfg.passphrase = val;

        }
        else if (key == "connection") {
            std::string upper = val;
            for (char& ch : upper) ch = (char)toupper((unsigned char)ch);
            if (upper == "WAN") {
                cfg.wan_mode = true;
            }
            else if (upper == "LAN") {
                cfg.wan_mode = false;
            }
            else {
                err = "settings.dat line " + std::to_string(lineno)
                    + ": connection must be LAN or WAN, got: \"" + val + "\"";
                return false;
            }
        }
        else if (key == "startup") {
            std::string lower = val;
            for (char& ch : lower) ch = (char)tolower((unsigned char)ch);
            cfg.startup = (lower == "true" || lower == "1" || lower == "yes");
        }

    }

    if (!got_vport) { err = "settings.dat: required key 'video_port' is missing"; return false; }
    if (!got_iport) { err = "settings.dat: required key 'input_port' is missing"; return false; }
    if (cfg.video_port == cfg.input_port) {
        err = "settings.dat: video_port and input_port must be different values";
        return false;
    }

    return true;
}

static const uint8_t PKT_HANDSHAKE = 0x01;
static const uint8_t PKT_HANDSHAKE_ACK = 0x02;
static const uint8_t PKT_HANDSHAKE_DENY = 0x03;
static const uint8_t PKT_VIDEO_FRAME = 0x04;
static const uint8_t PKT_HEARTBEAT = 0x05;
static const uint8_t PKT_HEARTBEAT_ACK = 0x06;
static const uint8_t PKT_AUDIO_FRAME = 0x12;
static const uint8_t PKT_MOUSE_EVENT = 0x10;
static const uint8_t PKT_KEY_EVENT = 0x11;
static const uint8_t PKT_DISCONNECT = 0xFF;

static const int   FPS_TARGET = 30;
static const ULONG JPEG_QUAL = 50;

static bool send_all(SOCKET s, const void* buf, int len) {
    const char* p = (const char*)buf;
    while (len > 0) { int r = send(s, p, len, 0); if (r <= 0) return false; p += r; len -= r; }
    return true;
}
static bool recv_all(SOCKET s, void* buf, int len) {
    char* p = (char*)buf;
    while (len > 0) { int r = recv(s, p, len, 0); if (r <= 0) return false; p += r; len -= r; }
    return true;
}
static bool send_packet(SOCKET s, uint8_t type, const void* data, uint32_t dlen) {
    uint8_t hdr[5]; hdr[0] = type;
    uint32_t nl = htonl(dlen); memcpy(hdr + 1, &nl, 4);
    if (!send_all(s, hdr, 5)) return false;
    if (data && dlen) return send_all(s, data, (int)dlen);
    return true;
}
static bool send_packet_empty(SOCKET s, uint8_t type) { return send_packet(s, type, NULL, 0); }

struct Packet { uint8_t type; std::vector<uint8_t> data; };
static bool recv_packet(SOCKET s, Packet& pkt) {
    uint8_t hdr[5]; if (!recv_all(s, hdr, 5)) return false;
    uint32_t nl; memcpy(&nl, hdr + 1, 4); uint32_t len = ntohl(nl);
    pkt.type = hdr[0]; pkt.data.resize(len);
    if (len > 0 && !recv_all(s, pkt.data.data(), (int)len)) return false;
    return true;
}

static ULONG_PTR g_gdiplus_token = 0;
static CLSID     g_jpeg_clsid;

static bool FindJpegClsid(CLSID* out) {
    UINT num = 0, sz = 0; GetImageEncodersSize(&num, &sz);
    if (!sz) return false;
    std::vector<uint8_t> buf(sz);
    ImageCodecInfo* p = (ImageCodecInfo*)buf.data();
    GetImageEncoders(num, sz, p);
    for (UINT i = 0; i < num; i++)
        if (wcscmp(p[i].MimeType, L"image/jpeg") == 0) { *out = p[i].Clsid; return true; }
    return false;
}

static HDESK SwitchToInputDesktop()
{
    HDESK hCurDesk = GetThreadDesktop(GetCurrentThreadId());
    HDESK hInputDesk = OpenInputDesktop(0, FALSE,
        DESKTOP_CREATEMENU | DESKTOP_CREATEWINDOW |
        DESKTOP_ENUMERATE | DESKTOP_HOOKCONTROL |
        DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS |
        DESKTOP_SWITCHDESKTOP);

    if (!hInputDesk)
        return NULL;

    DWORD nameLen1 = 0, nameLen2 = 0;
    GetUserObjectInformationW(hCurDesk, UOI_NAME, NULL, 0, &nameLen1);
    GetUserObjectInformationW(hInputDesk, UOI_NAME, NULL, 0, &nameLen2);
    std::wstring curName(nameLen1 / sizeof(wchar_t) + 1, L'\0');
    std::wstring inpName(nameLen2 / sizeof(wchar_t) + 1, L'\0');
    GetUserObjectInformationW(hCurDesk, UOI_NAME, &curName[0],
        (DWORD)(curName.size() * sizeof(wchar_t)), &nameLen1);
    GetUserObjectInformationW(hInputDesk, UOI_NAME, &inpName[0],
        (DWORD)(inpName.size() * sizeof(wchar_t)), &nameLen2);

    if (curName == inpName) {
        CloseDesktop(hInputDesk);
        return NULL;
    }

    SetThreadDesktop(hInputDesk);
    CloseDesktop(hInputDesk);
    return hCurDesk;  
}

static std::vector<uint8_t> CaptureScreenJpeg() {

    HDESK hPrevDesk = SwitchToInputDesktop();

    HDC hdcScr = GetDC(NULL);
    int sw = GetDeviceCaps(hdcScr, DESKTOPHORZRES);
    int sh = GetDeviceCaps(hdcScr, DESKTOPVERTRES);
    if (sw <= 0) sw = GetSystemMetrics(SM_CXSCREEN);
    if (sh <= 0) sh = GetSystemMetrics(SM_CYSCREEN);

    HDC     hdcMem = CreateCompatibleDC(hdcScr);
    HBITMAP hbmp = CreateCompatibleBitmap(hdcScr, sw, sh);
    HGDIOBJ hOld = SelectObject(hdcMem, hbmp);
    BitBlt(hdcMem, 0, 0, sw, sh, hdcScr, 0, 0, SRCCOPY);

    HFONT hf = CreateFontW(18, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Arial");
    HGDIOBJ hOldF = SelectObject(hdcMem, hf);
    SetBkMode(hdcMem, TRANSPARENT);
    SetTextColor(hdcMem, RGB(255, 60, 60));
    TextOutW(hdcMem, 8, 8, L"[REMOTE SESSION ACTIVE]", 23);
    SelectObject(hdcMem, hOldF); DeleteObject(hf);

    SelectObject(hdcMem, hOld); DeleteDC(hdcMem); ReleaseDC(NULL, hdcScr);

    if (hPrevDesk) {
        SetThreadDesktop(hPrevDesk);
    }

    Bitmap bmp(hbmp, NULL);
    EncoderParameters ep; memset(&ep, 0, sizeof(ep));
    ep.Count = 1; ep.Parameter[0].Guid = EncoderQuality;
    ep.Parameter[0].Type = EncoderParameterValueTypeLong;
    ep.Parameter[0].NumberOfValues = 1; ULONG q = JPEG_QUAL;
    ep.Parameter[0].Value = &q;

    IStream* pStream = NULL; CreateStreamOnHGlobal(NULL, TRUE, &pStream);
    bmp.Save(pStream, &g_jpeg_clsid, &ep);
    STATSTG st; memset(&st, 0, sizeof(st)); pStream->Stat(&st, STATFLAG_NONAME);
    ULONG fsz = st.cbSize.LowPart;
    std::vector<uint8_t> jpeg(fsz);
    LARGE_INTEGER zero; zero.QuadPart = 0; pStream->Seek(zero, STREAM_SEEK_SET, NULL);
    ULONG nr = 0; pStream->Read(jpeg.data(), fsz, &nr);
    pStream->Release(); DeleteObject(hbmp);
    return jpeg;
}

static std::atomic<bool> g_running(false);
static std::atomic<bool> g_session_active(false);
static SOCKET      g_video_sock = INVALID_SOCKET;
static SOCKET      g_input_sock = INVALID_SOCKET;
static std::string g_ctrl_name;
static HWND        g_status_hwnd = NULL;
static bool        g_tray_added = false;
static NOTIFYICONDATA g_nid;

static void AudioServeClient(SOCKET csock)
{
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);

    IMMDeviceEnumerator* pEnum = nullptr;
    IMMDevice* pDevice = nullptr;
    IAudioClient* pClient = nullptr;
    IAudioCaptureClient* pCapture = nullptr;
    WAVEFORMATEX* pwfx = nullptr;

    auto cleanup = [&]() {
        if (pwfx) { CoTaskMemFree(pwfx); pwfx = nullptr; }
        if (pCapture) { pCapture->Release(); pCapture = nullptr; }
        if (pClient) { pClient->Release();  pClient = nullptr; }
        if (pDevice) { pDevice->Release();  pDevice = nullptr; }
        if (pEnum) { pEnum->Release();    pEnum = nullptr; }
        CoUninitialize();
        };

    HRESULT hr = CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr,
        CLSCTX_ALL, __uuidof(IMMDeviceEnumerator), (void**)&pEnum);
    if (FAILED(hr)) { Log("AUDIO: no enumerator\n"); cleanup(); return; }

    hr = pEnum->GetDefaultAudioEndpoint(eRender, eConsole, &pDevice);
    if (FAILED(hr)) { Log("AUDIO: no endpoint\n"); cleanup(); return; }

    hr = pDevice->Activate(__uuidof(IAudioClient), CLSCTX_ALL, nullptr, (void**)&pClient);
    if (FAILED(hr)) { Log("AUDIO: Activate failed\n"); cleanup(); return; }

    hr = pClient->GetMixFormat(&pwfx);
    if (FAILED(hr) || !pwfx) { Log("AUDIO: GetMixFormat failed\n"); cleanup(); return; }

    UINT32 nativeCh = pwfx->nChannels;
    UINT32 nativeSR = pwfx->nSamplesPerSec;
    UINT32 nativeBPS = pwfx->wBitsPerSample;
    bool   isFloat = (pwfx->wFormatTag == WAVE_FORMAT_IEEE_FLOAT);
    if (pwfx->wFormatTag == WAVE_FORMAT_EXTENSIBLE) {
        auto* ex = reinterpret_cast<WAVEFORMATEXTENSIBLE*>(pwfx);
        static const GUID kFloat = { 0x00000003,0x0000,0x0010,{0x80,0x00,0x00,0xaa,0x00,0x38,0x9b,0x71} };
        isFloat = (ex->SubFormat == kFloat);
    }

    hr = pClient->Initialize(AUDCLNT_SHAREMODE_SHARED,
        AUDCLNT_STREAMFLAGS_LOOPBACK, 2000000, 0, pwfx, nullptr);
    CoTaskMemFree(pwfx); pwfx = nullptr;
    if (FAILED(hr)) { Log("AUDIO: Initialize failed hr=" + std::to_string(hr) + "\n"); cleanup(); return; }

    hr = pClient->GetService(__uuidof(IAudioCaptureClient), (void**)&pCapture);
    if (FAILED(hr)) { Log("AUDIO: GetService failed\n"); cleanup(); return; }

    pClient->Start();
    Log("AUDIO: streaming\n");

    bool send_ok = true;
    while (g_running && g_session_active && send_ok) {
        Sleep(10);
        UINT32 pktsz = 0;
        if (FAILED(pCapture->GetNextPacketSize(&pktsz))) break;
        while (pktsz > 0 && send_ok) {
            BYTE* pData = nullptr;
            UINT32 nFrames = 0;
            DWORD  flags = 0;
            if (FAILED(pCapture->GetBuffer(&pData, &nFrames, &flags, nullptr, nullptr))) break;

            std::vector<int16_t> pcm16(nFrames * 2, 0);
            if (!(flags & AUDCLNT_BUFFERFLAGS_SILENT) && pData) {
                for (UINT32 f = 0; f < nFrames; f++) {
                    for (int ch = 0; ch < 2; ch++) {
                        UINT32 srcCh = (ch < (int)nativeCh) ? ch : nativeCh - 1;
                        float s = 0.f;
                        if (isFloat && nativeBPS == 32) {
                            s = reinterpret_cast<const float*>(pData)[f * nativeCh + srcCh];
                        }
                        else if (!isFloat && nativeBPS == 16) {
                            s = reinterpret_cast<const int16_t*>(pData)[f * nativeCh + srcCh] / 32768.f;
                        }
                        else if (!isFloat && nativeBPS == 24) {
                            const uint8_t* bp = pData + (f * nativeCh + srcCh) * 3;
                            int32_t v = bp[0] | (bp[1] << 8) | (bp[2] << 16);
                            if (v & 0x800000) v |= 0xFF000000;
                            s = v / 8388608.f;
                        }
                        else if (!isFloat && nativeBPS == 32) {
                            s = reinterpret_cast<const int32_t*>(pData)[f * nativeCh + srcCh] / 2147483648.f;
                        }
                        s = s < -1.f ? -1.f : s > 1.f ? 1.f : s;
                        pcm16[f * 2 + ch] = (int16_t)(s * 32767.f);
                    }
                }
            }
            pCapture->ReleaseBuffer(nFrames);

            UINT32 pcmBytes = nFrames * 4;
            std::vector<uint8_t> pkt(4 + pcmBytes, 0);
            memcpy(pkt.data(), &nativeSR, 4);
            memcpy(pkt.data() + 4, pcm16.data(), pcmBytes);
            if (!send_packet(csock, PKT_AUDIO_FRAME, pkt.data(), (uint32_t)pkt.size()))
                send_ok = false;
            else if (FAILED(pCapture->GetNextPacketSize(&pktsz)))
                send_ok = false;
        }
    }

    pClient->Stop();
    Log("AUDIO: client disconnected\n");
    cleanup();
}

static void AudioStreamThread(int audio_port)
{
    SOCKET lsock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (lsock == INVALID_SOCKET) { Log("AUDIO: socket failed\n"); return; }
    int opt = 1; setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
    sockaddr_in sa{}; sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = INADDR_ANY; sa.sin_port = htons((u_short)audio_port);
    if (bind(lsock, (sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR || listen(lsock, 1) == SOCKET_ERROR) {
        Log("AUDIO: bind/listen failed\n"); closesocket(lsock); return;
    }
    Log("AUDIO: Listening on port " + std::to_string(audio_port) + "\n");

    while (g_running) {
        fd_set rs; FD_ZERO(&rs); FD_SET(lsock, &rs);
        timeval tv{ 1, 0 };
        if (select(0, &rs, NULL, NULL, &tv) <= 0) continue;
        sockaddr_in ca{}; int cal = sizeof(ca);
        SOCKET csock = accept(lsock, (sockaddr*)&ca, &cal);
        if (csock == INVALID_SOCKET) continue;
        Log("AUDIO: client connected\n");
        AudioServeClient(csock);
        closesocket(csock);
    }

    closesocket(lsock);
    Log("AUDIO: thread exit\n");
}

static void VideoStreamThread() {
    using namespace std::chrono;
    const milliseconds frame_ms(1000 / FPS_TARGET);
    Log("VIDEO: Streaming started\n");

    while (g_running && g_session_active) {
        auto t0 = steady_clock::now();

        std::vector<uint8_t> jpeg = CaptureScreenJpeg();
        if (!jpeg.empty()) {
            POINT cur = { 0, 0 }; GetCursorPos(&cur);
            HDC tmp = GetDC(NULL);
            int sw = GetDeviceCaps(tmp, DESKTOPHORZRES);
            int sh = GetDeviceCaps(tmp, DESKTOPVERTRES);
            ReleaseDC(NULL, tmp);
            if (sw <= 0) sw = GetSystemMetrics(SM_CXSCREEN);
            if (sh <= 0) sh = GetSystemMetrics(SM_CYSCREEN);

            int nx = sw ? (int)(((double)cur.x / sw) * 65535) : 0;
            int ny = sh ? (int)(((double)cur.y / sh) * 65535) : 0;
            nx = max(0, min(65535, nx));
            ny = max(0, min(65535, ny));
            uint32_t nnx = htonl((uint32_t)nx);
            uint32_t nny = htonl((uint32_t)ny);

            std::vector<uint8_t> payload(8 + jpeg.size());
            memcpy(payload.data() + 0, &nnx, 4);
            memcpy(payload.data() + 4, &nny, 4);
            memcpy(payload.data() + 8, jpeg.data(), jpeg.size());

            CryptVideoSend(payload);

            if (!send_packet(g_video_sock, PKT_VIDEO_FRAME,
                payload.data(), (uint32_t)payload.size())) {
                Log("VIDEO: Send failed\n");
                break;
            }
        }

        auto elapsed = duration_cast<milliseconds>(steady_clock::now() - t0);
        if (elapsed < frame_ms) std::this_thread::sleep_for(frame_ms - elapsed);
    }

    Log("VIDEO: Streaming ended\n");
    g_session_active = false;
}

static void HeartbeatThread() {
    while (g_running && g_session_active) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        if (!g_session_active) break;
        if (!send_packet_empty(g_video_sock, PKT_HEARTBEAT)) break;
    }
}

static void InputThread() {
    Log("INPUT: Listening\n");

    typedef VOID(WINAPI* PFN_SendSAS)(BOOL asUser);
    static PFN_SendSAS pfnSendSAS = nullptr;
    if (!pfnSendSAS) {
        HMODULE hSas = LoadLibraryW(L"sas.dll");
        if (hSas) pfnSendSAS = (PFN_SendSAS)GetProcAddress(hSas, "SendSAS");
    }

    bool ctrl_down = false;
    bool alt_down = false;
    bool del_pending = false;

    HDC tmp = GetDC(NULL);
    int phys_w = GetDeviceCaps(tmp, DESKTOPHORZRES);
    int phys_h = GetDeviceCaps(tmp, DESKTOPVERTRES);
    ReleaseDC(NULL, tmp);
    if (phys_w <= 0) phys_w = GetSystemMetrics(SM_CXSCREEN);
    if (phys_h <= 0) phys_h = GetSystemMetrics(SM_CYSCREEN);
    double abs_x = phys_w / 2.0, abs_y = phys_h / 2.0;

    while (g_running && g_session_active) {
        Packet pkt;
        if (!recv_packet(g_input_sock, pkt)) break;
        if (pkt.type == PKT_DISCONNECT) break;

        CryptInputRecv(pkt.data);

        if (pkt.type == PKT_MOUSE_EVENT && pkt.data.size() >= 12) {
            int16_t rx = 0, ry = 0;
            char ev[5] = {}, bt[5] = {};
            memcpy(&rx, pkt.data.data() + 0, 2);
            memcpy(&ry, pkt.data.data() + 2, 2);
            memcpy(ev, pkt.data.data() + 4, 4);
            memcpy(bt, pkt.data.data() + 8, 4);
            rx = (int16_t)ntohs(*(uint16_t*)&rx);
            ry = (int16_t)ntohs(*(uint16_t*)&ry);
            std::string evt(ev), btn(bt);

            INPUT inp; memset(&inp, 0, sizeof(inp)); inp.type = INPUT_MOUSE;
            if (evt == "rel ") {
                abs_x += rx; abs_y += ry;
                double cx = max(0.0, min((double)(phys_w - 1), abs_x));
                double cy = max(0.0, min((double)(phys_h - 1), abs_y));
                inp.mi.dx = (LONG)((cx / phys_w) * 65535.0);
                inp.mi.dy = (LONG)((cy / phys_h) * 65535.0);
                inp.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;
            }
            else if (evt == "down") {
                if (btn.substr(0, 4) == "left") inp.mi.dwFlags |= MOUSEEVENTF_LEFTDOWN;
                else if (btn.substr(0, 4) == "righ")  inp.mi.dwFlags |= MOUSEEVENTF_RIGHTDOWN;
                else if (btn.substr(0, 4) == "midd")  inp.mi.dwFlags |= MOUSEEVENTF_MIDDLEDOWN;
            }
            else if (evt == "up  ") {
                if (btn.substr(0, 4) == "left") inp.mi.dwFlags |= MOUSEEVENTF_LEFTUP;
                else if (btn.substr(0, 4) == "righ")  inp.mi.dwFlags |= MOUSEEVENTF_RIGHTUP;
                else if (btn.substr(0, 4) == "midd")  inp.mi.dwFlags |= MOUSEEVENTF_MIDDLEUP;
            }
            else if (evt == "scro") {
                inp.mi.dwFlags = MOUSEEVENTF_WHEEL;
                int d = 0; try { d = std::stoi(std::string(bt)); }
                catch (...) {}
                inp.mi.mouseData = (DWORD)(d * WHEEL_DELTA);
            }
            if (inp.mi.dwFlags) SendInput(1, &inp, sizeof(INPUT));
        }
        else if (pkt.type == PKT_KEY_EVENT && pkt.data.size() >= 5) {
            uint32_t vkn = 0; memcpy(&vkn, pkt.data.data(), 4);
            uint8_t pressed = pkt.data[4];
            WORD vk = (WORD)ntohl(vkn);

            if (vk == VK_CONTROL || vk == VK_LCONTROL || vk == VK_RCONTROL)
                ctrl_down = (pressed != 0);
            if (vk == VK_MENU || vk == VK_LMENU || vk == VK_RMENU)
                alt_down = (pressed != 0);

            if (vk == VK_DELETE && pressed && ctrl_down && alt_down) {
                if (pfnSendSAS) {
                    pfnSendSAS(FALSE); 
                    Log("INPUT: SendSAS triggered\n");
                }
                else {

                    INPUT sas[3]; memset(sas, 0, sizeof(sas));
                    sas[0].type = INPUT_KEYBOARD; sas[0].ki.wVk = VK_CONTROL;
                    sas[1].type = INPUT_KEYBOARD; sas[1].ki.wVk = VK_MENU;
                    sas[2].type = INPUT_KEYBOARD; sas[2].ki.wVk = VK_DELETE;
                    sas[2].ki.dwFlags = KEYEVENTF_EXTENDEDKEY;
                    SendInput(3, sas, sizeof(INPUT));
                    sas[0].ki.dwFlags = KEYEVENTF_KEYUP;
                    sas[1].ki.dwFlags = KEYEVENTF_KEYUP;
                    sas[2].ki.dwFlags = KEYEVENTF_KEYUP | KEYEVENTF_EXTENDEDKEY;
                    SendInput(3, sas, sizeof(INPUT));
                    Log("INPUT: Ctrl+Alt+Del fallback injected\n");
                }
                continue;
            }

            WORD sc = (WORD)MapVirtualKeyW(vk, MAPVK_VK_TO_VSC);
            static const WORD ext[] = {
                VK_RMENU, VK_RCONTROL, VK_RSHIFT,
                VK_INSERT, VK_DELETE, VK_HOME, VK_END,
                VK_PRIOR, VK_NEXT, VK_UP, VK_DOWN, VK_LEFT, VK_RIGHT,
                VK_NUMLOCK, VK_CANCEL, VK_SNAPSHOT, VK_DIVIDE,
                VK_LWIN, VK_RWIN, VK_APPS
            };
            bool isExt = false;
            for (WORD e : ext) if (vk == e) { isExt = true; break; }
            INPUT inp; memset(&inp, 0, sizeof(inp)); inp.type = INPUT_KEYBOARD;
            inp.ki.wVk = vk;
            inp.ki.wScan = sc;
            inp.ki.dwFlags = 0;
            if (!pressed) inp.ki.dwFlags |= KEYEVENTF_KEYUP;
            if (isExt)    inp.ki.dwFlags |= KEYEVENTF_EXTENDEDKEY;
            SendInput(1, &inp, sizeof(INPUT));
        }
    }

    Log("INPUT: Thread ended\n");
    g_session_active = false;
}

#define WM_TRAY_ICON   (WM_USER + 1)
#define IDM_DISCONNECT  1001

static LRESULT CALLBACK TrayWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_TRAY_ICON && (UINT)lp == WM_RBUTTONUP) {
        POINT pt; GetCursorPos(&pt);
        HMENU hm = CreatePopupMenu();
        AppendMenuW(hm, MF_STRING, IDM_DISCONNECT, L"Disconnect remote session");
        SetForegroundWindow(hwnd);
        int cmd = TrackPopupMenu(hm, TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, hwnd, NULL);
        DestroyMenu(hm);
        if (cmd == IDM_DISCONNECT) { Log("TRAY: Disconnect\n"); g_session_active = false; }
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static void AddTrayIcon(HWND hwnd) {
    memset(&g_nid, 0, sizeof(g_nid)); g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd = hwnd; g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE;
    g_nid.uCallbackMessage = WM_TRAY_ICON;
    g_nid.hIcon = LoadIcon(NULL, IDI_INFORMATION);
    wcscpy_s(g_nid.szTip, L"Remote Desktop - Session Active");
    Shell_NotifyIcon(NIM_ADD, &g_nid); g_tray_added = true;
}
static void RemoveTrayIcon() {
    if (g_tray_added) { Shell_NotifyIcon(NIM_DELETE, &g_nid); g_tray_added = false; }
}

static bool        g_upnp_mapped = false;
static std::string g_upnp_vid_desc;
static std::string g_upnp_inp_desc;

static LRESULT CALLBACK StatusWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    case WM_PAINT: {
        PAINTSTRUCT ps; HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc; GetClientRect(hwnd, &rc);

        HBRUSH bg = CreateSolidBrush(RGB(20, 20, 20));
        FillRect(hdc, &rc, bg); DeleteObject(bg);

        HPEN pen = CreatePen(PS_SOLID, 1, RGB(80, 80, 80));
        HGDIOBJ op = SelectObject(hdc, pen);
        HGDIOBJ ob = SelectObject(hdc, GetStockObject(NULL_BRUSH));
        RoundRect(hdc, 0, 0, rc.right - 1, rc.bottom - 1, 8, 8);
        SelectObject(hdc, op); SelectObject(hdc, ob); DeleteObject(pen);

        SetBkMode(hdc, TRANSPARENT);
        HFONT hf = CreateFontW(13, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        HGDIOBJ of = SelectObject(hdc, hf);

        SetTextColor(hdc, RGB(255, 80, 80));
        RECT r1 = { 10, 8, rc.right - 10, 24 };
        DrawTextW(hdc, L"  REMOTE SESSION ACTIVE", -1, &r1, DT_LEFT | DT_SINGLELINE);

        SetTextColor(hdc, RGB(180, 180, 180));
        std::wstring cl = L"    Controller: " +
            std::wstring(g_ctrl_name.begin(), g_ctrl_name.end());
        RECT r2 = { 10, 28, rc.right - 10, 44 };
        DrawTextW(hdc, cl.c_str(), -1, &r2, DT_LEFT | DT_SINGLELINE);

        SetTextColor(hdc, g_aes_enabled ? RGB(100, 220, 100) : RGB(200, 130, 50));
        RECT r3 = { 10, 44, rc.right - 10, 58 };
        DrawTextW(hdc,
            g_aes_enabled ? L"    Encrypted (AES-128-CTR)" : L"    Unencrypted",
            -1, &r3, DT_LEFT | DT_SINGLELINE);

        SetTextColor(hdc, g_upnp_mapped ? RGB(100, 180, 255) : RGB(140, 140, 140));
        RECT r4 = { 10, 58, rc.right - 10, 74 };
        DrawTextW(hdc,
            g_upnp_mapped ? L"    UPnP: ports forwarded" : L"    UPnP: not mapped (LAN only)",
            -1, &r4, DT_LEFT | DT_SINGLELINE);

        SetTextColor(hdc, RGB(80, 80, 80));
        RECT r5 = { 10, 72, rc.right - 10, 88 };
        DrawTextW(hdc, L"    Right-click tray to disconnect", -1, &r5, DT_LEFT | DT_SINGLELINE);

        SelectObject(hdc, of); DeleteObject(hf);
        EndPaint(hwnd, &ps);
        return 0;
    }
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static void RunStatusWindow() {
    HINSTANCE hInst = GetModuleHandle(NULL);
    WNDCLASSW wc; memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = StatusWndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"RemoteHostStatus";
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    RegisterClassW(&wc);

    DWORD exStyle = WS_EX_TOPMOST | WS_EX_TOOLWINDOW |
        WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE;
    int winW = 280, winH = 96;
    int scrH = GetSystemMetrics(SM_CYSCREEN);

    HWND hwnd = CreateWindowExW(exStyle, L"RemoteHostStatus",
        L"Remote Desktop - Session Active", WS_POPUP,
        10, scrH - winH - 10, winW, winH,
        NULL, NULL, hInst, NULL);

    SetLayeredWindowAttributes(hwnd, RGB(0, 0, 0), (BYTE)(255 * 0.70), LWA_ALPHA);
    g_status_hwnd = hwnd;
    ShowWindow(hwnd, SW_SHOWNOACTIVATE);
    UpdateWindow(hwnd);
    AddTrayIcon(hwnd);

    MSG wmsg;
    while (GetMessage(&wmsg, NULL, 0, 0) > 0) {
        TranslateMessage(&wmsg);
        DispatchMessage(&wmsg);
        if (!g_session_active) { DestroyWindow(hwnd); break; }
    }

    RemoveTrayIcon();
    g_status_hwnd = NULL;
}

static bool ShowConsentDialog(const std::string& ctrl_name) {
    std::wstring wn(ctrl_name.begin(), ctrl_name.end());
    std::wstring msg =
        L"A remote controller is requesting access.\n\n"
        L"Name: " + wn + L"\n\n"
        L"If you allow:\n"
        L"  - Your screen will be streamed.\n"
        L"  - They can control your mouse and keyboard\n"
        L"  - A red watermark will appear on your screen\n"
        L"Do you want to allow this connection?";
    return MessageBoxW(NULL, msg.c_str(),
        L"Remote Desktop - Access Request",
        MB_YESNO | MB_ICONQUESTION | MB_TOPMOST | MB_SETFOREGROUND) == IDYES;
}

static BSTR GetLocalIPBSTR()
{

    char hostname[256] = {};
    gethostname(hostname, sizeof(hostname));
    struct addrinfo hints {}, * res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    std::string bestIP = "0.0.0.0";
    int         bestRank = 99;

    if (getaddrinfo(hostname, nullptr, &hints, &res) == 0) {
        for (auto* p = res; p != nullptr; p = p->ai_next) {
            char ipbuf[INET_ADDRSTRLEN] = {};
            sockaddr_in* sa = reinterpret_cast<sockaddr_in*>(p->ai_addr);
            inet_ntop(AF_INET, &sa->sin_addr, ipbuf, sizeof(ipbuf));
            std::string ip = ipbuf;

            int rank = 99;
            if (ip.find("127.") == 0)               continue;

            else if (ip.find("192.168.") == 0)           rank = 0;

            else if (ip.find("10.") == 0)           rank = 1;

            else if (ip.find("172.") == 0) {

                int second = 0;
                try { second = std::stoi(ip.substr(4, ip.find('.', 4) - 4)); }
                catch (...) {}
                rank = (second >= 16 && second <= 31) ? 2 : 10;

            }
            else if (ip.find("169.254.") == 0)           rank = 20;

            else if (ip.find("100.") == 0)           rank = 15;

            else                                         rank = 10;

            if (rank < bestRank) { bestRank = rank; bestIP = ip; }
        }
        freeaddrinfo(res);
    }

    Log("HOST: Selected local IP = " + bestIP + "\n");
    int wlen = MultiByteToWideChar(CP_ACP, 0, bestIP.c_str(), -1, nullptr, 0);
    std::wstring wip(wlen, L'\0');
    MultiByteToWideChar(CP_ACP, 0, bestIP.c_str(), -1, &wip[0], wlen);
    return SysAllocString(wip.c_str());
}

static bool UPnPAddMapping(IStaticPortMappingCollection* pColl,
    int port, const char* desc)
{
    BSTR bProto = SysAllocString(L"TCP");
    BSTR bDesc = nullptr;
    {
        int wlen = MultiByteToWideChar(CP_ACP, 0, desc, -1, nullptr, 0);
        std::wstring wd(wlen, L'\0');
        MultiByteToWideChar(CP_ACP, 0, desc, -1, &wd[0], wlen);
        bDesc = SysAllocString(wd.c_str());
    }
    BSTR bLocalIP = GetLocalIPBSTR();

    IStaticPortMapping* pMap = nullptr;
    HRESULT hr = pColl->Add(
        (long)port,

        bProto,
        (long)port,

        bLocalIP,
        VARIANT_TRUE,

        bDesc,
        &pMap);

    SysFreeString(bProto);
    SysFreeString(bDesc);
    SysFreeString(bLocalIP);
    if (pMap) pMap->Release();

    return SUCCEEDED(hr);
}

static void UPnPRemoveMapping(IStaticPortMappingCollection* pColl, int port)
{
    BSTR bProto = SysAllocString(L"TCP");
    pColl->Remove((long)port, bProto);
    SysFreeString(bProto);
}

static void EnsureFirewallRules(int vport, int iport, int aport)
{
    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    wchar_t cmd[1024] = {};
    swprintf_s(cmd,
        L"advfirewall firewall add rule"
        L" name=\"RemoteDesktopHost\""
        L" dir=in action=allow protocol=TCP"
        L" localport=%d,%d,%d"
        L" program=\"%s\""
        L" enable=yes",
        vport, iport, aport, exePath);

    HINSTANCE res = ShellExecuteW(NULL, L"runas", L"netsh.exe", cmd, NULL, SW_HIDE);
    if ((INT_PTR)res > 32)
        Log("HOST: Firewall rule added/updated for ports "
            + std::to_string(vport) + ", "
            + std::to_string(iport) + ", "
            + std::to_string(aport) + "\n");
    else
        Log("HOST: Firewall rule setup skipped or failed (UAC denied?)\n");
}

static void CheckForDoubleNAT(IStaticPortMappingCollection* pColl, int probe_port)
{

    IStaticPortMapping* pMap = nullptr;
    BSTR bProto = SysAllocString(L"TCP");
    HRESULT hr = pColl->get_Item((long)probe_port, bProto, &pMap);
    SysFreeString(bProto);
    if (FAILED(hr) || !pMap) return;

    BSTR bExtIP = nullptr;
    hr = pMap->get_ExternalIPAddress(&bExtIP);
    pMap->Release();
    if (FAILED(hr) || !bExtIP) return;

    char extIPBuf[64] = {};
    WideCharToMultiByte(CP_ACP, 0, bExtIP, -1, extIPBuf, sizeof(extIPBuf), NULL, NULL);
    SysFreeString(bExtIP);
    std::string extIP = extIPBuf;
    Log("HOST: Router WAN IP reported by IGD = " + extIP + "\n");

    bool isCGNAT = (extIP.find("100.") == 0);
    bool isPrivate10 = (extIP.find("10.") == 0);
    bool isPrivate172 = false;
    if (extIP.find("172.") == 0) {
        int second = 0;
        try { second = std::stoi(extIP.substr(4, extIP.find('.', 4) - 4)); }
        catch (...) {}
        isPrivate172 = (second >= 16 && second <= 31);
    }
    bool isPrivate192 = (extIP.find("192.168.") == 0);

    if (isCGNAT || isPrivate10 || isPrivate172 || isPrivate192) {
        std::wstring reason = isCGNAT
            ? L"Your ISP is using CGNAT (Carrier-Grade NAT).\n"
            L"The external IP reported by your router (" + std::wstring(extIPBuf, extIPBuf + strlen(extIPBuf)) + L")\n"
            L"is itself inside a private range — your router is behind another NAT."
            : L"Double-NAT detected.\n"
            L"Your router's WAN IP (" + std::wstring(extIPBuf, extIPBuf + strlen(extIPBuf)) + L")\n"
            L"is a private address, meaning there is another router between you and the internet.";

        std::wstring msg = reason +
            L"WAN clients will not be able to connect.\n\n"
            L"Solutions:\n"
            L"  \x2022  Ask your ISP for a public static IP\n"
            L"  \x2022  Use a VPN tunnel (WireGuard, ZeroTier, Tailscale)\n"
            L"  \x2022  Use a relay/TURN server\n\n"
            L"LAN connections are unaffected.";

        MessageBoxW(NULL, msg.c_str(),
            L"Remote Desktop Host \x2014 Double-NAT / CGNAT Warning",
            MB_OK | MB_ICONWARNING | MB_TOPMOST);

        Log("HOST: WARNING — double-NAT/CGNAT: WAN IP=" + extIP + "\n");
    }
}

static void UPnPOpenPorts(int video_port, int input_port)
{
    g_upnp_mapped = false;

    CoInitializeEx(nullptr, COINIT_MULTITHREADED);

    IUPnPNAT* pNAT = nullptr;
    HRESULT hr = CoCreateInstance(__uuidof(UPnPNAT), nullptr,
        CLSCTX_ALL, __uuidof(IUPnPNAT), (void**)&pNAT);
    if (FAILED(hr) || !pNAT) {
        Log("UPnP: CoCreateInstance failed (NAT COM not available)\n");
        MessageBoxW(NULL,
            L"UPnP is not available on this system.\n\n"
            L"The Windows UPnP service (UPnPNAT) could not be started.\n\n"
            L"Possible fixes:\n"
            L"  \x2022  Enable \"SSDP Discovery\" & \"UPnP Device Host\"\n"
            L"  \x2022  Restart the host machine\n\n"
            L"WAN connections will not work.\n"
            L"LAN connections are unaffected.",
            L"Remote Desktop Host \x2014 UPnP Unavailable",
            MB_OK | MB_ICONWARNING | MB_TOPMOST);
        return;
    }

    IStaticPortMappingCollection* pColl = nullptr;
    hr = pNAT->get_StaticPortMappingCollection(&pColl);
    pNAT->Release();
    if (FAILED(hr) || !pColl) {
        Log("UPnP: No IGD found on this network\n");
        MessageBoxW(NULL,
            L"No UPnP-capable router (IGD) was found on this network.\n\n"
            L"Possible causes:\n"
            L"  \x2022  Your router has UPnP disabled.\n"
            L"  \x2022  You are using a switch with no UPnP-capable gateway\n"
            L"  \x2022  A firewall is blocking SSDP discovery (UDP port 1900)\n\n"
            L"WAN connections will not work.\n"
            L"LAN connections are unaffected.",
            L"Remote Desktop Host \x2014 No UPnP Router Found",
            MB_OK | MB_ICONWARNING | MB_TOPMOST);
        return;
    }

    g_upnp_vid_desc = "RDHost-Video-" + std::to_string(video_port);
    g_upnp_inp_desc = "RDHost-Input-" + std::to_string(input_port);

    bool ok_vid = UPnPAddMapping(pColl, video_port, g_upnp_vid_desc.c_str());
    bool ok_inp = UPnPAddMapping(pColl, input_port, g_upnp_inp_desc.c_str());

    if (ok_vid && ok_inp) {
        g_upnp_mapped = true;
        Log("UPnP: Ports " + std::to_string(video_port) + " & "
            + std::to_string(input_port) + " forwarded via IGD\n");

        wchar_t successMsg[512];
        swprintf_s(successMsg,
            L"UPnP port forwarding is active.\n\n"
            L"  \x2022  Video port:  %d\n"
            L"  \x2022  Input port:  %d\n\n"
            L"Remote clients can now connect over the internet\n"
            L"(provided your router's WAN IP is publicly reachable).",
            video_port, input_port);
        MessageBoxW(NULL, successMsg,
            L"Remote Desktop Host \x2014 UPnP Active",
            MB_OK | MB_ICONINFORMATION | MB_TOPMOST);

        CheckForDoubleNAT(pColl, video_port);
        pColl->Release();
        return;
    }

    pColl->Release();

    if (ok_vid || ok_inp) {
        int failed_port = ok_vid ? input_port : video_port;
        wchar_t msg[512];
        swprintf_s(msg,
            L"UPnP partial mapping: only one of the two ports was forwarded.\n\n"
            L"  \x2022  Video port %d:  %s\n"
            L"  \x2022  Input port %d:  %s\n\n"
            L"Port %d could not be mapped — your router may have rejected it.\n\n"
            L"Try forwarding port %d manually in your router settings.\n"
            L"Remote connections over WAN may be unreliable.",
            video_port, ok_vid ? L"OK" : L"FAILED",
            input_port, ok_inp ? L"OK" : L"FAILED",
            failed_port, failed_port);
        Log("UPnP: Partial mapping — port " + std::to_string(failed_port) + " failed\n");
        MessageBoxW(NULL, msg,
            L"Remote Desktop Host \x2014 UPnP Partial Mapping",
            MB_OK | MB_ICONWARNING | MB_TOPMOST);
        return;
    }

    Log("UPnP: Mapping failed for both ports\n");
    MessageBoxW(NULL,
        L"UPnP port forwarding failed for both ports.\n\n"
        L"Your router found but rejected the mapping requests.\n\n"
        L"Possible causes:\n"
        L"  \x2022  The router's UPnP implementation is restricted or broken\n"
        L"  \x2022  Another device has already claimed these ports\n"
        L"  \x2022  The router firmware has a UPnP bug\n\n"
        L"Try forwarding the ports manually in your router settings,\n"
        L"or use a VPN/tunnel solution (ZeroTier, Tailscale, WireGuard).",
        L"Remote Desktop Host \x2014 UPnP Mapping Failed",
        MB_OK | MB_ICONERROR | MB_TOPMOST);
}

static void UPnPClosePorts(int video_port, int input_port)
{
    if (!g_upnp_mapped) return;
    g_upnp_mapped = false;

    IUPnPNAT* pNAT = nullptr;
    HRESULT hr = CoCreateInstance(__uuidof(UPnPNAT), nullptr,
        CLSCTX_ALL, __uuidof(IUPnPNAT), (void**)&pNAT);
    if (FAILED(hr) || !pNAT) return;

    IStaticPortMappingCollection* pColl = nullptr;
    hr = pNAT->get_StaticPortMappingCollection(&pColl);
    pNAT->Release();
    if (FAILED(hr) || !pColl) return;

    UPnPRemoveMapping(pColl, video_port);
    UPnPRemoveMapping(pColl, input_port);
    pColl->Release();
    Log("UPnP: Port mappings removed\n");
}

static bool AcceptSession(SOCKET vid_listen, SOCKET inp_listen) {
    Log("\nHOST: Waiting for controller...\n");
    sockaddr_in addr; memset(&addr, 0, sizeof(addr)); int al = sizeof(addr);

    SOCKET is = accept(inp_listen, (sockaddr*)&addr, &al);
    if (is == INVALID_SOCKET) { Log("HOST: Input accept failed\n"); return false; }

    SOCKET vs = accept(vid_listen, (sockaddr*)&addr, &al);
    if (vs == INVALID_SOCKET) { closesocket(is); return false; }

    char ip[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
    Log(std::string("HOST: Connection from ") + ip + "\n");

    Packet pkt;
    if (!recv_packet(vs, pkt) || pkt.type != PKT_HANDSHAKE) {
        closesocket(vs); closesocket(is); return false;
    }
    std::string name(pkt.data.begin(), pkt.data.end());
    size_t nul = name.find('\0'); if (nul != std::string::npos) name = name.substr(0, nul);
    Log("HOST: Handshake from \"" + name + "\"\n");

    if (!ShowConsentDialog(name)) {
        const char* d = "Denied by user";
        send_packet(vs, PKT_HANDSHAKE_DENY, d, (uint32_t)strlen(d));
        closesocket(vs); closesocket(is);
        Log("HOST: Denied\n");
        return false;
    }

    g_aes_vid_send_ctr = 0;
    g_aes_inp_recv_ctr = 0;

    send_packet_empty(vs, PKT_HANDSHAKE_ACK);
    g_video_sock = vs;
    g_input_sock = is;
    g_ctrl_name = name;
    g_session_active = true;
    Log("HOST: Session started for \"" + name + "\"\n");
    return true;
}

static const wchar_t* STARTUP_REG_KEY =
L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
static const wchar_t* STARTUP_VALUE_NAME = L"RemoteDesktopHost";

static bool IsInStartup()
{
    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, STARTUP_REG_KEY,
        0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return false;

    wchar_t val[MAX_PATH] = {};
    DWORD sz = sizeof(val);
    DWORD type = 0;
    LONG r = RegQueryValueExW(hKey, STARTUP_VALUE_NAME, NULL,
        &type, (LPBYTE)val, &sz);
    RegCloseKey(hKey);

    if (r != ERROR_SUCCESS) return false;

    return (_wcsicmp(val, exePath) == 0);
}

static bool SetStartupEntry(bool enable)
{
    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, STARTUP_REG_KEY,
        0, KEY_WRITE, &hKey) != ERROR_SUCCESS)
        return false;

    LONG r;
    if (enable) {
        wchar_t exePath[MAX_PATH] = {};
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        r = RegSetValueExW(hKey, STARTUP_VALUE_NAME, 0, REG_SZ,
            (const BYTE*)exePath,
            (DWORD)((wcslen(exePath) + 1) * sizeof(wchar_t)));
    }
    else {
        r = RegDeleteValueW(hKey, STARTUP_VALUE_NAME);
    }
    RegCloseKey(hKey);
    return (r == ERROR_SUCCESS);
}

static void HandleStartupRegistration()
{
    if (IsInStartup()) return;

    int answer = MessageBoxW(
        NULL,
        L"This host is configured to register in Windows Startup\n"
        L"Do you want to add it to your startup apps?\n\n"
        L"(You can remove it later via Task Manager > Startup Apps)",
        L"Remote Desktop Host - Startup Registration",
        MB_YESNO | MB_ICONQUESTION | MB_TOPMOST | MB_SETFOREGROUND);

    if (answer == IDYES) {
        if (SetStartupEntry(true))
            Log("HOST: Registered in Windows startup\n");
        else
            Log("HOST: Failed to register in Windows startup (registry write error)\n");
    }
    else {
        Log("HOST: User declined startup registration\n");
    }
}

static bool IsRunningAsAdmin()
{
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminGroup))
    {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin == TRUE;
}

static void RelaunchAsAdmin()
{
    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    ShellExecuteW(NULL, L"runas", exePath, NULL, NULL, SW_SHOWNORMAL);
}

static void CheckAndWarnSASRegistry()
{
    HKEY hKey = NULL;
    LONG res = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        0, KEY_READ, &hKey);

    bool sasOk = false;
    if (res == ERROR_SUCCESS) {
        DWORD val = 0, sz = sizeof(val), type = 0;
        res = RegQueryValueExW(hKey, L"SoftwareSASGeneration",
            NULL, &type, (LPBYTE)&val, &sz);
        if (res == ERROR_SUCCESS && val >= 1)
            sasOk = true;
        RegCloseKey(hKey);
    }

    if (!sasOk) {
        int choice = MessageBoxW(NULL,
            L"The registry key required for Ctrl+Alt+Del (SendSAS) support was not found.\n\n"
            L"Without it, the remote Ctrl+Alt+Del function will not work.\n\n"
            L"Key:   HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\n"
            L"Value: SoftwareSASGeneration = 1\n\n"
            L"Click OK to add it automatically now.\n"
            L"Click Cancel to skip (Ctrl+Alt+Del forwarding will be disabled).",
            L"Remote Desktop Host \x2014 SendSAS Registry Key Missing",
            MB_OKCANCEL | MB_ICONWARNING | MB_TOPMOST | MB_SETFOREGROUND);

        if (choice == IDOK) {
            HKEY hWrite = NULL;
            LONG r = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                0, NULL, REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE, NULL, &hWrite, NULL);
            if (r == ERROR_SUCCESS) {
                DWORD val = 1;
                RegSetValueExW(hWrite, L"SoftwareSASGeneration",
                    0, REG_DWORD, (LPBYTE)&val, sizeof(val));
                RegCloseKey(hWrite);
                MessageBoxW(NULL,
                    L"Registry key added successfully.\n\n"
                    L"Ctrl+Alt+Del forwarding is now enabled.",
                    L"Remote Desktop Host \x2014 Registry Updated",
                    MB_OK | MB_ICONINFORMATION | MB_TOPMOST);
                Log("HOST: SoftwareSASGeneration registry key added\n");
            }
            else {
                MessageBoxW(NULL,
                    L"Failed to write the registry key.\n\n"
                    L"Please add it manually via an elevated Command Prompt:\n\n"
                    L"reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" "
                    L"/v SoftwareSASGeneration /t REG_DWORD /d 1 /f",
                    L"Remote Desktop Host \x2014 Registry Write Failed",
                    MB_OK | MB_ICONERROR | MB_TOPMOST);
                Log("HOST: Failed to write SoftwareSASGeneration registry key\n");
            }
        }
        else {
            Log("HOST: User skipped SoftwareSASGeneration registry key\n");
        }
    }
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
    if (!IsRunningAsAdmin()) {
        int choice = MessageBoxW(NULL,
            L"Remote Desktop Host must be run as Administrator.\n\n"
            L"This is required for:\n"
            L"  \x2022  Capturing the UAC / Secure Desktop screen\n"
            L"  \x2022  Sending Ctrl+Alt+Del to the remote machine\n"
            L"  \x2022  Injecting keyboard and mouse input globally\n\n"
            L"Click OK to restart as Administrator now.\n"
            L"Click Cancel to exit.",
            L"Remote Desktop Host \x2014 Administrator Required",
            MB_OKCANCEL | MB_ICONWARNING | MB_TOPMOST | MB_SETFOREGROUND);
        if (choice == IDOK)
            RelaunchAsAdmin();
        return 1;
    }
    HANDLE hMutex = CreateMutexW(NULL, TRUE, L"Global\\RemoteDesktopHost_SingleInstance");
    if (hMutex == NULL || GetLastError() == ERROR_ALREADY_EXISTS) {
        MessageBoxW(NULL,
            L"Remote Desktop Host is already running.\n\n"
            L"Only one instance may run at a time.",
            L"Remote Desktop Host - Already Running",
            MB_OK | MB_ICONWARNING | MB_TOPMOST);
        if (hMutex) ReleaseMutex(hMutex), CloseHandle(hMutex);
        return 1;
    }

    LogInit();
    CheckAndWarnSASRegistry();

    HostConfig cfg;
    std::string settingsError;
    if (!LoadSettings(cfg, settingsError)) {
        std::wstring werr(settingsError.begin(), settingsError.end());
        MessageBoxW(NULL, werr.c_str(),
            L"Remote Desktop Host - Configuration Error",
            MB_OK | MB_ICONERROR | MB_TOPMOST);
        LogShutdown();
        return 1;
    }

    Log("HOST: Config OK — video=" + std::to_string(cfg.video_port)
        + " input=" + std::to_string(cfg.input_port)
        + " audio=" + std::to_string(cfg.audio_port)
        + (cfg.wan_mode ? " mode=WAN" : " mode=LAN")
        + (cfg.startup ? " startup=yes" : " startup=no")
        + (cfg.passphrase.empty() ? " enc=off" : " enc=AES-128-CTR") + "\n");

    if (cfg.startup) HandleStartupRegistration();

    if (!cfg.passphrase.empty()) {
        uint8_t key[16];
        AES128::DeriveKey(cfg.passphrase, key);
        AES128::KeyExpansion(key, g_aes_ctx.rk);
        g_aes_enabled = true;
    }
    else {
        g_aes_enabled = false;
    }

    WSADATA wsa; memset(&wsa, 0, sizeof(wsa));
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        MessageBoxW(NULL, L"WSAStartup failed.",
            L"Remote Desktop Host - Error", MB_OK | MB_ICONERROR);
        LogShutdown(); return 1;
    }
    GdiplusStartupInput gsi;
    GdiplusStartup(&g_gdiplus_token, &gsi, NULL);
    FindJpegClsid(&g_jpeg_clsid);
    EnsureFirewallRules(cfg.video_port, cfg.input_port, cfg.audio_port);

    auto make_listener = [](int port) -> SOCKET {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return INVALID_SOCKET;
        int opt = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
        sockaddr_in addr; memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons((u_short)port);
        if (bind(s, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            closesocket(s); return INVALID_SOCKET;
        }
        listen(s, 1);
        return s;
        };

    const int PORT_HUNT_LIMIT = 20;
    SOCKET vid_listen = INVALID_SOCKET;
    {
        int configured = cfg.video_port;
        for (int attempt = 0; attempt < PORT_HUNT_LIMIT; ++attempt) {
            vid_listen = make_listener(cfg.video_port);
            if (vid_listen != INVALID_SOCKET) break;
            cfg.video_port++;
        }
        if (vid_listen == INVALID_SOCKET) {
            MessageBoxW(NULL,
                L"Could not bind the video port after 20 attempts.\n\n"
                L"All ports in range are in use by other applications.",
                L"Remote Desktop Host \x2014 Network Error",
                MB_OK | MB_ICONERROR | MB_TOPMOST);
            WSACleanup(); LogShutdown(); return 1;
        }
        if (cfg.video_port != configured) {
            wchar_t warn[256];
            swprintf_s(warn,
                L"Video port %d was already in use.\n\n"
                L"The host will listen on port %d instead.\n\n"
                L"Make sure your controller connects to the new port.",
                configured, cfg.video_port);
            MessageBoxW(NULL, warn,
                L"Remote Desktop Host \x2014 Port Changed",
                MB_OK | MB_ICONWARNING | MB_TOPMOST);
            Log("HOST: video_port changed from " + std::to_string(configured)
                + " to " + std::to_string(cfg.video_port) + " (original was in use)\n");
        }
    }

    if (cfg.input_port == cfg.video_port) cfg.input_port = cfg.video_port + 1;

    SOCKET inp_listen = INVALID_SOCKET;
    {
        int configured = cfg.input_port;
        for (int attempt = 0; attempt < PORT_HUNT_LIMIT; ++attempt) {
            if (cfg.input_port == cfg.video_port) { cfg.input_port++; continue; }
            inp_listen = make_listener(cfg.input_port);
            if (inp_listen != INVALID_SOCKET) break;
            cfg.input_port++;
        }
        if (inp_listen == INVALID_SOCKET) {
            closesocket(vid_listen);
            MessageBoxW(NULL,
                L"Could not bind the input port after 20 attempts.\n\n"
                L"All ports in range are in use by other applications.",
                L"Remote Desktop Host \x2014 Network Error",
                MB_OK | MB_ICONERROR | MB_TOPMOST);
            WSACleanup(); LogShutdown(); return 1;
        }
        if (cfg.input_port != configured) {
            wchar_t warn[256];
            swprintf_s(warn,
                L"Input port %d was already in use.\n\n"
                L"The host will listen on port %d instead.\n\n"
                L"Make sure your controller connects to the new port.",
                configured, cfg.input_port);
            MessageBoxW(NULL, warn,
                L"Remote Desktop Host \x2014 Port Changed",
                MB_OK | MB_ICONWARNING | MB_TOPMOST);
            Log("HOST: input_port changed from " + std::to_string(configured)
                + " to " + std::to_string(cfg.input_port) + " (original was in use)\n");
        }
    }

    Log("HOST: Listening on video=" + std::to_string(cfg.video_port)
        + " input=" + std::to_string(cfg.input_port) + "\n");

    if (cfg.wan_mode) {
        UPnPOpenPorts(cfg.video_port, cfg.input_port);
    }
    else {
        Log("HOST: LAN mode — skipping UPnP port forwarding\n");
    }

    g_running = true;
    std::thread t_audio(AudioStreamThread, cfg.audio_port);

    while (g_running) {
        if (!AcceptSession(vid_listen, inp_listen)) continue;

        std::thread t_vid(VideoStreamThread);
        std::thread t_hb(HeartbeatThread);
        std::thread t_inp(InputThread);
        std::thread t_ui(RunStatusWindow);

        t_vid.join(); t_hb.join(); t_inp.join();

        g_session_active = false;
        if (g_status_hwnd) PostMessage(g_status_hwnd, WM_DESTROY, 0, 0);
        t_ui.join();

        if (g_video_sock != INVALID_SOCKET) { closesocket(g_video_sock); g_video_sock = INVALID_SOCKET; }
        if (g_input_sock != INVALID_SOCKET) { closesocket(g_input_sock); g_input_sock = INVALID_SOCKET; }
        g_ctrl_name.clear();
        Log("HOST: Session ended. Waiting for next connection...\n");
    }

    if (cfg.wan_mode) UPnPClosePorts(cfg.video_port, cfg.input_port);
    CoUninitialize();

    if (t_audio.joinable()) t_audio.join();
    closesocket(vid_listen);
    closesocket(inp_listen);
    GdiplusShutdown(g_gdiplus_token);
    WSACleanup();
    Log("HOST: Shut down cleanly\n");
    LogShutdown();
    ReleaseMutex(hMutex);
    CloseHandle(hMutex);
    return 0;
}
