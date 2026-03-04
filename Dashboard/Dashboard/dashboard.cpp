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

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "msimg32.lib")
#pragma comment(lib, "ole32.lib")

static constexpr uint8_t PKT_HANDSHAKE = 0x01;
static constexpr uint8_t PKT_HANDSHAKE_ACK = 0x02;
static constexpr uint8_t PKT_HANDSHAKE_DENY = 0x03;
static constexpr uint8_t PKT_VIDEO_FRAME = 0x04;
static constexpr uint8_t PKT_HEARTBEAT = 0x05;
static constexpr uint8_t PKT_HEARTBEAT_ACK = 0x06;
static constexpr uint8_t PKT_MOUSE_EVENT = 0x10;
static constexpr uint8_t PKT_KEY_EVENT = 0x11;
static constexpr uint8_t PKT_DISCONNECT = 0xFF;

static constexpr int VIDEO_PORT = 55000;
static constexpr int INPUT_PORT = 55001;

static constexpr int ID_BTN_CONNECT = 101;
static constexpr int ID_BTN_DISCONNECT = 102;
static constexpr int ID_BTN_DEBUG = 103;
static constexpr int ID_EDIT_IP = 104;
static constexpr int ID_EDIT_NAME = 105;
static constexpr UINT WM_APP_STATUS = WM_APP + 1;
static constexpr UINT WM_APP_FRAME = WM_APP + 2;
static constexpr UINT WM_APP_DISCONN = WM_APP + 3;
static constexpr UINT WM_APP_CONNECTED = WM_APP + 4;
static constexpr UINT WM_APP_SHOW_SESSION = WM_APP + 5;

static constexpr UINT WM_APP_SHOW_CONNECT = WM_APP + 6;

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
            addr.sin_port = htons(INPUT_PORT);
            inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

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
        send_packet(sock, PKT_MOUSE_EVENT, payload, 12);
    }

    void send_key(uint32_t vk, bool pressed)
    {
        if (!running || sock == INVALID_SOCKET) return;
        uint8_t payload[5];
        uint32_t nvk = hton32(vk);
        memcpy(payload, &nvk, 4);
        payload[4] = pressed ? 1 : 0;
        send_packet(sock, PKT_KEY_EVENT, payload, 5);
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

    std::thread recv_thread;

    explicit VideoConnection(const std::string& h, const std::string& name)
        : host(h), controller_name(name) {
    }

    std::pair<bool, std::string> connect_video()
    {
        SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return { false,"socket() failed" };

        DWORD tv = 10000;

        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(VIDEO_PORT);
        inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

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
        while (running) {
            uint8_t ptype; std::vector<uint8_t> pdata;
            if (!recv_packet(sock, ptype, pdata)) break;

            if (ptype == PKT_VIDEO_FRAME && pdata.size() > 8) {
                uint32_t cx_n, cy_n;
                memcpy(&cx_n, pdata.data() + 0, 4); cx_n = ntoh32(cx_n);
                memcpy(&cy_n, pdata.data() + 4, 4); cy_n = ntoh32(cy_n);
                PendingFrame pf;
                pf.jpeg.assign(pdata.begin() + 8, pdata.end());
                pf.cx_n = cx_n;
                pf.cy_n = cy_n;
                if (frame_callback) frame_callback(std::move(pf));
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

    std::unique_ptr<VideoConnection> video_conn;
    std::unique_ptr<InputConnection> input_conn;

    std::mutex   frame_mutex;
    std::unique_ptr<PendingFrame> pending_frame;
    std::atomic<bool> frame_scheduled{ false };

    HBITMAP hFrameBmp = NULL;
    int     frameSrcW = 0, frameSrcH = 0;
    double  cursorRatX = 0, cursorRatY = 0;
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
        case ID_BTN_CONNECT:    on_connect();       break;
        case ID_BTN_DISCONNECT: on_disconnect_btn(); break;
        case ID_BTN_DEBUG:      toggle_debug();      break;
        }
        return 0;

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

    case WM_APP_CONNECTED:

        ShowWindow(hConnectWnd, SW_HIDE);
        create_session_window();

        hwnd = hSessionWnd;
        return 0;

    case WM_SIZE: {
        RECT rc; GetClientRect(h, &rc);
        int W = rc.right, H = rc.bottom;
        if (h == hSessionWnd && hCanvas && hStatusBar) {

            int barH = 36, sbH = 22;
            SetWindowPos(hStatusBar, NULL, 0, H - sbH, W, sbH, SWP_NOZORDER);
            SetWindowPos(hCanvas, NULL, 0, barH, W, std::max(1, H - barH - sbH), SWP_NOZORDER);
            MoveWindow(hBtnDisconn, 5, 5, 95, 26, TRUE);
            MoveWindow(hBtnDebug, 106, 5, 90, 26, TRUE);
            if (hLockLabel) MoveWindow(hLockLabel, 205, 9, W - 210, 18, TRUE);
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

    //
    // Register classes
    //
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

    //
    // Desired CLIENT size (no status bar anymore)
    //
    int clientW = 360;
    int clientH = 170;

    DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU;
    DWORD exStyle = 0;

    RECT rc = { 0, 0, clientW, clientH };
    AdjustWindowRectEx(&rc, style, FALSE, exStyle);

    int winW = rc.right - rc.left;
    int winH = rc.bottom - rc.top;

    int scrW = GetSystemMetrics(SM_CXSCREEN);
    int scrH = GetSystemMetrics(SM_CYSCREEN);

    int posX = (scrW - winW) / 2;
    int posY = (scrH - winH) / 2;

    //
    // Create main connect window
    //
    hConnectWnd = CreateWindowExW(
        exStyle,
        L"RDConnectCls",
        L"Remote Desktop Controller",
        style | WS_VISIBLE,
        posX, posY,
        winW, winH,
        NULL, NULL, hInst, NULL);

    if (!hConnectWnd)
        return false;

    hwnd = hConnectWnd;

    //
    // Helper lambdas
    //
    auto lbl = [&](const wchar_t* text, int x, int y, int w, int h)
        {
            HWND hw = CreateWindowW(
                L"STATIC", text,
                WS_CHILD | WS_VISIBLE | SS_LEFT,
                x, y, w, h,
                hConnectWnd, NULL, hInst, NULL);

            SendMessage(hw, WM_SETFONT, (WPARAM)hFont, TRUE);
            return hw;
        };

    auto edt = [&](const wchar_t* def, int id, int x, int y, int w, int h)
        {
            HWND hw = CreateWindowW(
                L"EDIT", def,
                WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                x, y, w, h,
                hConnectWnd, (HMENU)(INT_PTR)id, hInst, NULL);

            SendMessage(hw, WM_SETFONT, (WPARAM)hFont, TRUE);
            return hw;
        };

    auto btn = [&](const wchar_t* text, int id, int x, int y, int w, int h)
        {
            HWND hw = CreateWindowW(
                L"BUTTON", text,
                WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                x, y, w, h,
                hConnectWnd, (HMENU)(INT_PTR)id, hInst, NULL);

            SendMessage(hw, WM_SETFONT, (WPARAM)hFont, TRUE);
            return hw;
        };

    //
    // Layout (clean spacing)
    //
    int leftLabelX = 20;
    int editX = 100;
    int editW = 220;

    lbl(L"Host IP:", leftLabelX, 22, 70, 18);
    hEditIP = edt(L"192.168.1.5", ID_EDIT_IP, editX, 20, editW, 22);

    lbl(L"Your name:", leftLabelX, 55, 70, 18);
    hEditName = edt(L"Controller", ID_EDIT_NAME, editX, 53, editW, 22);

    hChkDebug = CreateWindowW(
        L"BUTTON", L"Show debug panel on connect",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        editX, 85, 220, 20,
        hConnectWnd, (HMENU)(INT_PTR)ID_BTN_DEBUG, hInst, NULL);

    SendMessage(hChkDebug, WM_SETFONT, (WPARAM)hFont, TRUE);

    //
    // Centered Connect button
    //
    int btnW = 190;
    int btnH = 30;
    int btnX = (clientW - btnW) / 2;

    hBtnConnect = btn(
        L"Connect to Desktop",
        ID_BTN_CONNECT,
        btnX,
        115,
        btnW,
        btnH);

    //
    // Remote cursor bitmap
    //
    hCursorBmp = make_remote_cursor_bmp(CURSOR_SIZE);

    return true;
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
    hBtnDebug = btn(L"Debug (F12)", ID_BTN_DEBUG, 106, 5, 90, 26);
    hLockLabel = lbl(L"Click inside stream to lock cursor  |  ESC to unlock",
        205, 9, 500, 18);

    hCanvas = CreateWindowExW(0, L"RDCanvasCls", NULL,
        WS_CHILD | WS_VISIBLE,
        0, 36, scrW / 2, scrH / 2 - 36 - 22, hSessionWnd, NULL, hInst, NULL);

    hStatusBar = CreateWindowW(L"STATIC", L"Connected",
        WS_CHILD | WS_VISIBLE | SS_LEFT | SS_SUNKEN,
        0, scrH / 2 - 22, scrW / 2, 22, hSessionWnd, NULL, hInst, NULL);
    SendMessage(hStatusBar, WM_SETFONT, (WPARAM)hFont, TRUE);

    if (SendMessage(hChkDebug, BM_GETCHECK, 0, 0) == BST_CHECKED)
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

    wchar_t ip_buf[64] = {}, name_buf[64] = {};
    GetWindowTextW(hEditIP, ip_buf, 64);
    GetWindowTextW(hEditName, name_buf, 64);

    std::wstring wip(ip_buf), wname(name_buf);
    std::string  host(wip.begin(), wip.end());
    std::string  name = wname.empty() ? "Controller"
        : std::string(wname.begin(), wname.end());
    if (host.empty()) {
        MessageBoxW(hConnectWnd, L"Please enter the host IP address.", L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    set_status("Connecting...");
    EnableWindow(hBtnConnect, FALSE);

    HWND postTarget = hConnectWnd;

    std::thread([this, host, name, postTarget]() {

        auto* hstat = new std::string("Connecting input channel...");
        PostMessage(postTarget, WM_APP_STATUS, 0, (LPARAM)hstat);

        auto ic = std::make_unique<InputConnection>(host);
        if (!ic->connect()) {
            PostMessage(postTarget, WM_APP_STATUS, 0,
                (LPARAM)new std::string("Failed: could not connect input channel"));
            PostMessage(postTarget, WM_APP_DISCONN, 0, 0);
            return;
        }

        PostMessage(postTarget, WM_APP_STATUS, 0,
            (LPARAM)new std::string("Waiting for host approval..."));

        auto vc = std::make_unique<VideoConnection>(host, name);

        vc->frame_callback = [this](PendingFrame pf) {

            HWND fw = hSessionWnd ? hSessionWnd : hConnectWnd;
            on_frame(std::move(pf));
            (void)fw;
            };
        vc->status_callback = [this, postTarget](std::string msg) {
            HWND target = hSessionWnd ? hSessionWnd : postTarget;
            PostMessage(target, WM_APP_STATUS, 0,
                (LPARAM)new std::string(msg));
            };

        auto [ok, msg] = vc->connect_video();
        if (!ok) {
            ic->disconnect();
            PostMessage(postTarget, WM_APP_STATUS, 0,
                (LPARAM)new std::string("Failed: " + msg));
            PostMessage(postTarget, WM_APP_DISCONN, 0, 0);
            return;
        }

        video_conn = std::move(vc);
        input_conn = std::move(ic);

        PostMessage(postTarget, WM_APP_CONNECTED, 0, 0);
        }).detach();
}

void ControllerApp::on_disconnected()
{
    unlock_cursor();
    destroy_session_window();

    ShowWindow(hConnectWnd, SW_SHOW);
    SetForegroundWindow(hConnectWnd);
    hwnd = hConnectWnd;

    set_status("Disconnected — ready to reconnect");
    EnableWindow(hBtnConnect, TRUE);
}

void ControllerApp::destroy_session_window()
{
    if (!hSessionWnd) return;

    if (debugVisible) toggle_debug();

    if (video_conn) { video_conn->disconnect(); video_conn.reset(); }
    if (input_conn) { input_conn->disconnect(); input_conn.reset(); }
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
    cursorRatX = pf->cx_n / 65535.0;
    cursorRatY = pf->cy_n / 65535.0;

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
        int cx = (int)(cursorRatX * cw);
        int cy = (int)(cursorRatY * ch);

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

    ShowCursor(FALSE);

    start_listeners();
}

void ControllerApp::unlock_cursor()
{
    if (!cursor_locked) return;
    cursor_locked = false;
    SetWindowTextW(hLockLabel,
        L"Click inside stream to lock cursor  |  ESC to unlock");
    ShowCursor(TRUE);
    stop_listeners();
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

        if (pressed || released) {
            DWORD vk = ks->vkCode;

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
    raw_hwnd = NULL;
    if (rh) PostMessageW(rh, WM_QUIT, 0, 0);
    if (raw_thread.joinable()) raw_thread.join();
}

void ControllerApp::raw_input_loop()
{
    const wchar_t* CLS = L"RawInputSink_RC";

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = RawInputWndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLS;
    RegisterClassExW(&wc);

    HWND hw = CreateWindowExW(0, CLS, NULL, 0,
        0, 0, 0, 0, HWND_MESSAGE, NULL, hInstance, NULL);
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

static HWND hDebugLabels[14] = {};
static HWND hDebugVals[14] = {};
static constexpr int DBG_ROWS = 13;

static const wchar_t* DBG_NAMES[] = {
    L"Cursor locked", L"Warp count", L"Raw events total", L"Mouse pkts sent",
    L"Last dx/dy",    L"Stream FPS",   L"Frames rendered",  L"Pin centre (px)",
    L"Lock rect",     L"Video conn",   L"Input conn",       L"Raw HWND",
    L"Raw thread alive"
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
                WS_CHILD | WS_VISIBLE | SS_LEFT, 5, y, 160, 16, hWnd, NULL, NULL, NULL);
            SendMessage(hDebugLabels[i], WM_SETFONT, (WPARAM)hf, TRUE);
            hDebugVals[i] = CreateWindowW(L"STATIC", L"—",
                WS_CHILD | WS_VISIBLE | SS_LEFT, 170, y, 220, 16, hWnd, NULL, NULL, NULL);
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
            50, 50, 410, 30 + DBG_ROWS * 18 + 40, NULL, NULL, hInstance, NULL);

        HWND hTitle = CreateWindowW(L"STATIC", L" CONTROLLER DEBUG ",
            WS_CHILD | WS_VISIBLE | SS_CENTER,
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

    if (debugVisible)
        SetTimer(hDebugWin, 1, 200, [](HWND, UINT, UINT_PTR, DWORD) {
        if (g_app) g_app->update_debug();
            });
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