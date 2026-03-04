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
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

static std::deque<std::string> g_log_queue;
static std::mutex              g_log_mutex;
static std::condition_variable g_log_cv;
static std::atomic<bool>       g_log_running(false);
static std::thread             g_log_thread;

static void LogWorker()
{

    std::ofstream logfile("remote_host.log", std::ios::app);

    while (g_log_running.load()) {
        std::deque<std::string> batch;
        {
            std::unique_lock<std::mutex> lk(g_log_mutex);
            g_log_cv.wait_for(lk, std::chrono::milliseconds(100),
                [] { return !g_log_queue.empty() || !g_log_running.load(); });
            batch.swap(g_log_queue);
        }
        for (const auto& msg : batch) {

            if (logfile.is_open())
                logfile << msg;
        }
        if (logfile.is_open())
            logfile.flush();
    }

    for (const auto& msg : g_log_queue) {
        if (logfile.is_open())
            logfile << msg;
    }
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
    if (g_log_thread.joinable())
        g_log_thread.join();
}

static void Log(const std::string& msg)
{
    std::lock_guard<std::mutex> lk(g_log_mutex);
    g_log_queue.push_back(msg);
    g_log_cv.notify_one();
}

static const uint8_t PKT_HANDSHAKE = 0x01;
static const uint8_t PKT_HANDSHAKE_ACK = 0x02;
static const uint8_t PKT_HANDSHAKE_DENY = 0x03;
static const uint8_t PKT_VIDEO_FRAME = 0x04;
static const uint8_t PKT_HEARTBEAT = 0x05;
static const uint8_t PKT_HEARTBEAT_ACK = 0x06;
static const uint8_t PKT_MOUSE_EVENT = 0x10;
static const uint8_t PKT_KEY_EVENT = 0x11;
static const uint8_t PKT_DISCONNECT = 0xFF;
static const int   VIDEO_PORT = 55000;
static const int   INPUT_PORT = 55001;
static const int   FPS_TARGET = 30;
static const ULONG JPEG_QUAL = 50;
static std::atomic<bool> g_running(false);
static std::atomic<bool> g_session_active(false);
static SOCKET      g_video_sock = INVALID_SOCKET;
static SOCKET      g_input_sock = INVALID_SOCKET;
static std::string g_ctrl_name;
static HWND           g_status_hwnd = NULL;
static bool           g_tray_added = false;
static NOTIFYICONDATA g_nid;
static ULONG_PTR g_gdiplus_token = 0;
static CLSID     g_jpeg_clsid;
static bool send_all(SOCKET s, const void* buf, int len)
{
    const char* p = reinterpret_cast<const char*>(buf);
    while (len > 0) {
        int sent = send(s, p, len, 0);
        if (sent == SOCKET_ERROR) return false;
        p += sent;
        len -= sent;
    }
    return true;
}
static bool recv_all(SOCKET s, void* buf, int len)
{
    char* p = reinterpret_cast<char*>(buf);
    while (len > 0) {
        int r = recv(s, p, len, 0);
        if (r <= 0) return false;
        p += r;
        len -= r;
    }
    return true;
}
static bool send_packet(SOCKET s, uint8_t pkt_type,
    const void* data, uint32_t data_len)
{
    uint8_t  hdr[5];
    uint32_t nlen = htonl(data_len);
    hdr[0] = pkt_type;
    memcpy(hdr + 1, &nlen, 4);
    if (!send_all(s, hdr, 5)) return false;
    if (data != NULL && data_len > 0)
        return send_all(s, data, (int)data_len);
    return true;
}
static bool send_packet_empty(SOCKET s, uint8_t pkt_type)
{
    return send_packet(s, pkt_type, NULL, 0);
}
struct Packet {
    uint8_t              type;
    std::vector<uint8_t> data;
};
static bool recv_packet(SOCKET s, Packet& pkt)
{
    uint8_t hdr[5];
    if (!recv_all(s, hdr, 5)) return false;
    uint32_t nlen = 0;
    memcpy(&nlen, hdr + 1, 4);
    uint32_t len = ntohl(nlen);
    pkt.type = hdr[0];
    pkt.data.resize(len);
    if (len > 0 && !recv_all(s, pkt.data.data(), (int)len)) return false;
    return true;
}
static bool FindJpegClsid(CLSID* pClsid)
{
    UINT num = 0, sz = 0;
    GetImageEncodersSize(&num, &sz);
    if (sz == 0) return false;

    std::vector<uint8_t> buf(sz);
    ImageCodecInfo* pInfo = reinterpret_cast<ImageCodecInfo*>(buf.data());
    GetImageEncoders(num, sz, pInfo);

    for (UINT i = 0; i < num; i++) {
        if (wcscmp(pInfo[i].MimeType, L"image/jpeg") == 0) {
            *pClsid = pInfo[i].Clsid;
            return true;
        }
    }
    return false;
}
static std::vector<uint8_t> CaptureScreenJpeg()
{

    HDC hdcScreen = GetDC(NULL);
    int sw = GetDeviceCaps(hdcScreen, DESKTOPHORZRES);
    int sh = GetDeviceCaps(hdcScreen, DESKTOPVERTRES);
    if (sw <= 0) sw = GetSystemMetrics(SM_CXSCREEN);
    if (sh <= 0) sh = GetSystemMetrics(SM_CYSCREEN);
    int vx = 0;
    int vy = 0;

    HDC     hdcMem = CreateCompatibleDC(hdcScreen);
    HBITMAP hbmp = CreateCompatibleBitmap(hdcScreen, sw, sh);
    HGDIOBJ hOld = SelectObject(hdcMem, hbmp);

    BitBlt(hdcMem, 0, 0, sw, sh, hdcScreen, vx, vy, SRCCOPY);

    HFONT hfont = CreateFontW(
        18, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Arial");
    HGDIOBJ hOldFont = SelectObject(hdcMem, hfont);
    SetBkMode(hdcMem, TRANSPARENT);
    SetTextColor(hdcMem, RGB(255, 60, 60));
    TextOutW(hdcMem, 8, 8, L"[REMOTE SESSION ACTIVE]", 23);
    SelectObject(hdcMem, hOldFont);
    DeleteObject(hfont);
    SelectObject(hdcMem, hOld);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    Bitmap bmp(hbmp, NULL);
    EncoderParameters ep;
    memset(&ep, 0, sizeof(ep));
    ep.Count = 1;
    ep.Parameter[0].Guid = EncoderQuality;
    ep.Parameter[0].Type = EncoderParameterValueTypeLong;
    ep.Parameter[0].NumberOfValues = 1;
    ULONG quality = JPEG_QUAL;
    ep.Parameter[0].Value = &quality;
    IStream* pStream = NULL;
    CreateStreamOnHGlobal(NULL, TRUE, &pStream);
    bmp.Save(pStream, &g_jpeg_clsid, &ep);
    STATSTG st;
    memset(&st, 0, sizeof(st));
    pStream->Stat(&st, STATFLAG_NONAME);
    ULONG fileSize = st.cbSize.LowPart;
    std::vector<uint8_t> jpeg(fileSize);
    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    pStream->Seek(zero, STREAM_SEEK_SET, NULL);
    ULONG nRead = 0;
    pStream->Read(jpeg.data(), fileSize, &nRead);
    pStream->Release();
    DeleteObject(hbmp);
    return jpeg;
}

static void VideoStreamThread()
{
    using namespace std::chrono;
    const milliseconds frame_ms(1000 / FPS_TARGET);

    Log("VIDEO: Streaming started\n");

    while (g_running && g_session_active) {
        steady_clock::time_point t0 = steady_clock::now();

        std::vector<uint8_t> jpeg = CaptureScreenJpeg();
        if (!jpeg.empty()) {

            POINT cur = { 0, 0 };
            GetCursorPos(&cur);

            HDC hdcTmpCur = GetDC(NULL);
            int sw = GetDeviceCaps(hdcTmpCur, DESKTOPHORZRES);
            int sh = GetDeviceCaps(hdcTmpCur, DESKTOPVERTRES);
            ReleaseDC(NULL, hdcTmpCur);
            if (sw <= 0) sw = GetSystemMetrics(SM_CXSCREEN);
            if (sh <= 0) sh = GetSystemMetrics(SM_CYSCREEN);

            int nx = (sw > 0) ? (int)(((double)cur.x / sw) * 65535) : 0;
            int ny = (sh > 0) ? (int)(((double)cur.y / sh) * 65535) : 0;
            nx = max(0, min(65535, nx));
            ny = max(0, min(65535, ny));
            uint32_t nnx = htonl((uint32_t)nx);
            uint32_t nny = htonl((uint32_t)ny);

            std::vector<uint8_t> payload(8 + jpeg.size());
            memcpy(payload.data(), &nnx, 4);
            memcpy(payload.data() + 4, &nny, 4);
            memcpy(payload.data() + 8, jpeg.data(), jpeg.size());

            if (!send_packet(g_video_sock, PKT_VIDEO_FRAME,
                payload.data(), (uint32_t)payload.size())) {
                Log("VIDEO: Send failed - connection lost\n");
                break;
            }
        }

        milliseconds elapsed =
            duration_cast<milliseconds>(steady_clock::now() - t0);
        if (elapsed < frame_ms)
            std::this_thread::sleep_for(frame_ms - elapsed);
    }

    Log("VIDEO: Streaming ended\n");
    g_session_active = false;
}

static void HeartbeatThread()
{
    while (g_running && g_session_active) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        if (!g_session_active) break;
        if (!send_packet_empty(g_video_sock, PKT_HEARTBEAT)) break;
    }
}

static void InputThread()
{
    Log("INPUT: Listening for control events\n");

    HDC hdcTmp = GetDC(NULL);
    int phys_w = GetDeviceCaps(hdcTmp, DESKTOPHORZRES);
    int phys_h = GetDeviceCaps(hdcTmp, DESKTOPVERTRES);
    ReleaseDC(NULL, hdcTmp);
    if (phys_w <= 0) phys_w = GetSystemMetrics(SM_CXSCREEN);
    if (phys_h <= 0) phys_h = GetSystemMetrics(SM_CYSCREEN);

    double abs_x = phys_w / 2.0;
    double abs_y = phys_h / 2.0;

    while (g_running && g_session_active) {
        Packet pkt;
        if (!recv_packet(g_input_sock, pkt)) break;

        if (pkt.type == PKT_DISCONNECT) break;

        if (pkt.type == PKT_MOUSE_EVENT && pkt.data.size() >= 12) {

            int16_t  raw_x = 0, raw_y = 0;
            char evt_buf[5] = { 0 };
            char btn_buf[5] = { 0 };
            memcpy(&raw_x, pkt.data.data() + 0, 2);
            memcpy(&raw_y, pkt.data.data() + 2, 2);
            memcpy(evt_buf, pkt.data.data() + 4, 4);
            memcpy(btn_buf, pkt.data.data() + 8, 4);

            raw_x = (int16_t)ntohs(*(uint16_t*)&raw_x);
            raw_y = (int16_t)ntohs(*(uint16_t*)&raw_y);

            std::string evt(evt_buf);
            std::string btn(btn_buf);

            INPUT inp;
            memset(&inp, 0, sizeof(inp));
            inp.type = INPUT_MOUSE;

            if (evt == "rel ") {

                abs_x += (double)raw_x;
                abs_y += (double)raw_y;

                double clamped_x = max(0.0, min((double)(phys_w - 1), abs_x));
                double clamped_y = max(0.0, min((double)(phys_h - 1), abs_y));

                LONG norm_x = (LONG)((clamped_x / phys_w) * 65535.0);
                LONG norm_y = (LONG)((clamped_y / phys_h) * 65535.0);
                inp.mi.dx = norm_x;
                inp.mi.dy = norm_y;
                inp.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;
            }
            else if (evt == "down") {
                inp.mi.dwFlags = 0;

                if (btn.substr(0, 4) == "left") inp.mi.dwFlags |= MOUSEEVENTF_LEFTDOWN;
                else if (btn.substr(0, 4) == "righ") inp.mi.dwFlags |= MOUSEEVENTF_RIGHTDOWN;
                else if (btn.substr(0, 4) == "midd") inp.mi.dwFlags |= MOUSEEVENTF_MIDDLEDOWN;
            }
            else if (evt == "up  ") {
                inp.mi.dwFlags = 0;
                if (btn.substr(0, 4) == "left") inp.mi.dwFlags |= MOUSEEVENTF_LEFTUP;
                else if (btn.substr(0, 4) == "righ") inp.mi.dwFlags |= MOUSEEVENTF_RIGHTUP;
                else if (btn.substr(0, 4) == "midd") inp.mi.dwFlags |= MOUSEEVENTF_MIDDLEUP;
            }
            else if (evt == "scro") {
                inp.mi.dwFlags = MOUSEEVENTF_WHEEL;
                int scroll_dir = 0;
                try { scroll_dir = std::stoi(std::string(btn_buf)); }
                catch (...) { scroll_dir = 1; }
                inp.mi.mouseData = (DWORD)(scroll_dir * WHEEL_DELTA);
            }
            if (inp.mi.dwFlags != 0)
                SendInput(1, &inp, sizeof(INPUT));
        }
        else if (pkt.type == PKT_KEY_EVENT && pkt.data.size() >= 5) {
            uint32_t vk_net = 0;
            uint8_t  pressed = 0;
            memcpy(&vk_net, pkt.data.data(), 4);
            pressed = pkt.data[4];

            WORD vk = (WORD)ntohl(vk_net);

            WORD sc = (WORD)MapVirtualKeyW(vk, MAPVK_VK_TO_VSC);

            static const WORD extended_vks[] = {
                VK_RMENU, VK_RCONTROL, VK_RSHIFT,
                VK_INSERT, VK_DELETE, VK_HOME, VK_END,
                VK_PRIOR, VK_NEXT,
                VK_UP, VK_DOWN, VK_LEFT, VK_RIGHT,
                VK_NUMLOCK, VK_CANCEL,
                VK_SNAPSHOT, VK_DIVIDE,
                VK_LWIN, VK_RWIN, VK_APPS,
            };
            bool is_extended = false;
            for (WORD ev : extended_vks)
                if (vk == ev) { is_extended = true; break; }

            INPUT inp;
            memset(&inp, 0, sizeof(inp));
            inp.type = INPUT_KEYBOARD;
            inp.ki.wVk = vk;
            inp.ki.wScan = sc;
            inp.ki.dwFlags = 0;
            if (!pressed)    inp.ki.dwFlags |= KEYEVENTF_KEYUP;
            if (is_extended) inp.ki.dwFlags |= KEYEVENTF_EXTENDEDKEY;
            SendInput(1, &inp, sizeof(INPUT));
        }
    }

    Log("INPUT: Control thread ended\n");
    g_session_active = false;
}

static bool ShowConsentDialog(const std::string& ctrl_name)
{
    std::wstring wname(ctrl_name.begin(), ctrl_name.end());
    std::wstring msg =
        std::wstring(L"A remote controller is requesting access.\n\n") +
        L"Controller: " + wname + L"\n\n" +
        L"If you allow:\n" +
        L"  - Your screen will be streamed to them\n" +
        L"  - They can control your mouse and keyboard\n" +
        L"  - A red watermark will appear on your screen\n" +
        L"  - You can disconnect by closing the status window\n\n" +
        L"Do you want to allow this connection?";

    int r = MessageBoxW(NULL, msg.c_str(),
        L"Remote Desktop - Access Request",
        MB_YESNO | MB_ICONQUESTION |
        MB_TOPMOST | MB_SETFOREGROUND);
    return (r == IDYES);
}

#define WM_TRAY_ICON   (WM_USER + 1)
#define IDM_DISCONNECT  1001

static LRESULT CALLBACK TrayWndProc(HWND hwnd, UINT msg,
    WPARAM wp, LPARAM lp)
{
    if (msg == WM_TRAY_ICON && (UINT)lp == WM_RBUTTONUP) {
        POINT pt;
        GetCursorPos(&pt);
        HMENU hMenu = CreatePopupMenu();
        AppendMenuW(hMenu, MF_STRING, IDM_DISCONNECT,
            L"Disconnect remote session");
        SetForegroundWindow(hwnd);
        int cmd = TrackPopupMenu(hMenu,
            TPM_RETURNCMD | TPM_NONOTIFY,
            pt.x, pt.y, 0, hwnd, NULL);
        DestroyMenu(hMenu);
        if (cmd == IDM_DISCONNECT) {
            Log("TRAY: User requested disconnect\n");
            g_session_active = false;

        }
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static void AddTrayIcon(HWND hwnd)
{
    memset(&g_nid, 0, sizeof(g_nid));
    g_nid.cbSize = sizeof(NOTIFYICONDATA);
    g_nid.hWnd = hwnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE;
    g_nid.uCallbackMessage = WM_TRAY_ICON;
    g_nid.hIcon = LoadIcon(NULL, IDI_INFORMATION);
    wcscpy_s(g_nid.szTip, _countof(g_nid.szTip),
        L"Remote Desktop - Session Active");
    Shell_NotifyIcon(NIM_ADD, &g_nid);
    g_tray_added = true;
}

static void RemoveTrayIcon()
{
    if (g_tray_added) {
        Shell_NotifyIcon(NIM_DELETE, &g_nid);
        g_tray_added = false;
    }
}

static LRESULT CALLBACK StatusWndProc(HWND hwnd, UINT msg,
    WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;

    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);

        HBRUSH hBg = CreateSolidBrush(RGB(20, 20, 20));
        FillRect(hdc, &rc, hBg);
        DeleteObject(hBg);

        HPEN hPen = CreatePen(PS_SOLID, 1, RGB(80, 80, 80));
        HGDIOBJ hOldPen = SelectObject(hdc, hPen);
        HGDIOBJ hOldBrush = SelectObject(hdc, GetStockObject(NULL_BRUSH));
        RoundRect(hdc, 0, 0, rc.right - 1, rc.bottom - 1, 8, 8);
        SelectObject(hdc, hOldPen);
        SelectObject(hdc, hOldBrush);
        DeleteObject(hPen);

        SetBkMode(hdc, TRANSPARENT);
        HFONT hf = CreateFontW(13, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        HGDIOBJ hOldFont = SelectObject(hdc, hf);

        SetTextColor(hdc, RGB(255, 80, 80));
        RECT r1 = { 10, 8, rc.right - 10, 24 };
        DrawTextW(hdc, L"●  REMOTE SESSION ACTIVE", -1, &r1, DT_LEFT | DT_SINGLELINE);

        SetTextColor(hdc, RGB(180, 180, 180));
        std::wstring ctrlLine = L"    Controller: " +
            std::wstring(g_ctrl_name.begin(), g_ctrl_name.end());
        RECT r2 = { 10, 28, rc.right - 10, 44 };
        DrawTextW(hdc, ctrlLine.c_str(), -1, &r2, DT_LEFT | DT_SINGLELINE);

        SetTextColor(hdc, RGB(100, 100, 100));
        RECT r3 = { 10, 44, rc.right - 10, 58 };
        DrawTextW(hdc, L"    Right-click tray icon to disconnect", -1, &r3, DT_LEFT | DT_SINGLELINE);

        SelectObject(hdc, hOldFont);
        DeleteObject(hf);
        EndPaint(hwnd, &ps);
        return 0;
    }
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static void RunStatusWindow()
{
    HINSTANCE hInst = GetModuleHandle(NULL);

    WNDCLASSW wc;
    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = StatusWndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"RemoteHostStatus";
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    RegisterClassW(&wc);

    DWORD exStyle = WS_EX_TOPMOST | WS_EX_TOOLWINDOW
        | WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE;
    DWORD style = WS_POPUP;

    int winW = 260, winH = 60;
    int scrW = GetSystemMetrics(SM_CXSCREEN);
    int scrH = GetSystemMetrics(SM_CYSCREEN);
    int posX = 10;
    int posY = scrH - winH - 10;

    HWND hwnd = CreateWindowExW(
        exStyle,
        L"RemoteHostStatus",
        L"Remote Desktop - Session Active",
        style,
        posX, posY, winW, winH,
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
        if (!g_session_active) {
            DestroyWindow(hwnd);
            break;
        }
    }

    RemoveTrayIcon();
    g_status_hwnd = NULL;
}

static bool AcceptSession(SOCKET vid_listen, SOCKET inp_listen)
{
    Log("\nHOST: Waiting for controller...\n");

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    int addrlen = sizeof(addr);

    Log("INPUT: Waiting for input channel...\n");
    SOCKET is = accept(inp_listen, (sockaddr*)&addr, &addrlen);
    if (is == INVALID_SOCKET) {
        Log("HOST: Input channel accept failed\n");
        return false;
    }
    Log("INPUT: Input channel accepted\n");

    SOCKET vs = accept(vid_listen, (sockaddr*)&addr, &addrlen);
    if (vs == INVALID_SOCKET) {
        closesocket(is);
        return false;
    }

    char ip[INET_ADDRSTRLEN] = { 0 };
    inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
    Log(std::string("VIDEO: Connection from ") + ip + "\n");

    Packet pkt;
    if (!recv_packet(vs, pkt) || pkt.type != PKT_HANDSHAKE) {
        closesocket(vs);
        closesocket(is);
        return false;
    }

    std::string ctrl_name(pkt.data.begin(), pkt.data.end());
    size_t nul = ctrl_name.find('\0');
    if (nul != std::string::npos) ctrl_name = ctrl_name.substr(0, nul);
    Log("HOST: Handshake received from \"" + ctrl_name + "\"\n");

    if (!ShowConsentDialog(ctrl_name)) {
        const char* deny_msg = "Denied by user";
        send_packet(vs, PKT_HANDSHAKE_DENY,
            deny_msg, (uint32_t)strlen(deny_msg));
        closesocket(vs);
        closesocket(is);
        Log("HOST: User denied the connection\n");
        return false;
    }

    send_packet_empty(vs, PKT_HANDSHAKE_ACK);

    g_video_sock = vs;
    g_input_sock = is;
    g_ctrl_name = ctrl_name;
    g_session_active = true;

    Log("HOST: Session started for \"" + ctrl_name + "\"\n");
    return true;
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
    LogInit();

    int answer = MessageBoxW(
        NULL,
        L"Remote Desktop Host\n\n"
        L"This program will listen for incoming remote desktop connections.\n"
        L"When a controller connects, you will be asked to approve.\n\n"
        L"Your screen will be visible to the approved controller.\n"
        L"A watermark and status window will always be shown.\n\n"
        L"Do you want to start listening for connections?",
        L"Remote Desktop Host - Start",
        MB_YESNO | MB_ICONINFORMATION | MB_TOPMOST);

    if (answer != IDYES) {
        Log("HOST: Cancelled by user\n");
        LogShutdown();
        return 0;
    }

    WSADATA wsa;
    memset(&wsa, 0, sizeof(wsa));
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        Log("WSAStartup failed\n");
        LogShutdown();
        return 1;
    }

    GdiplusStartupInput gsi;
    GdiplusStartup(&g_gdiplus_token, &gsi, NULL);
    FindJpegClsid(&g_jpeg_clsid);

    auto make_listener = [](int port) -> SOCKET {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return INVALID_SOCKET;

        int opt = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
            (const char*)&opt, sizeof(opt));

        sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons((u_short)port);

        if (bind(s, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            closesocket(s);
            return INVALID_SOCKET;
        }
        listen(s, 1);
        return s;
        };

    SOCKET vid_listen = make_listener(VIDEO_PORT);
    SOCKET inp_listen = make_listener(INPUT_PORT);

    if (vid_listen == INVALID_SOCKET || inp_listen == INVALID_SOCKET) {
        Log("HOST: Failed to bind listening sockets. Is another instance already running?\n");
        WSACleanup();
        LogShutdown();
        return 1;
    }

    Log("HOST: Listening on port " + std::to_string(VIDEO_PORT)
        + " (video) and " + std::to_string(INPUT_PORT) + " (input)\n");

    g_running = true;

    while (g_running) {

        if (!AcceptSession(vid_listen, inp_listen))
            continue;

        std::thread t_vid(VideoStreamThread);
        std::thread t_hb(HeartbeatThread);
        std::thread t_inp(InputThread);
        std::thread t_ui(RunStatusWindow);

        t_vid.join();
        t_hb.join();
        t_inp.join();

        g_session_active = false;
        if (g_status_hwnd != NULL) {
            PostMessage(g_status_hwnd, WM_DESTROY, 0, 0);
        }
        t_ui.join();

        if (g_video_sock != INVALID_SOCKET) {
            closesocket(g_video_sock);
            g_video_sock = INVALID_SOCKET;
        }
        if (g_input_sock != INVALID_SOCKET) {
            closesocket(g_input_sock);
            g_input_sock = INVALID_SOCKET;
        }
        g_session_active = false;
        g_ctrl_name.clear();

        Log("HOST: Session ended. Waiting for next connection...\n");

    }

    closesocket(vid_listen);
    closesocket(inp_listen);
    GdiplusShutdown(g_gdiplus_token);
    WSACleanup();

    Log("HOST: Shut down cleanly\n");
    LogShutdown();
    return 0;
}