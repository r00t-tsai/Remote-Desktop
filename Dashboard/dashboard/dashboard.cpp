#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windowsx.h>
#include <shellapi.h>
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
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "core\\core.lib")
#include "core\\core.h"

static const wchar_t* PROP_PAGE = L"SRDT_Page";
static constexpr ULONG_PTR TAG_DASHBOARD = 1;
static constexpr ULONG_PTR TAG_RC = 2;
static constexpr ULONG_PTR TAG_HOST = 3;

static void TagWindow(HWND hw, ULONG_PTR tag)
{
    if (hw) SetPropW(hw, PROP_PAGE, (HANDLE)tag);
}

static constexpr int ID_DASH_BTN_RC = 1001;
static constexpr int ID_DASH_BTN_HOST = 1002;
static constexpr int ID_RC_BTN_CONNECT = 101;
static constexpr int ID_RC_BTN_BACK = 114;
static constexpr int ID_RC_EDIT_IP = 104;
static constexpr int ID_RC_EDIT_NAME = 105;
static constexpr int ID_RC_EDIT_VPORT = 106;
static constexpr int ID_RC_EDIT_IPORT = 107;
static constexpr int ID_RC_EDIT_APORT = 120;
static constexpr int ID_RC_EDIT_PASS = 108;
static constexpr int ID_RC_CHK_INTERNET = 109;
static constexpr int ID_RC_CHK_DEBUG = 110;
static constexpr int ID_RC_CHK_STARTUP = 112;
static constexpr int ID_RC_EDIT_IP_GHOST = 113;
static constexpr int ID_HOST_EDIT_VPORT = 301;
static constexpr int ID_HOST_EDIT_IPORT = 302;
static constexpr int ID_HOST_EDIT_APORT = 303;
static constexpr int ID_HOST_EDIT_PASS = 304;
static constexpr int ID_HOST_CHK_INTERNET = 305;
static constexpr int ID_HOST_BTN_START = 306;
static constexpr int ID_HOST_BTN_BACK = 307;
static constexpr int ID_BTN_DISCONNECT = 102;
static constexpr int ID_BTN_DEBUG = 103;
static constexpr int ID_BTN_VOLUME = 121;
static constexpr int ID_OVERLAY_CANCEL = 200;
static constexpr int ID_OVERLAY_TIMER = 1;
static constexpr int ID_OVERLAY_LATE_TIMER = 2;
static constexpr UINT WM_APP_STATUS = WM_APP + 1;
static constexpr UINT WM_APP_FRAME = WM_APP + 2;
static constexpr UINT WM_APP_DISCONN = WM_APP + 3;
static constexpr UINT WM_APP_CONNECTED = WM_APP + 4;
static constexpr UINT WM_APP_CONN_CANCEL = WM_APP + 7;
static constexpr UINT WM_TRAY_ICON = WM_APP + 20;
static constexpr UINT TRAY_ID = 1;
static constexpr int  ID_TRAY_DISCONNECT = 401;
static constexpr int  ID_CONFIRM_YES = 402;
static constexpr int  ID_CONFIRM_NO = 403;
static constexpr UINT WM_APP_TRAY_DISCONNECT = WM_APP + 21;

enum class Page { Dashboard, RC, Host };
class ControllerApp {
public:
    HWND hWnd = NULL;

    HWND hDashTitle = NULL;
    HWND hDashSub = NULL;
    HWND hDashBtnRC = NULL;
    HWND hDashBtnHost = NULL;

    HWND hRcEditIP = NULL;
    HWND hRcIpGhost = NULL;
    HWND hRcEditName = NULL;
    HWND hRcEditVport = NULL;
    HWND hRcEditIport = NULL;
    HWND hRcEditAport = NULL;
    HWND hRcEditPass = NULL;
    HWND hRcChkInet = NULL;
    HWND hRcChkDebug = NULL;
    HWND hRcChkStartup = NULL;
    HWND hRcBtnConnect = NULL;
    HWND hRcBtnBack = NULL;

    HWND hHostEditVport = NULL;
    HWND hHostEditIport = NULL;
    HWND hHostEditAport = NULL;
    HWND hHostEditPass = NULL;
    HWND hHostChkInet = NULL;
    HWND hHostBtnStart = NULL;
    HWND hHostBtnBack = NULL;

    HWND hSessionWnd = NULL;
    HWND hCanvas = NULL;
    HWND hBtnDisconn = NULL;
    HWND hBtnDebug = NULL;
    HWND hBtnVolume = NULL;
    HWND hStatusBar = NULL;
    HWND hLockLabel = NULL;

    HWND hDebugWin = NULL;
    bool debugVisible = false;

    HWND hLoadingWnd = NULL;
    HWND hLoadingLabel = NULL;
    HWND hLoadingLate = NULL;
    HWND hLoadingCancel = NULL;
    int  spinAngle = 0;
    std::atomic<bool> connectCancelled{ false };

    int volumePct = 100;

    std::unique_ptr<VideoConnection> video_conn;
    std::unique_ptr<InputConnection> input_conn;
    std::thread audio_thread;

    std::mutex   frame_mutex;
    std::unique_ptr<PendingFrame> pending_frame;
    std::atomic<bool> frame_scheduled{ false };
    HBITMAP hFrameBmp = NULL;
    int  frameSrcW = 0, frameSrcH = 0;
    double cursorRatX = 0, cursorRatY = 0;
    double vCursorX = 0.5, vCursorY = 0.5;
    bool firstFrame = true;
    HBITMAP hCursorBmp = NULL;
    static constexpr int CURSOR_SIZE = 24;

    bool  cursor_locked = false;
    int   pin_cx = 0, pin_cy = 0;
    HWND  raw_hwnd = NULL;
    std::thread raw_thread;
    std::atomic<bool> raw_running{ false };
    std::atomic<int>  warp_pending{ 0 };
    HHOOK kb_hook = NULL;

    std::atomic<long> dbg_raw_events{ 0 };
    std::atomic<long> dbg_pkts_sent{ 0 };
    std::atomic<long> dbg_frames{ 0 };
    std::atomic<int>  dbg_last_dx{ 0 };
    std::atomic<int>  dbg_last_dy{ 0 };
    double dbg_fps = 0.0, dbg_fps_time = 0.0;
    long   dbg_frame_tick = 0;
    static constexpr double MOUSE_SPEED = 1.0;

    PROCESS_INFORMATION hostProc{};
    bool hostRunning = false;

    NOTIFYICONDATAW trayNID{};
    bool trayVisible = false;

    HWND hGrayOverlay = NULL;
    void show_gray_overlay();
    void hide_gray_overlay();
    void show_disconnect_confirm();

    Page currentPage = Page::Dashboard;

    HFONT hfTitle = NULL;
    HFONT hfBold = NULL;
    HFONT hfNormal = NULL;
    HFONT hfItalic = NULL;

    bool init(HINSTANCE hInst);
    void run();
    void destroy();

    void switch_page(Page p);

    void show_loading_overlay();
    void hide_loading_overlay();
    void cancel_connect();
    void tick_spinner();
    void show_late_label();
    void show_volume_menu();
    void set_volume_level(int cmd);

    void on_connect();
    void on_disconnected();
    void on_disconnect_btn();
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
    void update_ip_ghost();

    void on_start_host();
    void stop_host();
    void add_tray_icon();
    void remove_tray_icon();
    void show_tray_menu();
    void show_tray_balloon();

    LRESULT handle_message(HWND, UINT, WPARAM, LPARAM);
    static LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
    LRESULT CALLBACK CanvasProc(HWND, UINT, WPARAM, LPARAM);

private:
    HINSTANCE hInst = NULL;
    bool show_consent_dialog();
    void build_dashboard_page();
    void build_rc_page();
    void build_host_page();
};

static ControllerApp* g_app = nullptr;

static bool g_consent_result = false;

static LRESULT CALLBACK ConsentProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        HFONT hf = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

        LOGFONT lf{};
        GetObject(hf, sizeof(lf), &lf);
        lf.lfWeight = FW_BOLD;
        HFONT hBold = CreateFontIndirect(&lf);

        RECT rc;
        GetClientRect(hw, &rc);

        int W = rc.right;

        HWND hIcon = CreateWindowW(
            L"STATIC",
            NULL,
            WS_CHILD | WS_VISIBLE | SS_ICON,
            20, 20, 32, 32,
            hw, NULL, NULL, NULL);

        SendMessage(hIcon, STM_SETICON,
            (WPARAM)LoadIcon(NULL, IDI_WARNING), 0);

        HWND hTitle = CreateWindowW(
            L"STATIC",
            L"NOTICE",
            WS_CHILD | WS_VISIBLE,
            70, 20, W - 90, 20,
            hw, NULL, NULL, NULL);

        SendMessage(hTitle, WM_SETFONT, (WPARAM)hBold, TRUE);

        HWND hText = CreateWindowW(
            L"STATIC",
            L"This tool allows viewing and controlling a remote computer.\r\n\r\n"
            L"You must have explicit permission from the owner before connecting.\r\n"
            L"Unauthorized access to computer systems may be illegal.",
            WS_CHILD | WS_VISIBLE,
            70, 45, W - 90, 70,
            hw, NULL, NULL, NULL);

        SendMessage(hText, WM_SETFONT, (WPARAM)hf, TRUE);

        CreateWindowW(
            L"STATIC", L"",
            WS_CHILD | WS_VISIBLE | SS_ETCHEDHORZ,
            20, 120, W - 40, 2,
            hw, NULL, NULL, NULL);

        int btnW = 260;
        int btnH = 32;
        int btnY = 140;

        int btnX = (W - btnW) / 2;

        HWND hOK = CreateWindowW(
            L"BUTTON",
            L"I understand and wish to proceed",
            WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
            btnX, btnY,
            btnW, btnH,
            hw, (HMENU)IDOK, NULL, NULL);

        SendMessage(hOK, WM_SETFONT, (WPARAM)hf, TRUE);

        return 0;
    }

    case WM_COMMAND:
        g_consent_result = (LOWORD(wp) == IDOK);
        DestroyWindow(hw);
        return 0;

    case WM_CLOSE:
        g_consent_result = false;
        DestroyWindow(hw);
        return 0;
    }

    return DefWindowProcW(hw, msg, wp, lp);
}

bool ControllerApp::show_consent_dialog()
{
    const wchar_t* CLS = L"SRDT_ConsentCls";
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc); wc.lpfnWndProc = ConsentProc;
    wc.hInstance = hInst; wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW); wc.lpszClassName = CLS;
    RegisterClassExW(&wc);

    g_consent_result = false;
    const int W = 420;
    const int H = 200;
    RECT adj = { 0,0,W,H };
    DWORD s = WS_POPUP | WS_CAPTION | WS_SYSMENU, ex = WS_EX_DLGMODALFRAME | WS_EX_TOPMOST;
    AdjustWindowRectEx(&adj, s, FALSE, ex);
    RECT wr; GetWindowRect(hWnd, &wr);
    int dW = adj.right - adj.left, dH = adj.bottom - adj.top;
    int dX = (wr.left + wr.right) / 2 - dW / 2, dY = (wr.top + wr.bottom) / 2 - dH / 2;
    HWND hDlg = CreateWindowExW(ex, CLS, L"Notice Window", s,
        dX, dY, dW, dH, hWnd, NULL, hInst, NULL);
    ShowWindow(hDlg, SW_SHOW); UpdateWindow(hDlg);
    EnableWindow(hWnd, FALSE);
    MSG m;
    while (IsWindow(hDlg) && GetMessageW(&m, NULL, 0, 0) > 0) {
        TranslateMessage(&m); DispatchMessageW(&m);
    }
    EnableWindow(hWnd, TRUE);
    SetForegroundWindow(hWnd);
    UnregisterClassW(CLS, hInst);
    return g_consent_result;
}

static LRESULT CALLBACK CanvasProcStatic(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    return g_app ? g_app->CanvasProc(h, msg, wp, lp) : DefWindowProcW(h, msg, wp, lp);
}

LRESULT ControllerApp::CanvasProc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_LBUTTONDOWN:
        if (video_conn && video_conn->running && !cursor_locked) lock_cursor();
        return 0;
    case WM_PAINT: {
        PAINTSTRUCT ps; HDC hdc = BeginPaint(h, &ps);
        on_paint_canvas(hdc); EndPaint(h, &ps);
        return 0;
    }
    case WM_ERASEBKGND: return 1;
    }
    return DefWindowProcW(h, msg, wp, lp);
}
LRESULT CALLBACK ControllerApp::WndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    return g_app ? g_app->handle_message(h, msg, wp, lp) : DefWindowProcW(h, msg, wp, lp);
}

LRESULT ControllerApp::handle_message(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {

    case WM_TRAY_ICON:
        if (lp == WM_RBUTTONUP || lp == WM_LBUTTONUP) show_tray_menu();
        return 0;

    case WM_APP_TRAY_DISCONNECT:

        ShowWindow(hWnd, SW_SHOW);
        ShowWindow(hWnd, SW_RESTORE);
        SetForegroundWindow(hWnd);
        show_gray_overlay();
        show_disconnect_confirm();
        return 0;

    case WM_COMMAND: {
        int id = LOWORD(wp);
        switch (id) {

        case ID_DASH_BTN_RC:   switch_page(Page::RC);   break;
        case ID_DASH_BTN_HOST: switch_page(Page::Host); break;

        case ID_RC_BTN_CONNECT: on_connect();            break;
        case ID_RC_BTN_BACK:    switch_page(Page::Dashboard); break;
        case ID_RC_CHK_INTERNET:
        case ID_RC_EDIT_IP:
            if (HIWORD(wp) == EN_CHANGE || id == ID_RC_CHK_INTERNET)
                update_ip_ghost();
            break;

        case ID_HOST_BTN_START: on_start_host(); break;
        case ID_HOST_BTN_BACK:  switch_page(Page::Dashboard); break;

        case ID_BTN_DISCONNECT: on_disconnect_btn(); break;
        case ID_BTN_DEBUG:      toggle_debug();      break;
        case ID_BTN_VOLUME:     show_volume_menu();  break;

        case 501: case 502: case 503: case 504: case 505: case 506:
            set_volume_level(id); break;

        case ID_OVERLAY_CANCEL: cancel_connect(); break;

        case ID_CONFIRM_YES: stop_host();  break;
        case ID_CONFIRM_NO:
            hide_gray_overlay();
            ShowWindow(hWnd, SW_HIDE);

            show_tray_balloon();

            break;
        }
        return 0;
    }

    case WM_APP_CONN_CANCEL:
        hide_loading_overlay();
        if (hRcBtnConnect) EnableWindow(hRcBtnConnect, TRUE);
        return 0;

    case WM_TIMER:
        if (wp == ID_OVERLAY_TIMER) { tick_spinner(); return 0; }
        if (wp == ID_OVERLAY_LATE_TIMER) { KillTimer(h, ID_OVERLAY_LATE_TIMER); show_late_label(); return 0; }
        break;

    case WM_KEYDOWN: case WM_SYSKEYDOWN:
        if (wp == VK_ESCAPE) { unlock_cursor(); return 0; }
        if (wp == VK_F12) { toggle_debug();  return 0; }
        return 0;
    case WM_KEYUP: case WM_SYSKEYUP: return 0;

    case WM_APP_STATUS: {
        auto* s = reinterpret_cast<std::string*>(lp);
        set_status(*s);
        bool disc = s->find("disconnect") != std::string::npos ||
            s->find("Disconnect") != std::string::npos;
        delete s;
        if (disc) on_disconnected();
        return 0;
    }
    case WM_APP_FRAME:   render_frame();   return 0;
    case WM_APP_DISCONN: on_disconnected(); return 0;

    case WM_APP_CONNECTED: {
        SOCKET aud = (SOCKET)wp;
        hide_loading_overlay();
        create_session_window();
        if (aud != INVALID_SOCKET) {
            if (Core_AudioStopEvtValid()) Core_AudioStopEvtClose();
            Core_AudioStopEvtCreate();
            if (audio_thread.joinable()) audio_thread.join();
            audio_thread = std::thread(AudioPlaybackThread, aud);
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

    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN: {

        HDC hdc = (HDC)wp;
        SetBkMode(hdc, TRANSPARENT);
        return (LRESULT)GetStockObject(WHITE_BRUSH);
    }

    case WM_ERASEBKGND: {
        if (h == hWnd) {
            HDC hdc = (HDC)wp;
            RECT rc; GetClientRect(h, &rc);
            FillRect(hdc, &rc, (HBRUSH)GetStockObject(WHITE_BRUSH));
            return 1;
        }
        break;
    }

    case WM_CLOSE:   on_close();       return 0;
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

void ControllerApp::switch_page(Page p)
{
    currentPage = p;

    ULONG_PTR showTag = (p == Page::Dashboard) ? TAG_DASHBOARD :
        (p == Page::RC) ? TAG_RC : TAG_HOST;

    struct EnumData { ULONG_PTR showTag; };
    EnumData ed{ showTag };

    EnumChildWindows(hWnd, [](HWND child, LPARAM lp) -> BOOL {
        EnumData* ed = reinterpret_cast<EnumData*>(lp);
        ULONG_PTR tag = (ULONG_PTR)GetPropW(child, PROP_PAGE);
        if (tag != 0) {

            ShowWindow(child, tag == ed->showTag ? SW_SHOW : SW_HIDE);
        }
        return TRUE;
        }, (LPARAM)&ed);

    InvalidateRect(hWnd, NULL, TRUE);
    UpdateWindow(hWnd);

    switch (p) {
    case Page::Dashboard: SetWindowTextW(hWnd, L"Simple Remote Desktop v1.1.3"); break;
    case Page::RC:        SetWindowTextW(hWnd, L"Connect to Device");     break;
    case Page::Host:      SetWindowTextW(hWnd, L"Host RDP Connection");       break;
    }

    SetForegroundWindow(hWnd);
}

bool ControllerApp::init(HINSTANCE hi)
{
    hInst = hi;
    g_app = this;

    HDC hScreenDC = GetDC(NULL);
    int dpi = GetDeviceCaps(hScreenDC, LOGPIXELSY);
    ReleaseDC(NULL, hScreenDC);

    hfNormal = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

    hfBold = CreateFontW(-MulDiv(10, dpi, 72), 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    if (!hfBold) hfBold = hfNormal;

    hfTitle = CreateFontW(-MulDiv(20, dpi, 72), 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    if (!hfTitle) hfTitle = hfBold;

    hfItalic = CreateFontW(-MulDiv(8, dpi, 72), 0, 0, 0, FW_NORMAL, TRUE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    if (!hfItalic) hfItalic = hfNormal;

    {
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc); wc.lpfnWndProc = CanvasProcStatic;
        wc.hInstance = hi; wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
        wc.lpszClassName = L"RDCanvasCls"; RegisterClassExW(&wc);
    }
    {
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc); wc.lpfnWndProc = WndProc;
        wc.hInstance = hi; wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.lpszClassName = L"RDSessionCls"; RegisterClassExW(&wc);
    }

    {
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc); wc.lpfnWndProc = WndProc;
        wc.hInstance = hi; wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.lpszClassName = L"RDMainCls"; RegisterClassExW(&wc);
    }

    const int CW = 420, CH = 480;
    DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
    RECT adj = { 0,0,CW,CH };
    AdjustWindowRectEx(&adj, style, FALSE, 0);
    int winW = adj.right - adj.left, winH = adj.bottom - adj.top;
    int scrW = GetSystemMetrics(SM_CXSCREEN), scrH = GetSystemMetrics(SM_CYSCREEN);

    hWnd = CreateWindowExW(0, L"RDMainCls", L"Simple Remote Desktop",
        style | WS_VISIBLE,
        (scrW - winW) / 2, (scrH - winH) / 2, winW, winH,
        NULL, NULL, hi, NULL);
    if (!hWnd) return false;

    build_dashboard_page();
    build_rc_page();
    build_host_page();

    switch_page(Page::Dashboard);

    hCursorBmp = make_remote_cursor_bmp(CURSOR_SIZE);
    return true;
}

void ControllerApp::build_dashboard_page()
{
    const int CW = 420, CH = 480;
    int midX = CW / 2;

    auto mk = [&](HWND hw) { TagWindow(hw, TAG_DASHBOARD); return hw; };

    hDashTitle = mk(CreateWindowW(L"STATIC", L"Simple Remote Desktop",
        WS_CHILD | SS_CENTER | SS_NOPREFIX,
        20, 140, CW - 40, 38, hWnd, NULL, hInst, NULL));
    SendMessage(hDashTitle, WM_SETFONT, (WPARAM)hfTitle, TRUE);

    hDashSub = mk(CreateWindowW(L"STATIC", L"by r00t-tsai",
        WS_CHILD | SS_CENTER | SS_NOPREFIX,
        20, 182, CW - 40, 20, hWnd, NULL, hInst, NULL));
    SendMessage(hDashSub, WM_SETFONT, (WPARAM)hfItalic, TRUE);

    mk(CreateWindowW(L"STATIC", L"", WS_CHILD | SS_ETCHEDHORZ,
        60, 212, CW - 120, 2, hWnd, NULL, hInst, NULL));

    const int btnW = 230, btnH = 40;
    hDashBtnRC = mk(CreateWindowW(L"BUTTON", L"Connect to Device",
        WS_CHILD | BS_PUSHBUTTON,
        midX - btnW / 2, 228, btnW, btnH,
        hWnd, (HMENU)(INT_PTR)ID_DASH_BTN_RC, hInst, NULL));
    SendMessage(hDashBtnRC, WM_SETFONT, (WPARAM)hfBold, TRUE);

    hDashBtnHost = mk(CreateWindowW(L"BUTTON", L"Host RDP Connection",
        WS_CHILD | BS_PUSHBUTTON,
        midX - btnW / 2, 278, btnW, btnH,
        hWnd, (HMENU)(INT_PTR)ID_DASH_BTN_HOST, hInst, NULL));
    SendMessage(hDashBtnHost, WM_SETFONT, (WPARAM)hfBold, TRUE);
}

void ControllerApp::build_rc_page()
{
    const int CW = 420;
    const int col0 = 16, col1 = 126, ctrlW = 270, rowH = 26;

    auto lbl = [&](const wchar_t* t, int x, int y, int w, int h, bool bold = false)->HWND {
        HWND hw = CreateWindowW(L"STATIC", t, WS_CHILD | SS_LEFT | SS_NOPREFIX,
            x, y, w, h, hWnd, NULL, hInst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)(bold ? hfBold : hfNormal), TRUE);
        TagWindow(hw, TAG_RC); return hw;
        };
    auto edt = [&](const wchar_t* def, int id, int x, int y, int w, int h, DWORD ex = 0)->HWND {
        HWND hw = CreateWindowW(L"EDIT", def, WS_CHILD | WS_BORDER | ES_AUTOHSCROLL | ex,
            x, y, w, h, hWnd, (HMENU)(INT_PTR)id, hInst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)hfNormal, TRUE);
        TagWindow(hw, TAG_RC); return hw;
        };
    auto chk = [&](const wchar_t* t, int id, int x, int y, int w, int h)->HWND {
        HWND hw = CreateWindowW(L"BUTTON", t, WS_CHILD | BS_AUTOCHECKBOX | BS_NOTIFY,
            x, y, w, h, hWnd, (HMENU)(INT_PTR)id, hInst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)hfNormal, TRUE);
        TagWindow(hw, TAG_RC); return hw;
        };
    auto sep = [&](int y) {
        HWND hw = CreateWindowW(L"STATIC", L"", WS_CHILD | SS_ETCHEDHORZ,
            col0, y, CW - col0 * 2, 2, hWnd, NULL, hInst, NULL);
        TagWindow(hw, TAG_RC);
        };

    int y = 10;

    lbl(L"Connection", col0, y, CW - col0 * 2, 17, true); y += 22;
    lbl(L"Connect to a host device via LAN/WAN domain or IP.", col0, y, CW - col0 * 2, 15); y += 22;

    lbl(L"Host / IP:", col0, y + 3, col1 - col0 - 4, 17);
    hRcEditIP = edt(L"", ID_RC_EDIT_IP, col1, y, ctrlW, 22);

    hRcIpGhost = CreateWindowW(L"STATIC", L"e.g.  192.168.1.10, mypc.ddns.net, 203.0.113.5",
        WS_CHILD | SS_LEFT | SS_NOPREFIX | SS_NOTIFY,
        col1 + 4, y + 4, ctrlW - 8, 16, hWnd, (HMENU)(INT_PTR)ID_RC_EDIT_IP_GHOST, hInst, NULL);
    SendMessage(hRcIpGhost, WM_SETFONT, (WPARAM)hfItalic, TRUE);
    TagWindow(hRcIpGhost, TAG_RC);
    y += rowH;

    lbl(L"Your name:", col0, y + 3, col1 - col0 - 4, 17);
    hRcEditName = edt(L"Controller", ID_RC_EDIT_NAME, col1, y, ctrlW, 22); y += rowH + 4;

    sep(y); y += 6;
    lbl(L"Network Ports", col0, y, CW - col0 * 2, 17, true); y += 22;
    lbl(L"Configuration must match the host's ports in their settings.dat", col0, y, CW - col0 * 2, 15); y += 22;

    lbl(L"Video port:", col0, y + 3, col1 - col0 - 4, 17);
    hRcEditVport = edt(L"55000", ID_RC_EDIT_VPORT, col1, y, 88, 22, ES_NUMBER); y += rowH;

    lbl(L"Input port:", col0, y + 3, col1 - col0 - 4, 17);
    hRcEditIport = edt(L"55001", ID_RC_EDIT_IPORT, col1, y, 88, 22, ES_NUMBER); y += rowH;

    lbl(L"Audio port:", col0, y + 3, col1 - col0 - 4, 17);
    hRcEditAport = edt(L"55002", ID_RC_EDIT_APORT, col1, y, 88, 22, ES_NUMBER); y += rowH + 4;

    sep(y); y += 6;
    lbl(L"Encryption Key", col0, y, CW - col0 * 2, 17, true); y += 22;
    lbl(L"Enter the host device's encryption key (ignore if set to none).", col0, y, CW - col0 * 2, 15); y += 22;

    lbl(L"Host Key:", col0, y + 3, col1 - col0 - 4, 17);
    hRcEditPass = edt(L"", ID_RC_EDIT_PASS, col1, y, ctrlW, 22, ES_PASSWORD); y += rowH;

    lbl(L"Leave blank to disable encryption.", col1, y, ctrlW, 15); y += 20;

    sep(y); y += 10;

    {
        const int bW = 210, bH = 34;
        hRcBtnConnect = CreateWindowW(L"BUTTON", L"Connect to Desktop",
            WS_CHILD | BS_DEFPUSHBUTTON,
            (CW - bW) / 2, y, bW, bH,
            hWnd, (HMENU)(INT_PTR)ID_RC_BTN_CONNECT, hInst, NULL);
        SendMessage(hRcBtnConnect, WM_SETFONT, (WPARAM)hfBold, TRUE);
        TagWindow(hRcBtnConnect, TAG_RC);
    }
    y += 42;

    {
        const int bW = 100, bH = 26;
        hRcBtnBack = CreateWindowW(L"BUTTON", L"\x2190 Back",
            WS_CHILD | BS_PUSHBUTTON,
            (CW - bW) / 2, y, bW, bH,
            hWnd, (HMENU)(INT_PTR)ID_RC_BTN_BACK, hInst, NULL);
        SendMessage(hRcBtnBack, WM_SETFONT, (WPARAM)hfNormal, TRUE);
        TagWindow(hRcBtnBack, TAG_RC);
    }
}

void ControllerApp::build_host_page()
{
    const int CW = 420;
    const int col0 = 16, col1 = 126, ctrlW = 270, rowH = 26;

    auto lbl = [&](const wchar_t* t, int x, int y, int w, int h, bool bold = false)->HWND {
        HWND hw = CreateWindowW(L"STATIC", t, WS_CHILD | SS_LEFT | SS_NOPREFIX,
            x, y, w, h, hWnd, NULL, hInst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)(bold ? hfBold : hfNormal), TRUE);
        TagWindow(hw, TAG_HOST); return hw;
        };
    auto edt = [&](const wchar_t* def, int id, int x, int y, int w, int h, DWORD ex = 0)->HWND {
        HWND hw = CreateWindowW(L"EDIT", def, WS_CHILD | WS_BORDER | ES_AUTOHSCROLL | ex,
            x, y, w, h, hWnd, (HMENU)(INT_PTR)id, hInst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)hfNormal, TRUE);
        TagWindow(hw, TAG_HOST); return hw;
        };
    auto chk = [&](const wchar_t* t, int id, int x, int y, int w, int h)->HWND {
        HWND hw = CreateWindowW(L"BUTTON", t, WS_CHILD | BS_AUTOCHECKBOX | BS_NOTIFY,
            x, y, w, h, hWnd, (HMENU)(INT_PTR)id, hInst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)hfNormal, TRUE);
        TagWindow(hw, TAG_HOST); return hw;
        };
    auto sep = [&](int y) {
        HWND hw = CreateWindowW(L"STATIC", L"", WS_CHILD | SS_ETCHEDHORZ,
            col0, y, CW - col0 * 2, 2, hWnd, NULL, hInst, NULL);
        TagWindow(hw, TAG_HOST);
        };

    int y = 10;

    lbl(L"Host Connection", col0, y, CW - col0 * 2, 17, true); y += 22;
    lbl(L"Configure host ports and encryption.", col0, y, CW - col0 * 2, 15); y += 22;

    sep(y); y += 8;
    lbl(L"Network Ports", col0, y, CW - col0 * 2, 17, true); y += 22;

    lbl(L"Video port:", col0, y + 3, col1 - col0 - 4, 17);
    hHostEditVport = edt(L"55000", ID_HOST_EDIT_VPORT, col1, y, 88, 22, ES_NUMBER); y += rowH;

    lbl(L"Input port:", col0, y + 3, col1 - col0 - 4, 17);
    hHostEditIport = edt(L"55001", ID_HOST_EDIT_IPORT, col1, y, 88, 22, ES_NUMBER); y += rowH;

    lbl(L"Audio port:", col0, y + 3, col1 - col0 - 4, 17);
    hHostEditAport = edt(L"55002", ID_HOST_EDIT_APORT, col1, y, 88, 22, ES_NUMBER); y += rowH;

    hHostChkInet = chk(L"WAN Mode  (public IP / hostname)",
        ID_HOST_CHK_INTERNET, col1, y, ctrlW, 20); y += rowH + 4;

    sep(y); y += 6;
    lbl(L"Encryption Key", col0, y, CW - col0 * 2, 17, true); y += 22;

    lbl(L"Key:", col0, y + 3, col1 - col0 - 4, 17);
    hHostEditPass = edt(L"", ID_HOST_EDIT_PASS, col1, y, ctrlW, 22, ES_PASSWORD); y += rowH;

    lbl(L"Leave blank to disable encryption.", col1, y, ctrlW, 15); y += 24;

    sep(y); y += 10;

    {
        const int bW = 210, bH = 34;
        hHostBtnStart = CreateWindowW(L"BUTTON", L"Start Host",
            WS_CHILD | BS_DEFPUSHBUTTON,
            (CW - bW) / 2, y, bW, bH,
            hWnd, (HMENU)(INT_PTR)ID_HOST_BTN_START, hInst, NULL);
        SendMessage(hHostBtnStart, WM_SETFONT, (WPARAM)hfBold, TRUE);
        TagWindow(hHostBtnStart, TAG_HOST);
    }
    y += 42;

    {
        const int bW = 100, bH = 26;
        hHostBtnBack = CreateWindowW(L"BUTTON", L"\x2190 Back",
            WS_CHILD | BS_PUSHBUTTON,
            (CW - bW) / 2, y, bW, bH,
            hWnd, (HMENU)(INT_PTR)ID_HOST_BTN_BACK, hInst, NULL);
        SendMessage(hHostBtnBack, WM_SETFONT, (WPARAM)hfNormal, TRUE);
        TagWindow(hHostBtnBack, TAG_HOST);
    }
}

static LRESULT CALLBACK LoadingOverlayProc(HWND hOv, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == WM_COMMAND && LOWORD(wp) == ID_OVERLAY_CANCEL && g_app)
        PostMessage(g_app->hWnd, WM_COMMAND,
            MAKEWPARAM(ID_OVERLAY_CANCEL, BN_CLICKED), lp);

    if (msg == WM_PAINT) {
        PAINTSTRUCT ps; HDC hdc = BeginPaint(hOv, &ps);
        RECT rc; GetClientRect(hOv, &rc);
        FillRect(hdc, &rc, (HBRUSH)GetStockObject(WHITE_BRUSH));
        if (g_app) {
            int cx = (rc.right - rc.left) / 2, R = 22, cy_s = 54, dotR = 5;
            for (int seg = 0; seg < 8; seg++) {
                double ang = (g_app->spinAngle + seg * 45.0) * 3.14159265 / 180.0;
                int dx = (int)(R * cos(ang)), dy = (int)(R * sin(ang));
                int fade = 60 + seg * 25; if (fade > 220)fade = 220;
                COLORREF col = RGB(fade, fade, fade);
                HBRUSH br = CreateSolidBrush(col); HPEN pen = CreatePen(PS_SOLID, 1, col);
                HGDIOBJ op = SelectObject(hdc, pen), ob = SelectObject(hdc, br);
                Ellipse(hdc, cx + dx - dotR, cy_s + dy - dotR, cx + dx + dotR, cy_s + dy + dotR);
                SelectObject(hdc, op); SelectObject(hdc, ob);
                DeleteObject(br); DeleteObject(pen);
            }
        }
        EndPaint(hOv, &ps); return 0;
    }
    return DefWindowProcW(hOv, msg, wp, lp);
}

void ControllerApp::show_loading_overlay()
{
    if (hLoadingWnd) return;
    const wchar_t* CLS = L"SRDT_LoadingOverlay";
    WNDCLASSEXW wc{}; wc.cbSize = sizeof(wc); wc.lpfnWndProc = LoadingOverlayProc;
    wc.hInstance = hInst; wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wc.hCursor = LoadCursor(NULL, IDC_WAIT); wc.lpszClassName = CLS;
    RegisterClassExW(&wc);

    RECT cr; GetClientRect(hWnd, &cr);
    int ow = cr.right - cr.left, oh = cr.bottom - cr.top;
    hLoadingWnd = CreateWindowExW(0, CLS, NULL, WS_CHILD | WS_VISIBLE,
        0, 0, ow, oh, hWnd, NULL, hInst, NULL);
    if (!hLoadingWnd) return;

    int cx = ow / 2;
    hLoadingLabel = CreateWindowW(L"STATIC", L"Connecting...",
        WS_CHILD | WS_VISIBLE | SS_CENTER | SS_NOPREFIX,
        cx - 110, 88, 220, 20, hLoadingWnd, NULL, hInst, NULL);
    SendMessage(hLoadingLabel, WM_SETFONT, (WPARAM)hfNormal, TRUE);

    hLoadingLate = CreateWindowW(L"STATIC", L"Still attempting, please wait...",
        WS_CHILD | SS_CENTER | SS_NOPREFIX,
        cx - 130, 114, 260, 18, hLoadingWnd, NULL, hInst, NULL);
    SendMessage(hLoadingLate, WM_SETFONT, (WPARAM)hfNormal, TRUE);

    hLoadingCancel = CreateWindowW(L"BUTTON", L"Cancel",
        WS_CHILD | BS_PUSHBUTTON,
        cx - 50, 140, 100, 28, hLoadingWnd, (HMENU)(INT_PTR)ID_OVERLAY_CANCEL, hInst, NULL);
    SendMessage(hLoadingCancel, WM_SETFONT, (WPARAM)hfNormal, TRUE);

    spinAngle = 0; connectCancelled = false;
    BringWindowToTop(hLoadingWnd);
    SetTimer(hWnd, ID_OVERLAY_TIMER, 60, NULL);
    SetTimer(hWnd, ID_OVERLAY_LATE_TIMER, 5000, NULL);
    UpdateWindow(hWnd);
}

void ControllerApp::hide_loading_overlay()
{
    KillTimer(hWnd, ID_OVERLAY_TIMER);
    KillTimer(hWnd, ID_OVERLAY_LATE_TIMER);
    if (hLoadingWnd) {
        DestroyWindow(hLoadingWnd);
        hLoadingWnd = hLoadingLabel = hLoadingLate = hLoadingCancel = NULL;
    }
}

void ControllerApp::tick_spinner()
{
    spinAngle = (spinAngle + 15) % 360;
    if (hLoadingWnd) { RECT r = { 0,0,9999,85 }; InvalidateRect(hLoadingWnd, &r, TRUE); }
}

void ControllerApp::show_late_label()
{
    if (!hLoadingWnd) return;
    if (hLoadingLate) { ShowWindow(hLoadingLate, SW_SHOW); UpdateWindow(hLoadingLate); }
    if (hLoadingCancel) { ShowWindow(hLoadingCancel, SW_SHOW); UpdateWindow(hLoadingCancel); }
}

void ControllerApp::cancel_connect()
{
    connectCancelled = true;
    hide_loading_overlay();
    if (hRcBtnConnect) EnableWindow(hRcBtnConnect, TRUE);
}

void ControllerApp::create_session_window()
{
    int scrW = GetSystemMetrics(SM_CXSCREEN), scrH = GetSystemMetrics(SM_CYSCREEN);
    hSessionWnd = CreateWindowExW(0, L"RDSessionCls",
        L"Remote Desktop — Session", WS_OVERLAPPEDWINDOW,
        100, 100, scrW / 2, scrH / 2, NULL, NULL, hInst, NULL);

    auto btn = [&](const wchar_t* t, int id, int x, int y, int w, int h)->HWND {
        HWND hw = CreateWindowW(L"BUTTON", t, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            x, y, w, h, hSessionWnd, (HMENU)(INT_PTR)id, hInst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)hfNormal, TRUE); return hw;
        };
    auto lbl = [&](const wchar_t* t, int x, int y, int w, int h)->HWND {
        HWND hw = CreateWindowW(L"STATIC", t, WS_CHILD | WS_VISIBLE | SS_LEFT,
            x, y, w, h, hSessionWnd, NULL, hInst, NULL);
        SendMessage(hw, WM_SETFONT, (WPARAM)hfNormal, TRUE); return hw;
        };

    hBtnDisconn = btn(L"Disconnect", ID_BTN_DISCONNECT, 5, 5, 95, 26);
    hBtnVolume = btn(L"Volume", ID_BTN_VOLUME, 106, 5, 72, 26);
    hBtnDebug = btn(L"Debug(F12)", ID_BTN_DEBUG, 184, 5, 90, 26);
    hLockLabel = lbl(L"Click stream to lock cursor  |  ESC to unlock", 280, 9, 500, 18);

    hCanvas = CreateWindowExW(0, L"RDCanvasCls", NULL, WS_CHILD | WS_VISIBLE,
        0, 36, scrW / 2, scrH / 2 - 58, hSessionWnd, NULL, hInst, NULL);

    const wchar_t* enc = Core_IsAESEnabled()
        ? L"Connected  [AES-128-CTR encrypted]"
        : L"Connected  [Unencrypted]";
    hStatusBar = CreateWindowW(L"STATIC", enc,
        WS_CHILD | WS_VISIBLE | SS_LEFT | SS_SUNKEN,
        0, scrH / 2 - 22, scrW / 2, 22, hSessionWnd, NULL, hInst, NULL);
    SendMessage(hStatusBar, WM_SETFONT, (WPARAM)hfNormal, TRUE);

    if (hRcChkDebug && SendMessage(hRcChkDebug, BM_GETCHECK, 0, 0) == BST_CHECKED)
        toggle_debug();

    ShowWindow(hSessionWnd, SW_SHOW); UpdateWindow(hSessionWnd);
    RECT rc; GetClientRect(hSessionWnd, &rc);
    SendMessage(hSessionWnd, WM_SIZE, 0, MAKELPARAM(rc.right, rc.bottom));
}

void ControllerApp::run()
{
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg); DispatchMessageW(&msg);
    }
}

void ControllerApp::destroy()
{
    stop_listeners();
    if (video_conn) { video_conn->disconnect(); video_conn.reset(); }
    if (input_conn) { input_conn->disconnect(); input_conn.reset(); }
    if (hFrameBmp) { DeleteObject(hFrameBmp);  hFrameBmp = NULL; }
    if (hCursorBmp) { DeleteObject(hCursorBmp); hCursorBmp = NULL; }
    remove_tray_icon();
}

void ControllerApp::set_status(const std::string& s)
{
    if (!hStatusBar) return;
    std::wstring ws(s.begin(), s.end());
    SetWindowTextW(hStatusBar, ws.c_str());
}
void ControllerApp::update_ip_ghost()
{
    if (!hRcIpGhost || !hRcEditIP) return;
    bool wan = hRcChkInet && (SendMessage(hRcChkInet, BM_GETCHECK, 0, 0) == BST_CHECKED);
    SetWindowTextW(hRcIpGhost,
        wan ? L"e.g. 192.168.1.10 or mypc.ddns.net/203.0.113.5"
        : L"e.g.  192.168.1.10 or mypc.ddns.net/203.0.113.5");
    wchar_t buf[4] = {}; GetWindowTextW(hRcEditIP, buf, 4);
    ShowWindow(hRcIpGhost, buf[0] == L'\0' ? SW_SHOW : SW_HIDE);
}

void ControllerApp::on_connect()
{
    if (!show_consent_dialog()) return;

    wchar_t ipB[128] = {}, nameB[64] = {}, vpB[8] = {}, ipB2[8] = {}, apB[8] = {}, passB[128] = {};
    GetWindowTextW(hRcEditIP, ipB, 128);
    GetWindowTextW(hRcEditName, nameB, 64);
    GetWindowTextW(hRcEditVport, vpB, 8);
    GetWindowTextW(hRcEditIport, ipB2, 8);
    GetWindowTextW(hRcEditAport, apB, 8);
    GetWindowTextW(hRcEditPass, passB, 128);

    int vport = _wtoi(vpB), iport = _wtoi(ipB2), aport = _wtoi(apB);
    if (vport < 1024 || vport>65535)vport = 55000;
    if (iport < 1024 || iport>65535)iport = 55001;
    if (aport < 1024 || aport>65535)aport = 55002;
    Core_SetVideoPorts(vport, iport, aport);

    std::wstring wpass(passB);
    std::string pass(wpass.begin(), wpass.end());
    if (!pass.empty()) Core_SetupAES(pass); else Core_DisableAES();
    Core_ResetAESCounters(); Core_BwReset();

    std::wstring wip(ipB), wname(nameB);
    std::string host(wip.begin(), wip.end());
    std::string name = wname.empty() ? "Controller" : std::string(wname.begin(), wname.end());
    if (host.empty()) {
        MessageBoxW(hWnd, L"Please enter the host IP address or hostname.", L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    bool wan = hRcChkInet && (SendMessage(hRcChkInet, BM_GETCHECK, 0, 0) == BST_CHECKED);
    if (wan) {
        bool looks_lan = false;
        if (host.rfind("192.168.", 0) == 0 || host.rfind("10.", 0) == 0 || host == "localhost" ||
            host.rfind("172.16.", 0) == 0 || host.rfind("172.17.", 0) == 0 ||
            host.rfind("172.18.", 0) == 0 || host.rfind("172.19.", 0) == 0 ||
            host.rfind("172.20.", 0) == 0 || host.rfind("172.31.", 0) == 0)
            looks_lan = true;
        if (looks_lan) {
            if (MessageBoxW(hWnd,
                L"'WAN Discovery' is checked but the address looks like a LAN address.\n\n"
                L"For internet connections enter the public IP or hostname.\nContinue anyway?",
                L"Check Address", MB_YESNO | MB_ICONWARNING) != IDYES) return;
        }
    }

    EnableWindow(hRcBtnConnect, FALSE);
    show_loading_overlay();

    HWND post = hWnd;
    std::thread([this, host, name, post, vport, iport, aport, wan]() {

        auto nb = [&](int port)->SOCKET {
            sockaddr_in addr{}; addr.sin_family = AF_INET;
            addrinfo hints{}, * res = nullptr;
            hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
            char ps[8]; sprintf_s(ps, "%d", port);
            if (getaddrinfo(host.c_str(), ps, &hints, &res) == 0 && res) {
                addr = *reinterpret_cast<sockaddr_in*>(res->ai_addr);
                addr.sin_port = htons((u_short)port);
                freeaddrinfo(res);
            }
            else { if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) return INVALID_SOCKET; }
            SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s == INVALID_SOCKET) return INVALID_SOCKET;
            u_long nb1 = 1; ioctlsocket(s, FIONBIO, &nb1);
            ::connect(s, (sockaddr*)&addr, sizeof(addr));
            int slices = wan ? 200 : 60;
            for (int i = 0; i < slices && !connectCancelled; i++) {
                timeval tv{}; tv.tv_usec = 50000;
                fd_set ws, es; FD_ZERO(&ws); FD_SET(s, &ws); FD_ZERO(&es); FD_SET(s, &es);
                int r = select(0, NULL, &ws, &es, &tv);
                if (r > 0 && FD_ISSET(s, &ws)) {
                    int err = 0, elen = sizeof(err);
                    getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &elen);
                    if (err != 0) break;
                    u_long b0 = 0; ioctlsocket(s, FIONBIO, &b0);
                    BOOL nd = 1; setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char*)&nd, sizeof(nd));
                    return s;
                }
                if (r < 0 || FD_ISSET(s, &es)) break;
            }
            closesocket(s); return INVALID_SOCKET;
            };

        auto ic = std::make_unique<InputConnection>(host);
        ic->input_port = iport;
        bool inputOk = false;
        {
            int deadline = wan ? 300 : 60;
            auto dl = std::chrono::steady_clock::now() + std::chrono::seconds(deadline);
            while (!connectCancelled && std::chrono::steady_clock::now() < dl) {
                SOCKET s = nb(iport);
                if (connectCancelled) { if (s != INVALID_SOCKET)closesocket(s); break; }
                if (s != INVALID_SOCKET) { ic->sock = s; ic->running = true; inputOk = true; break; }
                for (int i = 0; i < 10 && !connectCancelled; i++)Sleep(50);
            }
        }
        if (connectCancelled) return;
        if (!inputOk) {
            PostMessage(post, WM_APP_CONN_CANCEL, 0, 0);
            PostMessage(post, WM_APP_STATUS, 0, (LPARAM)new std::string("Failed: could not connect input channel"));
            return;
        }
        if (connectCancelled) { ic->disconnect(); return; }

        auto vc = std::make_unique<VideoConnection>(host, name);
        vc->video_port = vport;
        vc->frame_callback = [this](PendingFrame pf) {on_frame(std::move(pf)); };
        vc->pending_check_callback = [this]()->bool {return frame_scheduled.load(); };
        vc->status_callback = [this, post](std::string m) {
            HWND t = hSessionWnd ? hSessionWnd : post;
            PostMessage(t, WM_APP_STATUS, 0, (LPARAM)new std::string(m));
            };

        auto [ok, errmsg] = vc->connect_video();
        if (connectCancelled) { ic->disconnect(); return; }
        if (!ok) {
            ic->disconnect();
            PostMessage(post, WM_APP_CONN_CANCEL, 0, 0);
            PostMessage(post, WM_APP_STATUS, 0, (LPARAM)new std::string("Failed: " + errmsg));
            return;
        }
        video_conn = std::move(vc);
        input_conn = std::move(ic);
        SOCKET asock = nb(aport);
        PostMessage(post, WM_APP_CONNECTED, (WPARAM)(asock != INVALID_SOCKET ? asock : (SOCKET)INVALID_SOCKET), 0);
        }).detach();
}

void ControllerApp::on_disconnected()
{
    unlock_cursor();
    destroy_session_window();
    hide_loading_overlay();
    if (hRcBtnConnect) EnableWindow(hRcBtnConnect, TRUE);
    switch_page(Page::RC);
}

void ControllerApp::destroy_session_window()
{
    if (!hSessionWnd) return;
    if (debugVisible) toggle_debug();
    if (video_conn) { video_conn->disconnect(); video_conn.reset(); }
    if (input_conn) { input_conn->disconnect(); input_conn.reset(); }
    if (Core_AudioStopEvtValid()) Core_AudioStopEvtSignal();
    if (audio_thread.joinable()) audio_thread.join();
    if (Core_AudioStopEvtValid()) Core_AudioStopEvtClose();
    { std::lock_guard<std::mutex>lk(frame_mutex); pending_frame.reset(); frame_scheduled = false; }
    if (hFrameBmp) { DeleteObject(hFrameBmp); hFrameBmp = NULL; }
    firstFrame = true;
    DestroyWindow(hSessionWnd);
    hSessionWnd = hCanvas = hBtnDisconn = hBtnVolume = hBtnDebug = hLockLabel = hStatusBar = NULL;
}

void ControllerApp::on_disconnect_btn() { on_disconnected(); }

void ControllerApp::on_close()
{
    unlock_cursor();
    stop_host();
    if (video_conn) { video_conn->disconnect(); video_conn.reset(); }
    if (input_conn) { input_conn->disconnect(); input_conn.reset(); }
    stop_listeners();
    remove_tray_icon();
    if (hSessionWnd) DestroyWindow(hSessionWnd);
    DestroyWindow(hWnd);
}

void ControllerApp::on_start_host()
{
    wchar_t vpB[8] = {}, ipB[8] = {}, apB[8] = {}, passB[128] = {};
    GetWindowTextW(hHostEditVport, vpB, 8);
    GetWindowTextW(hHostEditIport, ipB, 8);
    GetWindowTextW(hHostEditAport, apB, 8);
    GetWindowTextW(hHostEditPass, passB, 128);

    int vport = _wtoi(vpB), iport = _wtoi(ipB), aport = _wtoi(apB);
    if (vport < 1024 || vport>65535)vport = 55000;
    if (iport < 1024 || iport>65535)iport = 55001;
    if (aport < 1024 || aport>65535)aport = 55002;

    bool wan = (SendMessage(hHostChkInet, BM_GETCHECK, 0, 0) == BST_CHECKED);
    std::wstring wpass(passB);
    std::string pass(wpass.begin(), wpass.end());

    wchar_t exeDir[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exeDir, MAX_PATH);
    if (wchar_t* sl = wcsrchr(exeDir, L'\\')) *(sl + 1) = L'\0';

    wchar_t hostDir[MAX_PATH];
    swprintf_s(hostDir, L"%score\\host", exeDir);
    CreateDirectoryW(hostDir, NULL);

    wchar_t settingsPath[MAX_PATH];
    swprintf_s(settingsPath, L"%s\\settings.dat", hostDir);
    char narrowPath[MAX_PATH] = {};
    WideCharToMultiByte(CP_ACP, 0, settingsPath, -1, narrowPath, MAX_PATH, NULL, NULL);

    std::ofstream f(narrowPath, std::ios::trunc);
    if (!f.is_open()) {
        MessageBoxW(hWnd,
            L"Could not write core\\host\\settings.dat\n"
            L"Make sure the folder exists and is writable.",
            L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    f << "# Simple Remote Desktop — Host Agent Configuration\n";
    f << "video_port = " << vport << "\n";
    f << "input_port = " << iport << "\n";
    f << "audio_port = " << aport << "\n";
    f << "connection = " << (wan ? "WAN" : "LAN") << "\n";
    if (!pass.empty()) f << "passphrase = " << pass << "\n";
    else              f << "# passphrase =   (disabled)\n";
    f.close();

    wchar_t hostExe[MAX_PATH];
    swprintf_s(hostExe, L"%score\\host\\host.exe", exeDir);
    if (GetFileAttributesW(hostExe) == INVALID_FILE_ATTRIBUTES) {
        MessageBoxW(hWnd,
            L"host.exe not found in core\\host\\\n"
            L"Please copy host.exe there before starting.",
            L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    STARTUPINFOW si{}; si.cb = sizeof(si);
    ZeroMemory(&hostProc, sizeof(hostProc));
    if (!CreateProcessW(hostExe, NULL, NULL, NULL, FALSE, 0, NULL, hostDir, &si, &hostProc)) {
        MessageBoxW(hWnd, L"Failed to start host.exe.", L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    hostRunning = true;

    add_tray_icon();
    ShowWindow(hWnd, SW_HIDE);
    show_tray_balloon();
}

void ControllerApp::stop_host()
{
    if (!hostRunning)
        return;

    hostRunning = false;

    DWORD pid = hostProc.dwProcessId;

    if (hostProc.hProcess)
    {
        CloseHandle(hostProc.hProcess);
        CloseHandle(hostProc.hThread);
        ZeroMemory(&hostProc, sizeof(hostProc));
    }

    if (pid != 0)
    {
        wchar_t params[128];
        swprintf_s(params, L"/F /T /PID %lu", (unsigned long)pid);

        wchar_t sysDir[MAX_PATH];
        GetSystemDirectoryW(sysDir, MAX_PATH);

        wchar_t taskkillPath[MAX_PATH];
        swprintf_s(taskkillPath, L"%s\\taskkill.exe", sysDir);

        SHELLEXECUTEINFOW sei{};
        sei.cbSize = sizeof(sei);
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.hwnd = hWnd;
        sei.lpVerb = L"runas";
        sei.lpFile = taskkillPath;
        sei.lpParameters = params;
        sei.nShow = SW_HIDE;

        if (ShellExecuteExW(&sei))
        {
            if (sei.hProcess)
            {
                WaitForSingleObject(sei.hProcess, 8000);
                CloseHandle(sei.hProcess);
            }
        }
    }

    hide_gray_overlay();
    remove_tray_icon();

    ShowWindow(hWnd, SW_SHOW);
    SetForegroundWindow(hWnd);

    switch_page(Page::Host);
}

static LRESULT CALLBACK GrayOverlayProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == WM_PAINT) {
        PAINTSTRUCT ps; HDC hdc = BeginPaint(hw, &ps);
        RECT rc; GetClientRect(hw, &rc);

        HBRUSH br = CreateSolidBrush(RGB(180, 180, 180));
        FillRect(hdc, &rc, br);
        DeleteObject(br);
        EndPaint(hw, &ps);
        return 0;
    }

    if (msg == WM_LBUTTONDOWN || msg == WM_RBUTTONDOWN ||
        msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN ||
        msg == WM_SETCURSOR)
        return 0;
    return DefWindowProcW(hw, msg, wp, lp);
}

void ControllerApp::show_gray_overlay()
{
    if (hGrayOverlay) return;
    const wchar_t* CLS = L"SRDT_GrayOverlay";
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc); wc.lpfnWndProc = GrayOverlayProc;
    wc.hInstance = hInst; wc.hbrBackground = (HBRUSH)GetStockObject(GRAY_BRUSH);
    wc.lpszClassName = CLS;
    RegisterClassExW(&wc);

    RECT cr; GetClientRect(hWnd, &cr);
    hGrayOverlay = CreateWindowExW(0, CLS, NULL,
        WS_CHILD | WS_VISIBLE,
        0, 0, cr.right, cr.bottom,
        hWnd, NULL, hInst, NULL);
    BringWindowToTop(hGrayOverlay);
    UpdateWindow(hWnd);
}

void ControllerApp::hide_gray_overlay()
{
    if (!hGrayOverlay) return;
    DestroyWindow(hGrayOverlay);
    hGrayOverlay = NULL;
    InvalidateRect(hWnd, NULL, TRUE);
    UpdateWindow(hWnd);
}

static LRESULT CALLBACK ConfirmDisconnectProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        HFONT hf = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

        const int W = 420;
        const int pad = 20;

        const int btnW = 150;
        const int btnH = 34;

        const int btnY = 110;

        HWND hL1 = CreateWindowW(
            L"STATIC",
            L"Are you sure you want to disconnect?",
            WS_CHILD | WS_VISIBLE | SS_CENTER | SS_NOPREFIX,
            pad, 20, W - pad * 2, 20,
            hw, NULL, NULL, NULL);

        SendMessage(hL1, WM_SETFONT, (WPARAM)hf, TRUE);

        HWND hL2 = CreateWindowW(
            L"STATIC",
            L"This will terminate any ongoing remote connection session.",
            WS_CHILD | WS_VISIBLE | SS_CENTER | SS_NOPREFIX,
            pad, 45, W - pad * 2, 18,
            hw, NULL, NULL, NULL);

        SendMessage(hL2, WM_SETFONT, (WPARAM)hf, TRUE);

        CreateWindowW(
            L"STATIC", L"",
            WS_CHILD | WS_VISIBLE | SS_ETCHEDHORZ,
            pad, 75, W - pad * 2, 2,
            hw, NULL, NULL, NULL);

        int center = W / 2;

        HWND hYes = CreateWindowW(
            L"BUTTON", L"Disconnect",
            WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
            center - btnW - 10, btnY,
            btnW, btnH,
            hw, (HMENU)ID_CONFIRM_YES, NULL, NULL);

        SendMessage(hYes, WM_SETFONT, (WPARAM)hf, TRUE);

        HWND hNo = CreateWindowW(
            L"BUTTON", L"Cancel",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            center + 10, btnY,
            btnW, btnH,
            hw, (HMENU)ID_CONFIRM_NO, NULL, NULL);

        SendMessage(hNo, WM_SETFONT, (WPARAM)hf, TRUE);

        return 0;
    }

    case WM_COMMAND:
        if (g_app)
            PostMessage(g_app->hWnd, WM_COMMAND, wp, lp);

        DestroyWindow(hw);
        return 0;

    case WM_CLOSE:
        if (g_app)
            PostMessage(g_app->hWnd,
                WM_COMMAND,
                MAKEWPARAM(ID_CONFIRM_NO, BN_CLICKED),
                0);

        DestroyWindow(hw);
        return 0;
    }

    return DefWindowProcW(hw, msg, wp, lp);
}

void ControllerApp::show_disconnect_confirm()
{
    const wchar_t* CLS = L"SRDT_ConfirmDlg";
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc); wc.lpfnWndProc = ConfirmDisconnectProc;
    wc.hInstance = hInst; wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.lpszClassName = CLS;
    RegisterClassExW(&wc);

    const int DW = 435;
    const int DH = 200;
    RECT wr; GetWindowRect(hWnd, &wr);
    int cx = (wr.left + wr.right) / 2, cy = (wr.top + wr.bottom) / 2;

    HWND hDlg = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_DLGMODALFRAME,
        CLS, L"Disconnect Host",
        WS_POPUP | WS_CAPTION | WS_VISIBLE,
        cx - DW / 2, cy - DH / 2, DW, DH,
        hWnd, NULL, hInst, NULL);
    SetForegroundWindow(hDlg);
    (void)hDlg;

}

void ControllerApp::show_tray_balloon()
{
    if (!trayVisible)
        return;

    trayNID.uFlags = NIF_INFO;

    wcscpy_s(trayNID.szInfoTitle, L"Host Running");
    wcscpy_s(trayNID.szInfo,
        L"You can find the program in the system tray.");

    trayNID.dwInfoFlags = NIIF_INFO;

    Shell_NotifyIconW(NIM_MODIFY, &trayNID);
}

void ControllerApp::add_tray_icon()
{
    ZeroMemory(&trayNID, sizeof(trayNID));
    trayNID.cbSize = sizeof(trayNID);
    trayNID.hWnd = hWnd;
    trayNID.uID = TRAY_ID;
    trayNID.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    trayNID.uCallbackMessage = WM_TRAY_ICON;
    trayNID.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wcscpy_s(trayNID.szTip, L"Simple Remote Desktop - Host Active");
    Shell_NotifyIconW(NIM_ADD, &trayNID);
    trayVisible = true;
}

void ControllerApp::remove_tray_icon()
{
    if (!trayVisible) return;
    Shell_NotifyIconW(NIM_DELETE, &trayNID);
    trayVisible = false;
}

void ControllerApp::show_tray_menu()
{

    PostMessage(hWnd, WM_APP_TRAY_DISCONNECT, 0, 0);
}

void ControllerApp::show_volume_menu()
{
    if (!hBtnVolume) return;
    RECT rc; GetWindowRect(hBtnVolume, &rc);
    static const struct { int pct; const wchar_t* lbl; }kL[] = {
        {100,L"100%"},{75,L"75%"},{50,L"50%"},{25,L"25%"},{10,L"10%"},{0,L"0%"}
    };
    HMENU hm = CreatePopupMenu();
    for (int i = 0; i < 6; i++)
        AppendMenuW(hm, MF_STRING | (volumePct == kL[i].pct ? MF_CHECKED : 0), 501 + i, kL[i].lbl);
    SetForegroundWindow(hWnd);
    TrackPopupMenu(hm, TPM_LEFTALIGN | TPM_TOPALIGN, rc.left, rc.bottom, 0,
        hSessionWnd ? hSessionWnd : hWnd, NULL);
    DestroyMenu(hm);
}

void ControllerApp::set_volume_level(int cmd)
{
    static const int kP[] = { 100,75,50,25,10,0 };
    int idx = cmd - 501; if (idx < 0 || idx>5) return;
    volumePct = kP[idx];
    Core_SetAudioVolume(volumePct / 100.0f);
    wchar_t lbl[20];
    if (volumePct == 0)        swprintf_s(lbl, L"Vol:Mute");
    else if (volumePct == 100) swprintf_s(lbl, L"Volume");
    else                    swprintf_s(lbl, L"Vol:%d%%", volumePct);
    if (hBtnVolume) SetWindowTextW(hBtnVolume, lbl);
}

void ControllerApp::on_frame(PendingFrame pf)
{
    { std::lock_guard<std::mutex>lk(frame_mutex); pending_frame = std::make_unique<PendingFrame>(std::move(pf)); }
    if (!frame_scheduled.exchange(true)) {
        HWND t = hSessionWnd ? hSessionWnd : hWnd;
        PostMessage(t, WM_APP_FRAME, 0, 0);
    }
}

void ControllerApp::render_frame()
{
    frame_scheduled = false;
    std::unique_ptr<PendingFrame>pf;
    { std::lock_guard<std::mutex>lk(frame_mutex); pf = std::move(pending_frame); }
    if (!pf) return;
    int jw = 0, jh = 0;
    HBITMAP hNew = decode_jpeg(pf->jpeg.data(), pf->jpeg.size(), jw, jh);
    if (!hNew) return;
    if (hFrameBmp) DeleteObject(hFrameBmp);
    hFrameBmp = hNew; frameSrcW = jw; frameSrcH = jh;
    if (!cursor_locked) { cursorRatX = pf->cx_n / 65535.0; cursorRatY = pf->cy_n / 65535.0; }
    if (firstFrame && jw > 0) { fit_window_to_frame(jw, jh); firstFrame = false; }
    dbg_frames++;
    InvalidateRect(hCanvas, NULL, FALSE);
    {
        std::lock_guard<std::mutex>lk(frame_mutex);
        if (pending_frame && !frame_scheduled.exchange(true))
            PostMessage(hSessionWnd ? hSessionWnd : hWnd, WM_APP_FRAME, 0, 0);
    }
}

void ControllerApp::fit_window_to_frame(int rw, int rh)
{
    int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
    int maxW = (int)(sw * 0.90), maxH = (int)(sh * 0.90);
    int chrome = 36 + 22;
    double scale = std::min({ (double)maxW / rw,(double)(maxH - chrome) / rh,1.0 });
    int winW = (int)(rw * scale), winH = (int)(rh * scale) + chrome;
    HWND fw = hSessionWnd ? hSessionWnd : hWnd;
    SetWindowPos(fw, NULL, (sw - winW) / 2, (sh - winH) / 2, winW, winH, SWP_NOZORDER);
    UpdateWindow(fw);
}

void ControllerApp::on_paint_canvas(HDC hdc)
{
    RECT rc; GetClientRect(hCanvas, &rc);
    int cw = rc.right - rc.left, ch = rc.bottom - rc.top;
    if (!hFrameBmp || cw < 10 || ch < 10) { FillRect(hdc, &rc, (HBRUSH)GetStockObject(BLACK_BRUSH)); return; }
    blit_bitmap(hdc, hFrameBmp, frameSrcW, frameSrcH, 0, 0, cw, ch);
    if (hCursorBmp) {
        double dx = cursor_locked ? vCursorX : cursorRatX;
        double dy = cursor_locked ? vCursorY : cursorRatY;
        int cx = (int)(dx * cw), cy = (int)(dy * ch);
        BLENDFUNCTION bf{}; bf.BlendOp = AC_SRC_OVER; bf.SourceConstantAlpha = 255; bf.AlphaFormat = AC_SRC_ALPHA;
        HDC mdc = CreateCompatibleDC(hdc);
        HGDIOBJ old = SelectObject(mdc, hCursorBmp);
        AlphaBlend(hdc, cx, cy, CURSOR_SIZE, CURSOR_SIZE, mdc, 0, 0, CURSOR_SIZE, CURSOR_SIZE, bf);
        SelectObject(mdc, old); DeleteDC(mdc);
    }
}
void ControllerApp::lock_cursor()
{
    cursor_locked = true;
    SetWindowTextW(hLockLabel, L"CURSOR LOCKED  |  ESC to unlock");
    RECT cr; GetWindowRect(hCanvas, &cr);
    pin_cx = (cr.left + cr.right) / 2; pin_cy = (cr.top + cr.bottom) / 2;
    warp_pending.fetch_add(1); SetCursorPos(pin_cx, pin_cy);
    double rW = frameSrcW > 0 ? (double)frameSrcW : 1920.0, rH = frameSrcH > 0 ? (double)frameSrcH : 1080.0;
    double ax = std::max(0.0, std::min(rW - 1, cursorRatX * rW));
    double ay = std::max(0.0, std::min(rH - 1, cursorRatY * rH));
    vCursorX = ax / rW; vCursorY = ay / rH;
    if (input_conn && input_conn->running)
        input_conn->send_mouse((int16_t)ax, (int16_t)ay, "warp");
    ShowCursor(FALSE);
    start_listeners();
}

static std::atomic<bool> g_hook_ctrl{ false }, g_hook_shift{ false }, g_hook_alt{ false };

void ControllerApp::unlock_cursor()
{
    if (!cursor_locked) return;
    cursorRatX = vCursorX; cursorRatY = vCursorY;
    cursor_locked = false;
    if (hLockLabel) SetWindowTextW(hLockLabel, L"Click stream to lock cursor  |  ESC to unlock");
    ShowCursor(TRUE);
    stop_listeners();
    g_hook_ctrl = g_hook_shift = g_hook_alt = false;
}

static bool ui_has_focus()
{
    if (!g_app) return false;
    if (g_app->hSessionWnd && IsWindowVisible(g_app->hSessionWnd)) return false;
    HWND f = GetFocus();
    return f == g_app->hRcEditIP || f == g_app->hRcEditName;
}

static LRESULT CALLBACK LowLevelKeyboardProc(int code, WPARAM wp, LPARAM lp)
{
    if (code == HC_ACTION && g_app && g_app->cursor_locked && g_app->input_conn) {
        KBDLLHOOKSTRUCT* ks = reinterpret_cast<KBDLLHOOKSTRUCT*>(lp);
        bool dn = (wp == WM_KEYDOWN || wp == WM_SYSKEYDOWN);
        bool up = (wp == WM_KEYUP || wp == WM_SYSKEYUP);
        DWORD vk = ks->vkCode;
        if (vk == VK_CONTROL || vk == VK_LCONTROL || vk == VK_RCONTROL) g_hook_ctrl = dn;
        if (vk == VK_SHIFT || vk == VK_LSHIFT || vk == VK_RSHIFT)       g_hook_shift = dn;
        if (vk == VK_MENU || vk == VK_LMENU || vk == VK_RMENU)          g_hook_alt = dn;
        if (dn || up) {
            if (vk == VK_ESCAPE && g_hook_ctrl && g_hook_shift) {
                if (!ui_has_focus()) { g_app->input_conn->send_key(VK_CONTROL, dn); g_app->input_conn->send_key(VK_SHIFT, dn); g_app->input_conn->send_key(VK_ESCAPE, dn); }
                return 1;
            }
            if (vk == VK_DELETE && g_hook_ctrl && g_hook_alt) {
                if (!ui_has_focus()) { g_app->input_conn->send_key(VK_CONTROL, dn); g_app->input_conn->send_key(VK_MENU, dn); g_app->input_conn->send_key(VK_DELETE, dn); }
                return 1;
            }
            if (vk == VK_TAB && g_hook_alt) {
                if (!ui_has_focus()) { g_app->input_conn->send_key(VK_MENU, dn); g_app->input_conn->send_key(VK_TAB, dn); }
                return 1;
            }
            if (vk == VK_ESCAPE && dn) {
                HWND hw = g_app->hSessionWnd ? g_app->hSessionWnd : g_app->hWnd;
                PostMessageW(hw, WM_KEYDOWN, VK_ESCAPE, 0); return 1;
            }
            if (vk == VK_F12 && dn) {
                PostMessageW(g_app->hSessionWnd ? g_app->hSessionWnd : g_app->hWnd,
                    WM_COMMAND, MAKEWPARAM(ID_BTN_DEBUG, BN_CLICKED), 0); return 1;
            }
            if (vk == VK_LWIN || vk == VK_RWIN) { if (!ui_has_focus())g_app->input_conn->send_key(vk, dn); return 1; }
            if (!ui_has_focus()) g_app->input_conn->send_key(vk, dn);
        }
    }
    return CallNextHookEx(NULL, code, wp, lp);
}

static LRESULT CALLBACK RawInputWndProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == WM_INPUT && g_app) { g_app->handle_raw_input(lp); return 0; }
    return DefWindowProcW(hw, msg, wp, lp);
}

void ControllerApp::start_listeners()
{
    if (raw_running) return;
    raw_running = true; warp_pending = 0;
    kb_hook = SetWindowsHookExW(WH_KEYBOARD_LL, LowLevelKeyboardProc, NULL, 0);
    raw_thread = std::thread(&ControllerApp::raw_input_loop, this);
}

void ControllerApp::stop_listeners()
{
    if (kb_hook) { UnhookWindowsHookEx(kb_hook); kb_hook = NULL; }
    raw_running = false; warp_pending = 0;
    HWND rh = raw_hwnd;
    if (rh) PostMessageW(rh, WM_QUIT, 0, 0);
    if (raw_thread.joinable()) raw_thread.join();
    raw_hwnd = NULL;
}

void ControllerApp::raw_input_loop()
{
    wchar_t CLS[64]; swprintf_s(CLS, L"SRDT_RawSink_%u", GetCurrentThreadId());
    WNDCLASSEXW wc{}; wc.cbSize = sizeof(wc); wc.lpfnWndProc = RawInputWndProc;
    wc.hInstance = hInst; wc.lpszClassName = CLS;
    RegisterClassExW(&wc);
    HWND hw = CreateWindowExW(0, CLS, NULL, 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, hInst, NULL);
    if (!hw) { UnregisterClassW(CLS, hInst); return; }
    raw_hwnd = hw;
    RAWINPUTDEVICE rid{}; rid.usUsagePage = 0x01; rid.usUsage = 0x02;
    rid.dwFlags = RIDEV_INPUTSINK; rid.hwndTarget = hw;
    RegisterRawInputDevices(&rid, 1, sizeof(rid));
    MSG m{};
    while (GetMessageW(&m, NULL, 0, 0) > 0) { TranslateMessage(&m); DispatchMessageW(&m); }
    rid.dwFlags = RIDEV_REMOVE; rid.hwndTarget = NULL;
    RegisterRawInputDevices(&rid, 1, sizeof(rid));
    DestroyWindow(hw); raw_hwnd = NULL;
    UnregisterClassW(CLS, hInst);
}

void ControllerApp::handle_raw_input(LPARAM lp)
{
    if (!cursor_locked || !input_conn) return;
    UINT sz = 0;
    GetRawInputData((HRAWINPUT)lp, RID_INPUT, NULL, &sz, sizeof(RAWINPUTHEADER));
    if (sz == 0) return;
    std::vector<uint8_t>buf(sz);
    if (GetRawInputData((HRAWINPUT)lp, RID_INPUT, buf.data(), &sz, sizeof(RAWINPUTHEADER)) != sz) return;
    RAWINPUT* ri = (RAWINPUT*)buf.data();
    if (ri->header.dwType != RIM_TYPEMOUSE) return;
    RAWMOUSE& rm = ri->data.mouse;
    int dx = rm.lLastX, dy = rm.lLastY;
    if (dx || dy) {
        if (warp_pending.load() > 0) warp_pending.fetch_sub(1);
        else {
            dbg_raw_events++; dbg_last_dx = dx; dbg_last_dy = dy;
            int16_t ix = (int16_t)std::max(-32767, std::min(32767, (int)(dx * MOUSE_SPEED)));
            int16_t iy = (int16_t)std::max(-32767, std::min(32767, (int)(dy * MOUSE_SPEED)));
            if (ix || iy) {
                input_conn->send_mouse(ix, iy, "rel "); dbg_pkts_sent++;
                double rW = frameSrcW > 0 ? (double)frameSrcW : 1920.0, rH = frameSrcH > 0 ? (double)frameSrcH : 1080.0;
                double ax = std::max(0.0, std::min(rW - 1, vCursorX * rW + ix));
                double ay = std::max(0.0, std::min(rH - 1, vCursorY * rH + iy));
                vCursorX = ax / rW; vCursorY = ay / rH;
            }
            if (hCanvas) { RECT cr; GetWindowRect(hCanvas, &cr); pin_cx = (cr.left + cr.right) / 2; pin_cy = (cr.top + cr.bottom) / 2; }
            warp_pending.fetch_add(1); SetCursorPos(pin_cx, pin_cy);
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
        SHORT raw = (SHORT)rm.usButtonData; int ticks = raw / WHEEL_DELTA;
        char sb[8]; snprintf(sb, sizeof(sb), "%+d", ticks);
        input_conn->send_mouse(0, 0, "scro", sb);
    }
}

void ControllerApp::fwd_key(WPARAM vk, bool dn)
{
    if (!cursor_locked || !input_conn) return;
    if (vk == VK_ESCAPE || vk == VK_F12) return;
    if (ui_has_focus()) return;
    input_conn->send_key((uint32_t)vk, dn);
}

static HWND hDbgLabels[16] = {}, hDbgVals[16] = {};
static constexpr int DBG_ROWS = 15;
static const wchar_t* DBG_NAMES[] = {
    L"Cursor locked",L"Warp count",L"Raw events",L"Mouse pkts sent",
    L"Last dx/dy",L"Stream FPS",L"Frames rendered",L"Pin centre",
    L"Lock rect",L"Video conn",L"Input conn",L"Raw HWND",
    L"Raw thread",L"Recv FPS(EMA)",L"Throughput"
};

static LRESULT CALLBACK DebugWndProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE: {
        HFONT hf = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, FIXED_PITCH | FF_DONTCARE, L"Consolas");
        int y = 28;
        for (int i = 0; i < DBG_ROWS; i++, y += 18) {
            hDbgLabels[i] = CreateWindowW(L"STATIC", DBG_NAMES[i], WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX, 5, y, 160, 16, hw, NULL, NULL, NULL);
            SendMessage(hDbgLabels[i], WM_SETFONT, (WPARAM)hf, TRUE);
            hDbgVals[i] = CreateWindowW(L"STATIC", L"-", WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX, 170, y, 220, 16, hw, NULL, NULL, NULL);
            SendMessage(hDbgVals[i], WM_SETFONT, (WPARAM)hf, TRUE);
        }
        HWND hR = CreateWindowW(L"BUTTON", L"Reset", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 5, y, 80, 22, hw, (HMENU)1, NULL, NULL);
        SendMessage(hR, WM_SETFONT, (WPARAM)hf, TRUE);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == 1 && g_app) { g_app->dbg_raw_events = 0; g_app->dbg_pkts_sent = 0; g_app->dbg_frames = 0; g_app->dbg_fps = 0; }
        return 0;
    case WM_CLOSE: if (g_app) g_app->toggle_debug(); return 0;
    }
    return DefWindowProcW(hw, msg, wp, lp);
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
        WNDCLASSEXW wc{}; wc.cbSize = sizeof(wc); wc.lpfnWndProc = DebugWndProc;
        wc.hInstance = hInst; wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = L"RDDebugCls"; RegisterClassExW(&wc);
        hDebugWin = CreateWindowExW(WS_EX_TOPMOST, L"RDDebugCls", L"Debug",
            WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
            50, 50, 420, 32 + DBG_ROWS * 18 + 36, NULL, NULL, hInst, NULL);
        HWND hT = CreateWindowW(L"STATIC", L"CONTROLLER DEBUG",
            WS_CHILD | WS_VISIBLE | SS_CENTER | SS_NOPREFIX, 0, 0, 400, 22, hDebugWin, NULL, NULL, NULL);
        HFONT hfB = CreateFontW(14, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, FIXED_PITCH | FF_DONTCARE, L"Consolas");
        SendMessage(hT, WM_SETFONT, (WPARAM)hfB, TRUE);
        update_debug();
    }
}

void ControllerApp::update_debug()
{
    if (!debugVisible || !hDebugWin) return;
    double now = (double)GetTickCount64() / 1000.0, el = now - dbg_fps_time;
    if (el >= 1.0) { dbg_fps = dbg_frame_tick / el; dbg_frame_tick = 0; dbg_fps_time = now; }
    auto sv = [](int i, const std::wstring& s) {if (hDbgVals[i])SetWindowTextW(hDbgVals[i], s.c_str()); };
    auto b = [](bool v)->std::wstring {return v ? L"True" : L"False"; };
    sv(0, b(cursor_locked)); sv(1, std::to_wstring(warp_pending.load()));
    sv(2, std::to_wstring((long)dbg_raw_events)); sv(3, std::to_wstring((long)dbg_pkts_sent));
    { std::wostringstream ss; ss << L"dx=" << dbg_last_dx.load() << L"  dy=" << dbg_last_dy.load(); sv(4, ss.str()); }
    { std::wostringstream ss; ss << std::fixed << std::setprecision(1) << dbg_fps; sv(5, ss.str()); }
    sv(6, std::to_wstring((long)dbg_frames));
    { std::wostringstream ss; ss << L"(" << pin_cx << L"," << pin_cy << L")"; sv(7, ss.str()); }
    sv(8, L"(tracked)");
    sv(9, (video_conn && video_conn->running) ? L"connected" : L"none");
    sv(10, (input_conn && input_conn->running) ? L"connected" : L"none");
    sv(11, raw_hwnd ? L"active" : L"None");
    sv(12, b(raw_running.load()));
    { std::wostringstream ss; ss << std::fixed << std::setprecision(1) << Core_BwMeasuredFps() << L" fps" << (Core_BwIsCongested() ? L"  [CONGESTED]" : L""); sv(13, ss.str()); }
    { std::wostringstream ss; ss << Core_BwThroughputBps() / 1000 << L" kbps"; sv(14, ss.str()); }
    if (debugVisible)
        SetTimer(hDebugWin, 1, 200, [](HWND, UINT, UINT_PTR, DWORD) {if (g_app)g_app->update_debug(); });
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int)
{
    {
        wchar_t exePath[MAX_PATH] = {};
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        if (wchar_t* sl = wcsrchr(exePath, L'\\')) *(sl + 1) = L'\0';
        wcscat_s(exePath, MAX_PATH, L"core");
        SetDllDirectoryW(exePath);
    }

    Gdiplus::GdiplusStartupInput gsi;
    ULONG_PTR gToken;
    Gdiplus::GdiplusStartup(&gToken, &gsi, NULL);

    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
    INITCOMMONCONTROLSEX icc{ sizeof(icc),ICC_WIN95_CLASSES };
    InitCommonControlsEx(&icc);

    ControllerApp app;
    if (!app.init(hInst)) {
        MessageBoxW(NULL, L"Failed to initialise window.", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }
    app.run();
    app.destroy();

    WSACleanup();
    Gdiplus::GdiplusShutdown(gToken);
    return 0;
}