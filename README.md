# Simple C++ Remote Desktop
A lightweight remote desktop application built entirely in C++ for Windows. It allows you to view the screen and control the mouse and keyboard of another machine over a local network.

## Components
### Client
* Listens for incoming connections on TCP ports 55000 (video) and 55001 (input).
* Streams the desktop using GDI+ JPEG compression.
* Injects received mouse and keyboard commands into the system.

### Dashboard
* Provides a GUI to enter the target Host IP and your connection name.
* Displays the incoming desktop stream.
* Uses Raw Input and Low-Level Keyboard Hooks to capture your mouse and keystrokes seamlessly and forward them to the host.

## Building
### Compiler: Microsoft Visual C++ (MSVC) is highly recommended.
#### Libraries:
*  `ws2_32.lib, gdi32.lib, gdiplus.lib, user32.lib ` will automatically link if you compile with MSVC.
#### CPP Standard: 
* `std::thread, std::mutex, and std::atomic.` found in C++14 (C++17 recommended).
<div align="center">
  <video src="https://github.com/user-attachments/assets/826a084e-be17-4036-846a-01234cc155e5" width="800" controls></video>
</div>
