# Simple C++ Remote Desktop
A lightweight remote desktop application built entirely in C++ for Windows. It allows you to view the screen and control the mouse and keyboard of another machine over WAN/LAN.

## Components
### Host
* Listens for incoming connections on TCP ports 55000 (video) and 55001 (input).
* Streams the desktop using GDI+ JPEG compression.
* Injects received mouse and keyboard commands into the system.

### Dashboard Client
* GUI to enter the target Host IP and your connection name.
* Uses Raw Input and Low-Level Keyboard Hooks to capture your mouse and keystrokes and sends them to the client.
* Exports Host configuration settings.

## Building
### Compiler: Microsoft Visual C++ (MSVC) is highly recommended.
#### Libraries:
*  `ws2_32.lib, gdi32.lib, gdiplus.lib, user32.lib ` will automatically link if you compile with MSVC.
#### CPP Standard: 
* `std::thread, std::mutex, and std::atomic.` found in C++14 (C++17 recommended).

## Usage Instructions:
### 1. Open the Dashboard Client app
### 2. Configure the video/input ports
### 3. Check WAN Discovery if the Host machine is on a different network, otherwise leave it to LAN.
### 4. OPTIONAL Encryption Passphrase to encrypt the data sent through the network.
### 5. Export the settings.dat and place it in the same directory as the host program in the host machine.
### 6. Start the host program and connect the Dashboard to it.

<div align="center">
  <video src="https://github.com/user-attachments/assets/826a084e-be17-4036-846a-01234cc155e5" width="800" controls></video>
  <p><i>Demo: Controlling a Remote Desktop Session</i></p>
</div>
