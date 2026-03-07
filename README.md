<div align="center">
<img width="300" height="300" alt="logo" src="https://github.com/user-attachments/assets/842f0a24-15e5-4476-9ac3-24b7faff5bc7" />
</div>

<div align="center">
  <h1>Simple C++ Remote Desktop Protocol</h1>
</div>
A lightweight remote desktop application built entirely in C++ for Windows. It allows you to view the screen, listen to audio playbacks, and control the mouse and keyboard of another machine over WAN/LAN. 

This is one of my side projects back then that I forgot to upload when I was still in college practicing networking. This is not production-ready but only a proof-of-concept program that 100% works on private communication scenarios.

## Components
### Host
* Listens for incoming connections on TCP ports 55000 (video) and 55001 (input). These values are the default ones, you can configure those yourself.
* Streams the desktop using GDI+ JPEG compression.
* Injects received mouse and keyboard commands into the system.
* Captures audio stream directly from the default playback device.

### Dashboard Client
* GUI to enter the target Host IP and your connection name.
* Uses Raw Input and Low-Level Keyboard Hooks to capture your mouse and keystrokes and sends them to the host program.
* Exports Host configuration settings.
* Takes the audio data streamed from the Host and plays it through the speakers using Windows multimedia APIs.

> ## TO-DO LIST for v1.1.4
> 
> * Implement support for UAC Popups and Windows Security Screen

## Building
### Compiler: Microsoft Visual C++ (MSVC) is highly recommended.
#### Libraries:
*  `ws2_32.lib, gdi32.lib, gdiplus.lib, user32.lib ` will automatically link if you compile with MSVC.
#### CPP Standard: 
* `std::thread, std::mutex, and std::atomic.` found in C++14 (C++17 recommended).

## Usage Instructions:
1.  Open the Dashboard Client app
2.  Configure the video/audio/input ports
3.  Check WAN Discovery if the Host machine is on a different network, otherwise leave it to LAN.
4.  OPTIONAL: Encryption Passphrase to encrypt the data sent through the network.
5.  Export the settings.dat and place it in the same directory as the host program in the host machine.
6.  Start the host program and connect the Dashboard to it.


<div align="center">
  <video src="https://github.com/user-attachments/assets/2a1bee6e-d966-4a84-b1d4-9d6f2e521f3b" width="800" controls></video>
  <p><i>Demonstration v1.1.2</i></p>
</div>
