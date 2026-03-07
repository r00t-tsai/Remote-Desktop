<div align="center">
<img width="300" height="300" alt="logo" src="https://github.com/user-attachments/assets/842f0a24-15e5-4476-9ac3-24b7faff5bc7" />
</div>

<div align="center">
  <h1>Simple Remote Desktop</h1>
</div>
A lightweight remote desktop application built entirely in C++ for Windows. It allows you to view the screen, listen to audio playbacks, and control the mouse and keyboard of another machine over WAN/LAN. 

## Building
### Compiler: Microsoft Visual C++ (MSVC) is highly recommended.

## Usage Instructions:
- CONNECT TO A DEVICE
1.  Open the app, select Connect to Device.
2.  Configure the IP/domain, video/audio/input ports of the host.
3.  Enter the encryption key of the host, leave it blank if it is unencrypted.
5.  Click Connect to Desktop.

- HOSTING THE CONNECTION
1. Open the app, select Host RDP Connection.
2. Configure the video/audio/input port numbers.
3. If the controller/operator is on a different network, tick the WAN Mode box, otherwise leave it unticked.
4. Enter the encryption key for your private connection.
5. Click Start Host.
> Side Note: If on WAN Mode, your router must be configured to do Port Forwarding. The Program assumes this condition and will spit errors if this condition is not met.
> ## TO-DO LIST for v1.1.4
> 
> * Implement support for UAC Popups and Windows Security Screen

<div align="center">
  <video src="https://github.com/user-attachments/assets/2a1bee6e-d966-4a84-b1d4-9d6f2e521f3b" width="800" controls></video>
  <p><i>Demonstration v1.1.2</i></p>
</div>
