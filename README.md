# ITSOLERA SOC Internship — Task 04: Agent Tesla Malware Analysis & Incident Response

**Programme:** ITSOLERA Cybersecurity (SOC) Winter Internship  
**Task:** 04 — Advanced Malware Analysis and Incident Response  
**Prepared by:** Rahul Kumar  
**Team:** Epsilon  
**Organization:** IT Solera Pvt. Ltd.  
**Date:** 24 March 2026  

## Objective

Analyse an Agent Tesla information stealer with static, dynamic and hybrid techniques in a controlled VM, compare the findings with public reporting, and produce detections, MITRE ATT&CK mapping and an incident response plan.

## Sample overview

| Attribute | Value |
|---|---|
| Malware | Agent Tesla (InfoStealer) |
| File name | `Invoice.exe` |
| Size | 1,138,688 bytes |
| Type | PE32, 32-bit GUI executable |
| Compiler/packer | Visual Studio 2017 C++ with AutoIt wrapper |
| MD5 | `269688cb4c25e741534e9c1f39fcb741` |
| SHA-1 | `45c2f9033272e5b903434caaab0995f342345851` |
| SHA-256 | `f5df30356e96faf9cd78beb315949553bc8956c13298a0633c821ff4fa4caa9e` |

The sample came from MalwareBazaar and was handled as a password-protected archive. **No executable malware is included in this repository.**

## Lab and tooling

Windows 10 VM with a host-only adapter and no internet access. The analysis used 7-Zip, HashMyFiles, Detect It Easy, PEStudio, Sysinternals Strings, IDA Free, Process Explorer, Process Monitor, Regshot, FakeNet-NG, DumpIt and ANY.RUN for hybrid validation.

## Analysis findings

### Static

- `strings.exe` produced no useful output, and DIE identified an AutoIt-compiled, packed/obfuscated PE.
- PEStudio showed `.rsrc` entropy of `7.819`, strongly indicating an encrypted or packed payload.
- Suspicious imports included `WSOCK32.dll`, `WININET.dll`, `MPR.dll`, `AttachThreadInput`, `SetWindowsHookEx`, `GetAsyncKeyState`, `AdjustTokenPrivileges` and `CreateProcessAsUserW`.
- IDA Free showed unpacking loops, XOR/decryption routines and no readable .NET payload before execution.

### Dynamic

- Process count rose from 122 to 138 and commit charge from 46.25% to 59.71%.
- `Invoice.exe` spawned `RegSvcs.exe` (PID 5492), confirming process hollowing of a legitimate .NET utility.
- Regshot showed persistence through HKCU/HKLM Run keys, StartupApproved entries and a custom `.hivu` file-extension registration.
- Process Monitor showed more than 4.6 million events, heavy activity in `%AppData%\Local\Temp`, and scanning for browser `Login Data` and `Cookies` files.
- FakeNet-NG captured HTTP requests to `ip-api.com`, POSTs to `login.live.com`, and SMTP activity on port 587.
- A memory dump revealed the decrypted .NET payload, C2 configuration and staged stolen data.

### Hybrid

ANY.RUN confirmed Agent Tesla with high confidence and tagged behaviours `stealer`, `evasion`, `exfiltration`, `ftp` and `agenttesla`.

## Capabilities and MITRE mapping

- **Credential theft:** 50+ browsers, email clients, FTP/VPN clients and Discord.
- **Collection:** keylogging, clipboard capture and screenshots.
- **Evasion:** WMI virtualization checks, sandbox DLL checks, `IsDebuggerPresent`, timing checks, AutoIt packing.
- **Persistence:** Run keys, startup shortcuts, scheduled tasks or services in some variants.
- **Exfiltration:** SMTP 25/587, HTTP/HTTPS 80/443, FTP 21 and Telegram.
- **MITRE:** T1566.001, T1059.001, T1059.007, T1547.001, T1134.002, T1055.012, T1027.002, T1497.001, T1555.003, T1056.001, T1115, T1113, T1005, T1071.001, T1048.003.

## IOCs

- Domains: `ip-api.com`, `login.live.com`, `mail.taikei-rmc-co.biz`, `api.ipify.org`.
- Historical IPs: `185.62.189.43`, `173.231.16.76`, `185.198.59.26`.
- Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, `HKCU\...\FileExts\.hivu`.
- Processes: `RegSvcs.exe`, `RegAsm.exe` or `Aspnet_compiler.exe` with unusual parent processes.

A generic detection rule is provided in `iocs/agent_tesla.yar`.

## Incident response summary

Isolate the host, reset exposed credentials and block C2; terminate hollowed processes, delete Run keys and staged files; reimage where possible, scan with AV/EDR, restore clean backups and monitor for 30 days. Preventive controls include blocking execution from `%Temp%`/`%AppData%`, filtering `.jse`, `.rar` and `.iso` attachments, and running invoice-themed phishing simulations.

## Repository contents

- `Rahul_Kumar_Task_04_Report.pdf` and `.docx` — full analysis report.
- `Rahul_Kumar_Task_04_Brief.pdf` — original task instructions.
- `iocs/agent_tesla.yar` — generic YARA detection rule.
- `evidence/screenshots/` — 85 screenshots covering static analysis, dynamic behaviour and sandbox results.
