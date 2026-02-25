[README.md](https://github.com/user-attachments/files/25537534/README.md)
# 🛡️ Windows Security Hardening & Performance Optimizer

A PowerShell script that automates common Windows security hardening tasks and system performance optimizations. Built for IT support, cybersecurity learning, and helping everyday users secure and speed up their Windows machines.

> ⚠️ Must be run as Administrator. Tested on Windows 10 and Windows 11.

---

## 📋 Features

### 🔒 Security Hardening
| Task | What It Does |
|------|-------------|
| Firewall | Enables Windows Firewall on all profiles (Domain, Private, Public) |
| Windows Defender | Ensures real-time protection is active |
| Disable RDP | Turns off Remote Desktop to reduce attack surface |
| Disable SMBv1 | Removes the legacy protocol exploited by WannaCry ransomware |
| Reduce Telemetry | Sets Windows data collection to minimum |
| Disable AutoRun | Prevents malware from auto-executing via USB or disc |
| Windows Updates | Checks for and flags any pending security updates |
| UAC Check | Verifies User Account Control is enabled |
| Admin Audit | Lists local administrator accounts for review |

### ⚡ Performance Optimization
| Task | What It Does |
|------|-------------|
| Power Plan | Sets system to High Performance mode |
| Visual Effects | Adjusts animations for best performance |
| Temp File Cleanup | Clears system and user temp folders |
| DNS Flush | Clears DNS cache to fix slow/broken connections |
| Network Reset | Releases, renews IP and resets Winsock |
| Startup Audit | Lists startup programs slowing down boot time |
| SysMain | Disables Superfetch (recommended for SSD systems) |

---

## 🚀 How to Use

### 1. Download the script
Click the green **Code** button above and select **Download ZIP**, or clone the repo:
```bash
git clone https://github.com/yourusername/windows-optimizer.git
```

### 2. Open PowerShell as Administrator
- Press `Windows + S` and search for **PowerShell**
- Right-click and select **Run as Administrator**

### 3. Allow script execution (first time only)
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 4. Navigate to the script folder and run it
```powershell
cd C:\path\to\windows-optimizer
.\Optimize-Windows.ps1
```

### 5. Choose your mode
The script will prompt you to select:
- `1` — Security Hardening Only
- `2` — Performance Optimization Only
- `3` — Full (Security + Performance)

---

## 📸 Example Output

```
============================================================
   Windows Security Hardening & Performance Optimizer
============================================================

[*] Enabling Windows Firewall on all profiles...
[+] Firewall enabled on all profiles.
[*] Enabling Windows Defender real-time protection...
[+] Windows Defender real-time protection is ON.
[*] Disabling Remote Desktop Protocol (RDP)...
[+] RDP disabled.
...
============================================================
 All tasks completed. A restart may be required for some
 changes to take effect.
============================================================
```

---

## ⚙️ Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 or later (built into Windows)
- Administrator privileges

---

## 🔁 Restart Required?

Some changes require a restart to fully take effect, including:
- RDP disable
- SMBv1 disable
- Network stack reset

---

## 📚 What I Learned Building This

This project gave me hands-on experience with:
- **PowerShell scripting** — functions, error handling, registry edits, service management
- **Windows security concepts** — attack surface reduction, firewall management, legacy protocol risks
- **Network troubleshooting** — DNS, IP renewal, Winsock reset
- **System administration** — startup management, power plans, service configuration

---

## 🤝 Contributing

Pull requests are welcome. If you have a hardening task or optimization you'd like added, open an issue or submit a PR.

---

## 📄 License

MIT License — free to use, modify, and share.

---

*Built by Patrick Moreno 
