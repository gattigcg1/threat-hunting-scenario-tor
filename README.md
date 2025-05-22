<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/gattigcg1/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

A search of the DeviceFileEvents table in MDE was conducted that checked to see if any FileName had “tor” in the last 7 days. It appears that a TOR installation exe was discovered to have been downloaded by the user ‘gattigcg1’. Also there is activity related to creating a text file titled ‘tor-shopping-list.txt’. These events began at: 2025-05-08T17:46:07.9550548Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "vm-windows-10" and FileName contains "tor"
| where InitiatingProcessAccountName == "gattigcg1"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
![image](https://github.com/user-attachments/assets/60de2bf3-5478-431e-b20a-3fd4324db3c8)

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that referenced ‘tor-browser-windows-x86_64-portable-14.5.1.exe’. Based on the logs, at 2025-05-09T22:55:45.5353055Z, a process for the Tor Browser portable executable was created from the user's downloads folder on a Windows 10 virtual machine, initiated with a silent installation command. 

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "vm-windows-10" and  ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.1.exe"
| where InitiatingProcessAccountName == "gattigcg1"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/64bd109e-d559-47d2-8280-9b45bb071aa4)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any evidence that user ‘gattigcg1’ opened the tor browser, and found said evidence in the logs at 2025-05-09T23:07:38.3917564Z. Used this query: 

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "vm-windows-10" and InitiatingProcessAccountName == "gattigcg1"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project  Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/d2e83aeb-940e-4a77-8b6e-49e84d6418f1)

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searching DeviceNetworkEvents for network activity involving tor browser. For device "vm-windows-10", logs reveal successful outbound connections primarily on ports 443 and 4443, a failed connection on port 9000, and local listening connections by "tor.exe", a successful connection was first detected from “firefox.exe” through port 9151 at 2025-05-09T22:56:40.3203592Z and port 9150 at 2025-05-09T22:57:07.2029984Z. 

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "vm-windows-10" and InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/d098fa29-5daf-45b9-9972-345136ef0693)

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-05-08T17:46:07.9550548Z`
- **Event:** The user "gattigcg1" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** The Tor installation executable was downloaded.
- **File Path:** `C:\Users\gattigcg1\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

- ### 2. File Creation - TOR Shopping List

- **Timestamp:** `2025-05-08T17:44:21.5073428Z`
- **Event:** The user "gattigcg1" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** A text file titled tor-shopping-list.txt was created.
- **File Path:** `C:\Users\gattigcg1\Desktop\tor-shopping-list.txt`

### 3. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-05-09T22:55:45.5353055Z`
- **Event:** The user "gattigcg1" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 4. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-05-09T23:07:38.3917564Z`
- **Event:** User "gattigcg1" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\gattigcg1\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 5. Network Activity - Device Network Events

- **Timestamp:** `2025-05-09T22:56:40.3203592Z`
- **Event:** A network connection on port `9151` and `9150` by user "gattigcg1" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 6. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-05-09T22:56:40.3203592Z` - Connected on port `9151`.
  - `2025-05-09T22:57:07.2029984Z` - Connected on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "gattigcg1" through the TOR browser.
- **Action:** Multiple successful connections detected.

---

## Summary

The investigation revealed that the user "gattigcg1" downloaded a Tor installation executable on May 8, 2025, and subsequently created a text file named tor-shopping-list.txt. On May 9, 2025, the user executed the Tor Browser with a silent installation command and later opened it, generating network activity primarily on ports 443 and 9151, indicative of Tor usage.

---

## Response Taken

TOR usage was confirmed on the endpoint `vm-windows-10` by the user `gattigcg1`. The device was isolated, and the user's direct manager was notified.

---
