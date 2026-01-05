# Splunk SIEM – Brute Force Detection Lab

## 📌 Project Overview
This project demonstrates the setup and operation of a **Security Information and Event Management (SIEM)** system using **Splunk Enterprise**. The objective was to simulate a **real-world SOC monitoring scenario** by ingesting Windows logs, detecting suspicious authentication activity, and generating alerts based on security events.

The lab focuses on **brute-force login detection**, a core responsibility of entry-level SOC analysts.

---

## 🧱 Architecture
- **Splunk Enterprise** – SIEM platform for log ingestion, search, alerting, and dashboards  
- **Splunk Universal Forwarder** – Agent used to collect and forward Windows logs  
- **Windows Endpoint** – Log source (Security, System, Application logs)

Logs were forwarded locally using TCP port **9997**.

---

## 🔍 Data Sources
The following Windows Event Logs were ingested:
- **Security**
- **System**
- **Application**

Primary security focus:
- Failed authentication attempts
- Suspicious login behavior

---

## 🚨 Detection Use Case: Brute Force Authentication Attempt

### Description
A brute-force authentication attempt was simulated by generating multiple failed login attempts on a Windows system. These events were captured by Splunk and analyzed using Windows **Event ID 4625**.

### Detection Logic
```spl
index=* EventCode=4625
| stats count by Account_Name
| where count > 5
