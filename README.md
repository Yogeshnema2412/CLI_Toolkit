# 🛡️ CLI_Toolkit - CyberSec MultiTool 

**CyberSec MultiTool** is an all-in-one Python-based cybersecurity toolkit designed for **ethical hackers, cybersecurity students, and red teamers**. This CLI-based suite contains multiple tools to perform **network reconnaissance**, **SQL injection testing**, **web scraping**, **brute force attacks**, and more—strictly for educational and authorized testing environments.

---

## 🧠 Modules Included

| Module                     | Description                                                              |
|----------------------------|--------------------------------------------------------------------------|
| 🔍 Network Scanner         | Scans a given network for active hosts and open ports (uses Scapy + Sockets) |
| 🔓 Directory Bruteforcer   | Discovers hidden directories using a wordlist                            |
| 🔐 Login Bruteforcer       | Attempts brute-force login on web forms using username/password files    |
| 🧱 SQL Injection Scanner   | Tests for SQLi vulnerabilities using common payloads                     |
| 🌐 Web Scraper             | Extracts titles and links from target web pages using BeautifulSoup      |

---

## 📁 File Structure

CyberSec-MultiTool/
│
├── mega_project.py # Main orchestrator with CLI menu
├── network_scan.py # Network & port scanning utility
├── sql_map.py # SQL injection testing module
├── web_scrap.py # Web scraping module
├── web_brout.py # Login brute force script
├── brout_forcing.py # Directory brute force script
├── requirements.txt # All Python dependencies
└── README.md # You are here!


---

## ⚙️ Requirements

- Python 3.7+
- `requests`, `beautifulsoup4`, `scapy`

Install dependencies:

```bash
pip install -r requirements.txt
```
##Features To Add


 GUI version using Tkinter or PyQt

 Logging system for results

 Multi-threaded scanning

 Proxy and Tor support

 
##⚖️ Disclaimer

This project is built for educational purposes only. Do not use it on unauthorized systems or websites. Misuse can be illegal under cybersecurity laws. Always obtain permission before testing any target.

