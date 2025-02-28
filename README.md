# 🛡️ Python HoneyPot
A lightweight Python-based Honeypot with a GUI interface that detects and logs potential cyber attacks. It simulates a vulnerable system to attract attackers and record malicious activities for analysis.

🚀 Features

Detects Common Attack Types: SQL Injection, XSS, Brute Force, Port Scanning, Malware, and more.
Logs Attack Attempts: Stores attacker IPs and patterns in honeypot.log.
GUI-Based Control: Start/Stop the honeypot and view logs in real-time.
Fake Response to Attackers: Sends a fake access denial message to deceive attackers.
Multi-Threaded: Runs in a background thread to keep the GUI responsive.

📌 Attack Vectors Detected:

Attack Type  |    Detection Mechanism

SQL Injection  |    Detects database queries (SELECT, DROP, INSERT) in user input. 

XSS (Cross-Site Scripting)  |    Identifies <script> tags used for JavaScript injection.

Directory Traversal  |    Matches ../ patterns attempting unauthorized access.

Brute Force Login  |    Detects weak passwords (admin, 123456, root).

Port Scanning  |    Flags scanning tools like nmap, masscan.

Malware Infection  |    Recognizes keywords (trojan, ransomware, virus).

Spam Emails  |    Detects spam-related words (free money, lottery win).

Botnet Activity  |    Identifies botnet communication (C2, command and control).

Unauthorized Access  |    Recognizes hacking attempts (illegal access, hacker).

Data Exfiltration  |    Detects data leaks (export, exfiltrate, leak).

New Exploits  |    Flags mentions of zero-day, buffer overflow, etc.

🛠️ Installation Guide:

1️⃣ Clone the Repository
 git clone https://github.com/yourusername/python-honeypot.git
 cd python-honeypot

2️⃣ Install Dependencies
Ensure you have Python 3 installed, then install required modules:
pip install -r requirements.txt
(If using system Python, use pip3 instead)

3️⃣ Run the Honeypot
python honeypot.py

🎮 Usage:
Enter a Port Number in the GUI.
Click Start Honeypot to begin listening for attacks.
Logs will display in the GUI Log Window and honeypot.log.
Click Stop Honeypot to stop listening.

🔍 Example Logs

2024-02-28 12:34:56 - Honeypot started on 0.0.0.0:8080
2024-02-28 12:35:12 - Connection attempt from ('192.168.1.50', 51234)
2024-02-28 12:35:13 - Possible SQL Injection detected from ('192.168.1.50', 51234): SELECT * FROM users WHERE username='admin' --

📖 How It Works

Opens a TCP server that listens for incoming connections.
Captures and inspects incoming data using re (regular expressions).
Identifies attack patterns and logs the events.
Responds to attackers with a fake denial message.
