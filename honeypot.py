import socket
import logging
import tkinter as tk
from tkinter import scrolledtext
import re
import threading

# Configure logging
logging.basicConfig(filename="honeypot.log", level=logging.INFO,
                    format="%(asctime)s - %(message)s")

running = False
sock = None

def detect_attack(data):
    patterns = {
        "SQL Injection": re.compile(r"(UNION|SELECT|DROP|INSERT|UPDATE|DELETE).*", re.IGNORECASE),
        "XSS Attack": re.compile(r"(<script>.*</script>)", re.IGNORECASE),
        "Directory Traversal": re.compile(r"(\.\.\/|\.\.\\)", re.IGNORECASE),
        "Brute Force Login": re.compile(r"(password|123456|admin|root)", re.IGNORECASE),
        "Port Scanning": re.compile(r"(nmap|masscan|zmap)", re.IGNORECASE),
        "Malware Infection": re.compile(r"(trojan|virus|worm|ransomware)", re.IGNORECASE),
        "Spam Emails": re.compile(r"(viagra|free money|lottery win|click here)", re.IGNORECASE),
        "Botnet Activity": re.compile(r"(botnet|command and control|c2)", re.IGNORECASE),
        "Unauthorized Access": re.compile(r"(unauthorized|illegal access|hacker)", re.IGNORECASE),
        "Data Exfiltration": re.compile(r"(export|transfer|exfiltrate|leak)", re.IGNORECASE),
        "New Exploits": re.compile(r"(zero-day|exploit|buffer overflow|privilege escalation)", re.IGNORECASE)
    }
    
    for attack, pattern in patterns.items():
        if pattern.search(data):
            return attack
    return None

def honeypot_listener(port):
    global running, sock
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("0.0.0.0", port))
    sock.listen(5)
    log_text.insert(tk.END, f"Honeypot started on port {port}\n")
    logging.info(f"Honeypot started on 0.0.0.0:{port}")
    
    while running:
        conn, addr = sock.accept()
        log_text.insert(tk.END, f"Connection attempt from {addr}\n")
        logging.info(f"Connection attempt from {addr}")
        
        try:
            data = conn.recv(1024).decode("utf-8")
            if data:
                attack_type = detect_attack(data)
                if attack_type:
                    log_text.insert(tk.END, f"Possible {attack_type} detected from {addr}\n")
                    logging.info(f"Possible {attack_type} detected from {addr}: {data}")
                
            conn.send(b"Access denied! This incident has been reported.\n")
        except Exception as e:
            logging.error(f"Error handling connection from {addr}: {str(e)}")
        
        conn.close()

def start_honeypot():
    global running
    if not running:
        running = True
        port = int(port_entry.get())
        threading.Thread(target=honeypot_listener, args=(port,), daemon=True).start()

def stop_honeypot():
    global running, sock
    running = False
    if sock:
        sock.close()
        log_text.insert(tk.END, "Honeypot stopped.\n")
        logging.info("Honeypot stopped.")

def exit_application():
    stop_honeypot()
    root.destroy()

# GUI Setup
root = tk.Tk()
root.title("Honeypot GUI")

tk.Label(root, text="Enter Port:").pack()
port_entry = tk.Entry(root)
port_entry.pack()

start_button = tk.Button(root, text="Start Honeypot", command=start_honeypot)
start_button.pack()

stop_button = tk.Button(root, text="Stop Honeypot", command=stop_honeypot)
stop_button.pack()

exit_button = tk.Button(root, text="Exit", command=exit_application)
exit_button.pack()

log_text = scrolledtext.ScrolledText(root, width=50, height=10)
log_text.pack()

root.mainloop()