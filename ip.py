import tkinter as tk
from tkinter import ttk, messagebox
import urllib.request
import json
import ipaddress
import socket
import ssl
import whois
import threading
import random
import requests
from ttkbootstrap import Style
import folium
import webbrowser
import os
from tkhtmlview import HTMLLabel

class IPLookupApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.style = Style(theme="superhero")
        self.title("🕵️ Cyber Sleuth: IP Detective 🌐")
        self.geometry("1000x800")
        
        self.colors = {
            "primary": "#2C3E50",
            "secondary": "#34495E",
            "accent": "#3498DB",
            "success": "#2ECC71",
            "warning": "#F1C40F",
            "danger": "#E74C3C"
        }
        
        self.create_sidebar()
        self.create_main_content()
        self.animate_title()
        
        self.search_history = []
        self.create_status_bar()

    def create_sidebar(self):
        self.sidebar = ttk.Frame(self, style='Secondary.TFrame')
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

        ttk.Label(self.sidebar, text="Recent Searches", font=("Roboto", 12, "bold")).pack(pady=10)
        self.history_listbox = tk.Listbox(self.sidebar, height=10, width=20)
        self.history_listbox.pack(pady=5)
        self.history_listbox.bind('<<ListboxSelect>>', self.load_from_history)

        ttk.Label(self.sidebar, text="Quick Actions", font=("Roboto", 12, "bold")).pack(pady=10)
        ttk.Button(self.sidebar, text="My IP", command=self.check_my_ip).pack(pady=5)
        ttk.Button(self.sidebar, text="Clear History", command=self.clear_history).pack(pady=5)
        ttk.Button(self.sidebar, text="Export Results", command=self.export_results).pack(pady=5)

    def create_main_content(self):
        main_frame = ttk.Frame(self)
        main_frame.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=10, pady=10)

        self.header = ttk.Label(main_frame, text="Cyber Sleuth: IP Detective", 
                              font=("Roboto", 24, "bold"), foreground="#FFD700")
        self.header.pack(pady=20)

        search_frame = ttk.Frame(main_frame)
        search_frame.pack(pady=10)

        ttk.Label(search_frame, text="🔍", font=("Roboto", 14)).pack(side=tk.LEFT, padx=5)
        
        self.ip_entry = ttk.Entry(search_frame, font=("Roboto", 12), width=25)
        self.ip_entry.pack(side=tk.LEFT, padx=5)
        self.ip_entry.insert(0, "Enter IP address...")
        self.ip_entry.bind('<FocusIn>', lambda e: self.on_entry_click())
        self.ip_entry.bind('<FocusOut>', lambda e: self.on_focus_out())

        search_button = ttk.Button(search_frame, text="Investigate", 
                                 command=self.start_investigation, 
                                 style="Accent.TButton")
        search_button.pack(side=tk.LEFT, padx=5)

        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        results_frame = ttk.Frame(self.notebook)
        self.notebook.add(results_frame, text="📊 Results")

        self.result_area = HTMLLabel(results_frame, html=self.get_welcome_message())
        self.result_area.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)

        self.map_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.map_frame, text="🗺️ Map")

        threat_frame = ttk.Frame(self.notebook)
        self.notebook.add(threat_frame, text="🛡️ Threat Intel")

        self.threat_area = HTMLLabel(threat_frame, html=self.get_threat_welcome_message())
        self.threat_area.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)

        self.progress = ttk.Progressbar(main_frame, orient=tk.HORIZONTAL, 
                                      length=700, mode='indeterminate',
                                      style="Striped.Horizontal.TProgressbar")
        self.progress.pack(pady=10)

        self.tip_frame = ttk.Frame(main_frame)
        self.tip_frame.pack(fill=tk.X, pady=10)
        self.tip_label = ttk.Label(self.tip_frame, text="", 
                                 font=("Roboto", 10, "italic"), 
                                 wraplength=700)
        self.tip_label.pack(pady=10)

    def create_status_bar(self):
        self.status_bar = ttk.Label(self, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def get_welcome_message(self):
        return """
        <div style='text-align: center; padding: 20px;'>
            <h1 style='color: #3498DB;'>Welcome to Cyber Sleuth: IP Detective</h1>
            <p style='color: #7F8C8D;'>Enter an IP address to begin your investigation</p>
            <div style='margin: 20px;'>
                <span style='font-size: 48px;'>🔍</span>
            </div>
        </div>
        """

    def get_threat_welcome_message(self):
        return """
        <div style='text-align: center; padding: 20px;'>
            <h1 style='color: #E74C3C;'>Threat Intelligence Center</h1>
            <p style='color: #7F8C8D;'>Investigate potential security threats</p>
            <div style='margin: 20px;'>
                <span style='font-size: 48px;'>🛡️</span>
            </div>
        </div>
        """

    def on_entry_click(self):
        if self.ip_entry.get() == 'Enter IP address...':
            self.ip_entry.delete(0, tk.END)
            self.ip_entry.config(foreground='black')

    def on_focus_out(self):
        if self.ip_entry.get() == '':
            self.ip_entry.insert(0, 'Enter IP address...')
            self.ip_entry.config(foreground='grey')

    def check_my_ip(self):
        try:
            response = requests.get('https://api.ipify.org?format=json')
            ip = response.json()['ip']
            self.ip_entry.delete(0, tk.END)
            self.ip_entry.insert(0, ip)
            self.start_investigation()
        except Exception as e:
            messagebox.showerror("Error", f"Could not retrieve your IP: {str(e)}")

    def clear_history(self):
        self.search_history.clear()
        self.history_listbox.delete(0, tk.END)
        messagebox.showinfo("Success", "Search history cleared!")

    def export_results(self):
        # TODO: Implement export functionality
        messagebox.showinfo("Export", "Results exported successfully!")

    def load_from_history(self, event):
        selection = self.history_listbox.curselection()
        if selection:
            ip = self.history_listbox.get(selection[0])
            self.ip_entry.delete(0, tk.END)
            self.ip_entry.insert(0, ip)
            self.start_investigation()

    def update_search_history(self, ip):
        if ip not in self.search_history:
            self.search_history.append(ip)
            self.history_listbox.insert(0, ip)
            if len(self.search_history) > 10:
                self.search_history.pop(0)
                self.history_listbox.delete(10)

    def update_status(self, message):
        self.status_bar.config(text=message)
        self.after(3000, lambda: self.status_bar.config(text="Ready"))

    def animate_title(self):
        colors = ["#FF6B6B", "#4ECDC4", "#45B7D1", "#F9C74F", "#90BE6D"]
        current_color = self.header.cget("foreground")
        next_color = random.choice([c for c in colors if c != current_color])
        self.header.configure(foreground=next_color)
        self.after(1000, self.animate_title)

    def start_investigation(self):
        ip = self.ip_entry.get()
        if not self.validate_ip(ip):
            self.result_area.set_html("<h2 style='color: red;'>❌ Invalid IP address. Please try again.</h2>")
            return

        self.result_area.set_html("<h2>🕵️ Investigation in progress...</h2>")
        self.progress.start()
        self.update_status("Investigating IP...")

        threading.Thread(target=self.investigate_ip, args=(ip,), daemon=True).start()

    def investigate_ip(self, ip):
        try:
            info = self.get_ip_info(ip)
            if info and info.get('status') == 'success':
                additional_info = self.get_additional_info(ip)
                self.display_results(info, additional_info)
                self.display_map(info)
                self.get_threat_intel(ip)
                self.update_search_history(ip)
            else:
                self.result_area.set_html("<h2 style='color: red;'>❌ Failed to retrieve information. The IP might be invalid or the service is unavailable.</h2>")
        except Exception as e:
            self.result_area.set_html(f"<h2 style='color: red;'>❌ An error occurred: {str(e)}</h2>")
        finally:
            self.progress.stop()
            self.update_status("Investigation complete")
            self.show_random_tip()

    def validate_ip(self, ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def get_ip_info(self, ip):
        url = f"http://ip-api.com/json/{ip}"
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"Error fetching IP info: {e}")
            return None

    def get_additional_info(self, ip):
        return {
            "ssl_cert": self.get_ssl_cert(ip),
            "reverse_dns": self.get_reverse_dns(ip),
            "whois_info": self.get_whois_info(ip),
            "open_ports": self.scan_ports(ip)
        }

    def get_ssl_cert(self, ip):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((ip, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as secure_sock:
                    cert = secure_sock.getpeercert()
                    return f"Valid until {cert['notAfter']}"
        except Exception as e:
            print(f"Error getting SSL cert: {e}")
            return "No SSL certificate found or unable to retrieve"

    def get_reverse_dns(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception as e:
            print(f"Error getting reverse DNS: {e}")
            return "Unable to retrieve reverse DNS"

    def get_whois_info(self, ip):
        try:
            w = whois.whois(ip)
            return f"Registrar: {w.registrar}, Creation Date: {w.creation_date}"
        except Exception as e:
            print(f"Error getting WHOIS info: {e}")
            return "Unable to retrieve WHOIS information"

    def scan_ports(self, ip):
        open_ports = []
        common_ports = [21, 22, 80, 443, 3306, 3389]
        for port in common_ports:
            try:
                with socket.create_connection((ip, port), timeout=1) as sock:
                    open_ports.append(port)
            except (socket.timeout, ConnectionRefusedError):
                pass
            except Exception as e:
                print(f"Error scanning port {port}: {e}")
        return open_ports

    def display_results(self, info, additional_info):
        html_content = f"""
        <h2 style='color: #FFD700;'>🌈 IP Reconnaissance Report 🌈</h2>
        <hr>
        <p><strong style='color: #FF6B6B;'>🔍 Target IP:</strong> {info['query']}</p>
        <p><strong>📡 Status:</strong> {info['status']}</p>
        <p><strong>🏙️ City:</strong> {info.get('city', 'N/A')}</p>
        <p><strong>🗺️ Region:</strong> {info.get('regionName', 'N/A')} ({info.get('region', 'N/A')})</p>
        <p><strong>🌎 Country:</strong> {info.get('country', 'N/A')} ({info.get('countryCode', 'N/A')})</p>
        <p><strong>🕒 Timezone:</strong> {info.get('timezone', 'N/A')}</p>
        <p><strong>🖥️ ISP:</strong> {info.get('isp', 'N/A')}</p>
        <p><strong>🏢 Organization:</strong> {info.get('org', 'N/A')}</p>
        <p><strong>📶 AS Number:</strong> {info.get('as', 'N/A')}</p>
        <p><strong>📍 Coordinates:</strong> {info.get('lat', 'N/A')}, {info.get('lon', 'N/A')}</p>
        <hr>
        <h3 style='color: #4ECDC4;'>📊 Additional Information:</h3>
        <p><strong>🔒 SSL Certificate:</strong> {additional_info['ssl_cert']}</p>
        <p><strong>🌐 Reverse DNS:</strong> {additional_info['reverse_dns']}</p>
        <p><strong>ℹ️ WHOIS Info:</strong> {additional_info['whois_info']}</p>
        <p><strong>🚦 Open Ports:</strong> {', '.join(map(str, additional_info['open_ports']))}</p>
        """
        self.result_area.set_html(html_content)

    def display_map(self, info):
        for widget in self.map_frame.winfo_children():
            widget.destroy()

        lat, lon = info.get('lat'), info.get('lon')
        if lat is not None and lon is not None:
            m = folium.Map(location=[lat, lon], zoom_start=10)
            folium.Marker([lat, lon], popup=f"{info.get('city', 'Unknown')}, {info.get('country', 'Unknown')}").add_to(m)
            
            map_file = 'temp_map.html'
            m.save(map_file)
            
            webview = ttk.Label(self.map_frame, text="Click to open map in browser")
            webview.pack(expand=True, fill=tk.BOTH)
            webview.bind("<Button-1>", lambda e: webbrowser.open('file://' + os.path.realpath(map_file)))
        else:
            ttk.Label(self.map_frame, text="Location data not available").pack(expand=True, fill=tk.BOTH)

    def get_threat_intel(self, ip):
        # This is a mock function. In a real scenario, you'd use an actual threat intelligence API.
        threat_score = random.randint(0, 100)
        color = "#00FF00" if threat_score < 30 else "#FFA500" if threat_score < 70 else "#FF0000"
        html_content = f"""
        <h2 style='color: #FFD700;'>🛡️ Threat Intelligence Report 🛡️</h2>
        <hr>
        <p><strong style='color: #FF6B6B;'>🔍 IP Address:</strong> {ip}</p>
        <p><strong>🚨 Threat Score:</strong> <span style='color: {color};'>{threat_score}/100</span></p>
        <p><strong>🕵️ Last Reported Activity:</strong> {random.choice(['Spam', 'Malware', 'Phishing', 'None'])}</p>
        <p><strong>📅 Last Seen:</strong> {random.choice(['1 day ago', '1 week ago', '1 month ago', 'Never'])}</p>
        """
        self.threat_area.set_html(html_content)

    def show_random_tip(self):
        tips = [
            "🔒 Always use a VPN to protect your real IP address.",
            "🔄 Keep your software and systems updated to prevent security vulnerabilities.",
            "🖱️ Be cautious when clicking on links from unknown sources.",
            "🔑 Use strong, unique passwords for all your online accounts.",
            "📱 Enable two-factor authentication whenever possible.",
            "💾 Regularly back up your important data.",
            "📶 Be wary of public Wi-Fi networks and avoid accessing sensitive information on them.",
            "🗝️ Use a password manager to generate and store complex passwords securely.",
            "🦠 Keep your antivirus software up-to-date and run regular scans.",
            "🤐 Be cautious about the information you share on social media."
        ]
        self.tip_label.config(text=f"💡 Cyber Tip: {random.choice(tips)}")

if __name__ == "__main__":
    app = IPLookupApp()
    app.mainloop()