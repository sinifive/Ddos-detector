import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import time
import socket
from scapy.all import sniff, IP, TCP, UDP
import collections
from datetime import datetime

class PacketMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Monitor")
        self.root.geometry("1000x600")
        self.root.configure(bg="#f5f5f5")
        
        # Variables
        self.packets = []
        self.is_capturing = False
        self.capture_thread = None
        self.threshold = 100  # Default packets per second threshold
        self.excluded_ips = set()  # IPs to exclude (gateways etc.)
        self.packet_counts = collections.defaultdict(int)
        self.last_check_time = time.time()
        self.gateway_detection_done = False
        
        # Create GUI
        self.create_menu()
        self.create_toolbar()
        self.create_packet_list()
        self.create_details_panel()
        self.create_status_bar()
        
        # Update status periodically
        self.root.after(1000, self.update_status)
    
    def create_menu(self):
        menu_bar = tk.Menu(self.root)
        
        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Start Capture", command=self.start_capture)
        file_menu.add_command(label="Stop Capture", command=self.stop_capture)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        settings_menu = tk.Menu(menu_bar, tearoff=0)
        settings_menu.add_command(label="Set Threshold", command=self.set_threshold)
        settings_menu.add_command(label="Manage Excluded IPs", command=self.manage_excluded_ips)
        
        help_menu = tk.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Help", command=self.show_help)
        
        menu_bar.add_cascade(label="File", menu=file_menu)
        menu_bar.add_cascade(label="Settings", menu=settings_menu)
        menu_bar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menu_bar)
    
    def create_toolbar(self):
        toolbar_frame = tk.Frame(self.root, bg="#e0e0e0")
        toolbar_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Start button
        start_img = tk.PhotoImage(data="R0lGODlhFAAUAIABAAAAAP///yH5BAEKAAEALAAAAAAUABQAAAImjI+py+0Po5y02ouz3rz7D4biSJbmiabqyrbuC8fyTNf2jef6VgAAOw==")
        start_btn = ttk.Button(toolbar_frame, text="Start", command=self.start_capture)
        start_btn.pack(side=tk.LEFT, padx=2)
        
        # Stop button
        stop_btn = ttk.Button(toolbar_frame, text="Stop", command=self.stop_capture)
        stop_btn.pack(side=tk.LEFT, padx=2)
        
        # Threshold setting
        threshold_label = ttk.Label(toolbar_frame, text="Threshold:")
        threshold_label.pack(side=tk.LEFT, padx=(10, 2))
        
        self.threshold_var = tk.StringVar(value=str(self.threshold))
        threshold_entry = ttk.Entry(toolbar_frame, textvariable=self.threshold_var, width=6)
        threshold_entry.pack(side=tk.LEFT)
        threshold_entry.bind("<Return>", lambda e: self.set_threshold_from_entry())
        
        # Apply button
        apply_btn = ttk.Button(toolbar_frame, text="Apply", command=self.set_threshold_from_entry)
        apply_btn.pack(side=tk.LEFT, padx=2)
    
    def create_packet_list(self):
        # Frame for packet list
        packet_frame = tk.Frame(self.root)
        packet_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create treeview for packet list
        columns = ("No.", "Time", "Source", "Destination", "Protocol", "Length")
        self.packet_tree = ttk.Treeview(packet_frame, columns=columns, show="headings")
        
        # Set column headings
        for col in columns:
            self.packet_tree.heading(col, text=col)
            width = 100
            if col == "No.":
                width = 50
            elif col == "Time":
                width = 150
            self.packet_tree.column(col, width=width)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(packet_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack elements
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind selection event
        self.packet_tree.bind("<<TreeviewSelect>>", self.on_packet_select)
    
    def create_details_panel(self):
        details_frame = tk.LabelFrame(self.root, text="Packet Details", padx=5, pady=5)
        details_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.details_text = tk.Text(details_frame, height=10, wrap=tk.WORD)
        self.details_text.pack(fill=tk.BOTH, expand=True)
        self.details_text.config(state=tk.DISABLED)
    
    def create_status_bar(self):
        status_frame = tk.Frame(self.root, bd=1, relief=tk.SUNKEN)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_label = tk.Label(status_frame, text="Ready")
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        self.packet_count_label = tk.Label(status_frame, text="Packets: 0")
        self.packet_count_label.pack(side=tk.RIGHT, padx=5)
    
    def start_capture(self):
        if not self.is_capturing:
            self.is_capturing = True
            self.status_label.config(text="Capturing...")
            
            # Clear existing packets
            for item in self.packet_tree.get_children():
                self.packet_tree.delete(item)
            self.packets = []
            
            # Start capture in a separate thread
            self.capture_thread = threading.Thread(target=self.capture_packets)
            self.capture_thread.daemon = True
            self.capture_thread.start()
    
    def stop_capture(self):
        self.is_capturing = False
        self.status_label.config(text="Stopped")
    
    def capture_packets(self):
        def packet_callback(packet):
            if not self.is_capturing:
                return
            
            # Process only IP packets
            if IP in packet:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                length = len(packet)
                
                # Determine protocol
                protocol = "Other"
                if TCP in packet:
                    protocol = "TCP"
                elif UDP in packet:
                    protocol = "UDP"
                
                # Add to our packet list
                packet_info = {
                    "no": len(self.packets) + 1,
                    "time": timestamp,
                    "src": src_ip,
                    "dst": dst_ip,
                    "protocol": protocol,
                    "length": length,
                    "packet": packet
                }
                self.packets.append(packet_info)
                
                # Update GUI from the main thread
                self.root.after(1, lambda: self.add_packet_to_tree(packet_info))
                
                # Check for potential DoS
                current_time = time.time()
                if current_time - self.last_check_time >= 1:  # Every second
                    self.check_dos_attack()
                    self.last_check_time = current_time
                
                # Auto-detect gateways if not done yet
                if not self.gateway_detection_done and len(self.packets) > 100:
                    self.detect_gateways()
                    self.gateway_detection_done = True
                
                # Track packet counts for DoS detection
                self.packet_counts[src_ip] += 1
        
        try:
            # Start capturing (without using eth0)
            sniff(prn=packet_callback, store=0)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Capture error: {str(e)}"))
            self.is_capturing = False
    
    def add_packet_to_tree(self, packet_info):
        if not self.is_capturing:
            return
        
        # Add to treeview
        values = (
            packet_info["no"],
            packet_info["time"],
            packet_info["src"],
            packet_info["dst"],
            packet_info["protocol"],
            packet_info["length"]
        )
        self.packet_tree.insert("", "end", values=values)
        
        # Update packet count
        self.packet_count_label.config(text=f"Packets: {len(self.packets)}")
        
        # Auto-scroll to the bottom
        self.packet_tree.yview_moveto(1)
    
    def on_packet_select(self, event):
        selected_items = self.packet_tree.selection()
        if not selected_items:
            return
        
        item = selected_items[0]
        index = int(self.packet_tree.item(item, "values")[0]) - 1
        if 0 <= index < len(self.packets):
            packet = self.packets[index]["packet"]
            self.display_packet_details(packet)
    
    def display_packet_details(self, packet):
        # Enable text widget for editing
        self.details_text.config(state=tk.NORMAL)
        
        # Clear previous content
        self.details_text.delete("1.0", tk.END)
        
        # Add packet summary
        self.details_text.insert(tk.END, f"Packet Summary:\n{packet.summary()}\n\n")
        
        # Add IP details if present
        if IP in packet:
            self.details_text.insert(tk.END, "IP Details:\n")
            self.details_text.insert(tk.END, f"  Source: {packet[IP].src}\n")
            self.details_text.insert(tk.END, f"  Destination: {packet[IP].dst}\n")
            self.details_text.insert(tk.END, f"  Version: {packet[IP].version}\n")
            self.details_text.insert(tk.END, f"  TTL: {packet[IP].ttl}\n")
            
            # Add TCP/UDP details if present
            if TCP in packet:
                self.details_text.insert(tk.END, "\nTCP Details:\n")
                self.details_text.insert(tk.END, f"  Source Port: {packet[TCP].sport}\n")
                self.details_text.insert(tk.END, f"  Destination Port: {packet[TCP].dport}\n")
                self.details_text.insert(tk.END, f"  Sequence: {packet[TCP].seq}\n")
                self.details_text.insert(tk.END, f"  Flags: {packet[TCP].flags}\n")
            elif UDP in packet:
                self.details_text.insert(tk.END, "\nUDP Details:\n")
                self.details_text.insert(tk.END, f"  Source Port: {packet[UDP].sport}\n")
                self.details_text.insert(tk.END, f"  Destination Port: {packet[UDP].dport}\n")
                self.details_text.insert(tk.END, f"  Length: {packet[UDP].len}\n")
        
        # Try to add any payload data
        if hasattr(packet, 'load') and packet.load:
            try:
                payload = packet.load.decode('utf-8', errors='replace')
                self.details_text.insert(tk.END, f"\nPayload:\n{payload}\n")
            except:
                self.details_text.insert(tk.END, "\nBinary payload (not displayed)\n")
        
        # Disable text widget again
        self.details_text.config(state=tk.DISABLED)
    
    def check_dos_attack(self):
        if not self.is_capturing:
            return
        
        # Check each IP's packet count against threshold
        for ip, count in self.packet_counts.items():
            if ip in self.excluded_ips:
                continue  # Skip excluded IPs
                
            if count > self.threshold:
                self.alert_dos_attack(ip, count)
        
        # Reset counters
        self.packet_counts.clear()
    
    def alert_dos_attack(self, ip, count):
        # Alert in a non-blocking way
        def show_alert():
            result = messagebox.askquestion(
                "DoS Attack Alert",
                f"Potential DoS attack detected!\n\nIP: {ip}\nPacket count: {count} (threshold: {self.threshold})\n\nAdd this IP to exclusion list?"
            )
            if result == "yes":
                self.excluded_ips.add(ip)
        
        # Schedule alert on main thread
        self.root.after(0, show_alert)
    
    def detect_gateways(self):
        # Simple gateway detection: find IPs with the most connections
        ip_count = collections.Counter()
        
        for packet_info in self.packets:
            ip_count[packet_info["src"]] += 1
            ip_count[packet_info["dst"]] += 1
        
        # Get top 3 most active IPs - likely gateways or important servers
        for ip, _ in ip_count.most_common(3):
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                if any(keyword in hostname.lower() for keyword in ["router", "gateway", "modem"]):
                    self.excluded_ips.add(ip)
            except:
                # If hostname lookup fails, just add the IP if it's very active
                if ip_count[ip] > len(self.packets) * 0.2:  # If it appears in 20%+ of packets
                    self.excluded_ips.add(ip)
    
    def set_threshold(self):
        new_threshold = simpledialog.askinteger(
            "Set Threshold", 
            "Enter packets per second threshold for DoS detection:",
            initialvalue=self.threshold,
            minvalue=1,
            maxvalue=10000
        )
        
        if new_threshold:
            self.threshold = new_threshold
            self.threshold_var.set(str(self.threshold))
    
    def set_threshold_from_entry(self):
        try:
            new_threshold = int(self.threshold_var.get())
            if 1 <= new_threshold <= 10000:
                self.threshold = new_threshold
            else:
                messagebox.showwarning("Invalid Value", "Threshold must be between 1 and 10000")
                self.threshold_var.set(str(self.threshold))
        except ValueError:
            messagebox.showwarning("Invalid Value", "Threshold must be a number")
            self.threshold_var.set(str(self.threshold))
    
    def manage_excluded_ips(self):
        # Create a dialog to manage excluded IPs
        dialog = tk.Toplevel(self.root)
        dialog.title("Manage Excluded IPs")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Create listbox for IPs
        frame = tk.Frame(dialog)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        label = tk.Label(frame, text="Excluded IPs (gateways, etc.):")
        label.pack(anchor=tk.W)
        
        ip_listbox = tk.Listbox(frame)
        ip_listbox.pack(fill=tk.BOTH, expand=True)
        for ip in sorted(self.excluded_ips):
            ip_listbox.insert(tk.END, ip)
        
        # Buttons
        btn_frame = tk.Frame(dialog)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        add_btn = ttk.Button(
            btn_frame, 
            text="Add", 
            command=lambda: self.add_excluded_ip(ip_listbox)
        )
        add_btn.pack(side=tk.LEFT, padx=5)
        
        remove_btn = ttk.Button(
            btn_frame, 
            text="Remove", 
            command=lambda: self.remove_excluded_ip(ip_listbox)
        )
        remove_btn.pack(side=tk.LEFT, padx=5)
        
        close_btn = ttk.Button(
            btn_frame, 
            text="Close", 
            command=dialog.destroy
        )
        close_btn.pack(side=tk.RIGHT, padx=5)
    
    def add_excluded_ip(self, listbox):
        ip = simpledialog.askstring("Add IP", "Enter IP address to exclude:")
        if ip:
            self.excluded_ips.add(ip)
            listbox.delete(0, tk.END)
            for ip in sorted(self.excluded_ips):
                listbox.insert(tk.END, ip)
    
    def remove_excluded_ip(self, listbox):
        selection = listbox.curselection()
        if selection:
            ip = listbox.get(selection[0])
            self.excluded_ips.remove(ip)
            listbox.delete(selection[0])
    
    def show_about(self):
        messagebox.showinfo(
            "About", 
            "Network Packet Monitor\n\n"
            "A tool for monitoring network traffic and detecting DoS attacks.\n\n"
            "Features:\n"
            "- Real-time packet capture\n"
            "- DoS attack detection\n"
            "- Gateway auto-detection\n"
            "- Packet details inspection"
        )
    
    def show_help(self):
        help_text = """
Network Packet Monitor Help

Getting Started:
1. Click "Start" to begin capturing packets
2. Click "Stop" to pause the capture
3. Click on any packet in the list to view its details

DoS Detection:
- Set your threshold for packets per second
- The app will alert you if any non-excluded IP exceeds this threshold
- Gateways are automatically detected and excluded

Managing IPs:
- Go to Settings > Manage Excluded IPs to add or remove IPs from the exclusion list

Notes:
- You may need to run this app with administrator/root privileges for packet capture
- The app uses Scapy for packet capture
"""
        messagebox.showinfo("Help", help_text)
    
    def update_status(self):
        if self.is_capturing:
            self.status_label.config(text=f"Capturing... (Excluded IPs: {len(self.excluded_ips)})")
        
        # Schedule next update
        self.root.after(1000, self.update_status)

def main():
    root = tk.Tk()
    app = PacketMonitor(root)
    root.mainloop()

if __name__ == "__main__":
    main()
