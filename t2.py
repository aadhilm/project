import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import bcrypt
import json
import os
import logging
import re
import socket
import threading
import platform
import networkx as nx
import matplotlib.pyplot as plt
from scapy.all import traceroute
import psutil
from datetime import datetime
import subprocess
import requests
import whois
import ssl
import time
import paramiko
import sqlite3
import queue
import speedtest
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from flask import Flask, render_template, request, jsonify

# Database Initialization
def init_db():
    conn = sqlite3.connect('network_scanner.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, password TEXT, role TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS activity_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, action TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

init_db()

# User Management Classes
class UserManager:
    def __init__(self):
        self.conn = sqlite3.connect('network_scanner.db')
        self.c = self.conn.cursor()
        self.create_default_admin()

    def create_default_admin(self):
        self.c.execute("SELECT * FROM users WHERE username=?", ("admin",))
        if not self.c.fetchone():
            self.register_user("admin", "admin123", role="admin")

    def hash_password(self, password):
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    def verify_password(self, hashed_password, password):
        return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))

    def register_user(self, username, password, role="user"):
        self.c.execute("SELECT * FROM users WHERE username=?", (username,))
        if self.c.fetchone():
            return False  # User already exists
        hashed_password = self.hash_password(password)
        self.c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed_password, role))
        self.conn.commit()
        return True

    def authenticate_user(self, username, password):
        self.c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = self.c.fetchone()
        if user and self.verify_password(user[1], password):
            return {"username": user[0], "password": user[1], "role": user[2]}
        return None

    def delete_user(self, username):
        self.c.execute("DELETE FROM users WHERE username=?", (username,))
        self.conn.commit()

class ActivityLogger:
    def __init__(self):
        self.conn = sqlite3.connect('network_scanner.db')
        self.c = self.conn.cursor()

    def log_activity(self, username, action):
        self.c.execute("INSERT INTO activity_logs (username, action) VALUES (?, ?)", (username, action))
        self.conn.commit()

class PasswordManager:
    def __init__(self, min_length=8, require_uppercase=True, require_digits=True):
        self.min_length = min_length
        self.require_uppercase = require_uppercase
        self.require_digits = require_digits

    def validate_password(self, password):
        if len(password) < self.min_length:
            return False, f"Password must be at least {self.min_length} characters long."
        if self.require_uppercase and not re.search("[A-Z]", password):
            return False, "Password must contain at least one uppercase letter."
        if self.require_digits and not re.search("[0-9]", password):
            return False, "Password must contain at least one digit."
        return True, "Password is valid."

    def reset_password(self, username, old_password, new_password):
        user_manager = UserManager()
        user = user_manager.authenticate_user(username, old_password)
        if not user:
            return False, "Old password is incorrect."
        is_valid, message = self.validate_password(new_password)
        if not is_valid:
            return False, message
        hashed_password = user_manager.hash_password(new_password)
        user_manager.c.execute("UPDATE users SET password=? WHERE username=?", (hashed_password, username))
        user_manager.conn.commit()
        return True, "Password reset successful."

class UserManagementWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("User Management")
        self.geometry("600x400")
        self.configure(bg="#1e1e2f")

        self.style = ttk.Style(self)
        self.style.configure("TLabel", foreground="#ffffff", background="#1e1e2f")
        self.style.configure("TButton", background="#3e3e56", foreground="#ffffff")

        self.user_manager = UserManager()
        self.activity_logger = ActivityLogger()
        self.setup_ui()

    def setup_ui(self):
        ttk.Label(self, text="Username:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.username_entry = ttk.Entry(self, width=20)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(self, text="Password:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.password_entry = ttk.Entry(self, width=20, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(self, text="Role:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.role_entry = ttk.Entry(self, width=20)
        self.role_entry.grid(row=2, column=1, padx=5, pady=5)

        ttk.Button(self, text="Create User", command=self.create_user).grid(row=3, column=0, columnspan=2, pady=10)
        ttk.Button(self, text="Delete User", command=self.delete_user).grid(row=4, column=0, columnspan=2, pady=10)

    def create_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        role = self.role_entry.get()
        if self.user_manager.register_user(username, password, role):
            messagebox.showinfo("Success", "User created successfully.")
            self.activity_logger.log_activity(username, "created user")
        else:
            messagebox.showerror("Error", "User already exists.")

    def delete_user(self):
        username = self.username_entry.get()
        if self.user_manager.authenticate_user(username, self.password_entry.get()):
            self.user_manager.delete_user(username)
            messagebox.showinfo("Success", "User deleted successfully.")
            self.activity_logger.log_activity(username, "deleted user")
        else:
            messagebox.showerror("Error", "User not found or password incorrect.")

class LoginWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Login")
        self.geometry("300x250")
        self.configure(bg="#1e1e2f")

        ttk.Label(self, text="Username:").pack(pady=5)
        self.username_entry = ttk.Entry(self)
        self.username_entry.pack(pady=5)

        ttk.Label(self, text="Password:").pack(pady=5)
        self.password_entry = ttk.Entry(self, show="*")
        self.password_entry.pack(pady=5)

        ttk.Button(self, text="Login", command=self.authenticate).pack(pady=5)
        ttk.Button(self, text="Login as Guest", command=self.login_as_guest).pack(pady=5)

    def authenticate(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        user_manager = UserManager()
        user = user_manager.authenticate_user(username, password)
        if user:
            self.master.open_main_window(username)
            self.destroy()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

    def login_as_guest(self):
        self.master.open_main_window("guest")
        self.destroy()


class NetworkScanner(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Futuristic Network Scanner")
        self.geometry("1200x700")
        self.configure(bg="#1e1e2f")

        self.user_manager = UserManager()
        self.activity_logger = ActivityLogger()
        self.logged_in_user = None  # Track logged-in user
        
        # Initializing login screen
        self.login_window = LoginWindow(self)
        self.withdraw()  # Hide main window until login is successful

        # Flags
        self.scanning = False
        self.auto_scanning = False
        self.auto_scan_timer = None  # Store the timer object
        self.device_graph = nx.Graph()

        # Bandwidth Monitor
        self.bandwidth_monitor = BandwidthMonitor(self)

        # Vulnerability Scanner
        self.vulnerability_scanner = None

        # Styling
        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self.setup_style()

        # Initialize the web interface after the UI is set up
        self.web_interface = None

    def setup_style(self):
        """Setup the modern style for widgets."""
        self.style.configure("TLabel", font=("Helvetica", 12), foreground="#ffffff", background="#1e1e2f")
        self.style.configure("TButton", font=("Helvetica", 12), background="#3e3e56", foreground="#ffffff")
        self.style.configure("TFrame", background="#1e1e2f")
        self.style.configure("TEntry", font=("Helvetica", 12), foreground="#000000")
        self.style.configure("TListbox", font=("Courier", 12), background="#1e1e2f", foreground="#00ff7f")

    def open_main_window(self, username):
        """Open the main network scanner window after successful login."""
        self.logged_in_user = username
        self.deiconify()  # Show the main window
        self.setup_ui()
        self.start_bandwidth_monitor()
        # Initialize the web interface after the UI is set up
        self.web_interface = WebInterface(self)
        self.start_web_interface()

        # Fetch user data from the database
        self.user_manager.c.execute("SELECT * FROM users WHERE username=?", (self.logged_in_user,))
        user_data = self.user_manager.c.fetchone()
        if user_data:
            user_data = {"username": user_data[0], "password": user_data[1], "role": user_data[2]}
        else:
            user_data = {}

        # If the user is a guest, disable certain features
        if user_data.get("role") == "guest":
            # Disable buttons for features that guests should not access
            for widget in self.winfo_children():
                if isinstance(widget, ttk.Button):
                    if widget["text"] in ["Advanced Visualize Topology", "SSH Connect", "Export Results", "Clear Output"]:
                        widget.config(state="disabled")

    def start_web_interface(self):
        """Start the Flask web interface in a separate thread."""
        if self.web_interface:
            threading.Thread(
                target=self.web_interface.run,
                kwargs={"host": "0.0.0.0", "port": 5000},
                daemon=True,
            ).start()
            self.append_output("Web interface started at http://127.0.0.1:500 or http://localhost:5000\n")

    def append_output(self, text):
        """Append text to the output widget if it exists."""
        if hasattr(self, "output_text") and self.output_text:
            self.output_text.config(state="normal")
            self.output_text.insert(tk.END, text)
            self.output_text.config(state="disabled")
            self.output_text.yview(tk.END)

    def setup_ui(self):
        """Setup the main UI with all components in one screen."""
        main_frame = ttk.Frame(self, padding=10)
        main_frame.pack(fill="both", expand=True)

        # Left panel: Controls and scan settings
        control_frame = ttk.Frame(main_frame, width=300)
        control_frame.pack(side="left", fill="y", padx=10, pady=10)
        self.setup_controls(control_frame)

        # Center panel: Output and visualization
        output_frame = ttk.Frame(main_frame)
        output_frame.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        self.setup_output(output_frame)

        # Right panel: System Info, Bandwidth Monitoring, and Vulnerability Scanning
        right_frame = ttk.Frame(main_frame, width=250)
        right_frame.pack(side="right", fill="y", padx=10, pady=10)

         # Log Out Button (top-right corner)
        logout_frame = ttk.Frame(right_frame)
        logout_frame.pack(fill="x", pady=5)
        ttk.Button(logout_frame, text="Log Out", command=self.log_out).pack(side="right", padx=5, pady=5)

        # System Info
        system_info_frame = ttk.Frame(right_frame, padding=10)
        system_info_frame.pack(fill="x", pady=10)
        self.setup_system_info(system_info_frame)

        # Bandwidth Monitoring
        bandwidth_frame = ttk.LabelFrame(right_frame, text="Bandwidth Monitoring", padding=5)
        bandwidth_frame.pack(fill="x", pady=5)

        # Create a frame to hold the bandwidth output and buttons horizontally
        bandwidth_output_frame = ttk.Frame(bandwidth_frame)
        bandwidth_output_frame.pack(fill="x", pady=5)

        # Bandwidth Output Box (Reduced width and height)
        self.bandwidth_output = tk.Text(
            bandwidth_output_frame,
            wrap="word",
            height=3,  # Reduced height
            width=20,  # Reduced width (20 characters wide)
            bg="#1e1e2f",
            fg="#00ff7f",
            font=("Courier", 12)
        )
        self.bandwidth_output.pack(side="left", fill="x", expand=True, pady=5)

        # Buttons for Start and Stop Bandwidth Monitor
        button_frame = ttk.Frame(bandwidth_output_frame)
        button_frame.pack(side="right", padx=5)

        ttk.Button(button_frame, text="Start", command=self.start_bandwidth_monitor).pack(side="left", padx=2)
        ttk.Button(button_frame, text="Stop", command=self.stop_bandwidth_monitor).pack(side="left", padx=2)

        # Bandwidth Graph
        self.bandwidth_figure = Figure(figsize=(7, 4), dpi=100)
        self.bandwidth_plot = self.bandwidth_figure.add_subplot(111)
        self.bandwidth_plot.set_title("Bandwidth Usage Over Time")
        self.bandwidth_plot.set_xlabel("Time")
        self.bandwidth_plot.set_ylabel("Bytes")
        self.bandwidth_canvas = FigureCanvasTkAgg(self.bandwidth_figure, master=bandwidth_frame)
        self.bandwidth_canvas.get_tk_widget().pack(fill="x", pady=5)

        # Fetch user data from the database
        self.user_manager.c.execute("SELECT * FROM users WHERE username=?", (self.logged_in_user,))
        user_data = self.user_manager.c.fetchone()
        if user_data:
            user_data = {"username": user_data[0], "password": user_data[1], "role": user_data[2]}
        else:
            user_data = {}

        # If the user is a guest, disable certain features
        if user_data.get("role") == "guest":
            # Disable buttons for features that guests should not access
            for widget in control_frame.winfo_children():
                if isinstance(widget, ttk.Button):
                    if widget["text"] in ["Advanced Visualize Topology", "SSH Connect", "Export Results", "Clear Output"]:
                        widget.config(state="disabled")
        elif user_data.get("role") == "admin":
            ttk.Button(control_frame, text="User Management", command=self.open_user_management).pack(fill="x", pady=5)
        
    def update_bandwidth_graph(self, time_data, usage_data):
        """Update the bandwidth graph with new data."""
        self.bandwidth_plot.clear()
        # Set graph background color
        self.bandwidth_plot.set_facecolor("#1e1e2f")  # Dark background color
        # Set grid color
        self.bandwidth_plot.grid(color="#3e3e56", linestyle="--", linewidth=0.5)
        # Plot the data with a custom color (e.g., cyan, magenta, etc.)
        self.bandwidth_plot.plot(time_data, usage_data, color="#00ff7f", label="Bandwidth Usage", linewidth=2)
        # Customize title and labels
        self.bandwidth_plot.set_title("Bandwidth Usage Over Time", color="white", fontsize=12)
        self.bandwidth_plot.set_xlabel("Time", color="white", fontsize=10)
        self.bandwidth_plot.set_ylabel("Bytes", color="white", fontsize=10)
        # Customize tick colors
        self.bandwidth_plot.tick_params(axis="x", colors="white")
        self.bandwidth_plot.tick_params(axis="y", colors="white")
        # Customize legend
        legend = self.bandwidth_plot.legend()
        for text in legend.get_texts():
            text.set_color("white")
        # Redraw the canvas
        self.bandwidth_canvas.draw()

    def start_bandwidth_monitor(self):
        """Start bandwidth monitoring."""
        self.bandwidth_monitor.start()
        self.append_output("Bandwidth monitoring started.\n")

    def stop_bandwidth_monitor(self):
        """Stop bandwidth monitoring."""
        self.bandwidth_monitor.stop()
        self.append_output("Bandwidth monitoring stopped.\n")

    def update_bandwidth_output(self, message):
        """Update the bandwidth output box."""
        self.bandwidth_output.config(state="normal")
        self.bandwidth_output.insert(tk.END, message)
        self.bandwidth_output.config(state="disabled")
        self.bandwidth_output.yview(tk.END)

        
    def setup_controls(self, parent):
        """Setup the control panel on the left side with a scrollbar."""
        # Create a canvas and a vertical scrollbar
        canvas = tk.Canvas(parent, bg="#1e1e2f", highlightthickness=0)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        # Configure the canvas to scroll
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Pack the canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Add the scan settings to the scrollable frame
        ttk.Label(scrollable_frame, text="Scan Settings", font=("Helvetica", 16, "bold")).pack(pady=10)
        ttk.Label(scrollable_frame, text="Main System IP:").pack(anchor="w", pady=5)
        self.local_ip_entry = ttk.Entry(scrollable_frame, state="readonly", width=20)
        self.local_ip_entry.pack(fill="x", padx=5, pady=5)
        self.fetch_main_ip()

        self.font_size_label = ttk.Label(scrollable_frame, text="Font Size:")
        self.font_size_label.pack(anchor="w", pady=5)
        self.font_size_spinner = ttk.Spinbox(scrollable_frame, from_=8, to=30, command=self.update_font_size, width=3)
        self.font_size_spinner.set(14)
        self.font_size_spinner.pack(fill="x", padx=5, pady=5)

        ttk.Label(scrollable_frame, text="Scan Device", font=("Helvetica", 12, "bold")).pack(pady=10)
        ttk.Label(scrollable_frame, text="Network Prefix:").pack(anchor="w", pady=5)
        self.network_prefix_entry = ttk.Entry(scrollable_frame, width=20)
        self.network_prefix_entry.insert(0, "192.168.1")
        self.network_prefix_entry.pack(fill="x", padx=5, pady=5)

        ttk.Label(scrollable_frame, text="IP Range (e.g., 3-8):").pack(anchor="w", pady=5)
        self.ip_range_entry = ttk.Entry(scrollable_frame, width=20)
        self.ip_range_entry.insert(0, "1-254")
        self.ip_range_entry.pack(fill="x", padx=5, pady=5)

        ttk.Button(scrollable_frame, text="Start Scan", command=self.start_scan).pack(fill="x", pady=5)
        ttk.Button(scrollable_frame, text="Stop Scan", command=self.stop_scan).pack(fill="x", pady=5)

        ttk.Label(scrollable_frame, text="Advance Scanning", font=("Helvetica", 12, "bold")).pack(pady=10)
        ttk.Label(scrollable_frame, text="Target IP/Host:").pack(anchor="w", pady=5)
        self.vuln_target_entry = ttk.Entry(scrollable_frame, width=20)
        self.vuln_target_entry.insert(0, "192.168.1")
        self.vuln_target_entry.pack(fill="x", padx=5, pady=5)
        ttk.Button(scrollable_frame, text="Scan for Vulnerabilities", command=self.run_vulnerability_scan).pack(fill="x", pady=5)

        ttk.Label(scrollable_frame, text="Traceroute Target:").pack(anchor="w", pady=5)
        self.traceroute_entry = ttk.Entry(scrollable_frame, width=20)
        self.traceroute_entry.insert(0, "192.168.1")
        self.traceroute_entry.pack(fill="x", padx=5, pady=5)

        ttk.Button(scrollable_frame, text="Traceroute", command=self.traceroute_device).pack(fill="x", pady=5)
        ttk.Button(scrollable_frame, text="Auto Scan", command=self.toggle_auto_scan).pack(fill="x", pady=5)
        ttk.Button(scrollable_frame, text="Visualize Topology", command=self.visualize_network).pack(fill="x", pady=5)
        ttk.Button(scrollable_frame, text="Advanced Visualize Topology", command=self.advanced_visualize_network).pack(fill="x", pady=5)
        ttk.Button(scrollable_frame, text="Web Scan", command=self.open_web_scanner).pack(fill="x", pady=5)
        ttk.Button(scrollable_frame, text="SSH Connect", command=self.open_ssh_connection).pack(fill="x", pady=5)
        ttk.Button(scrollable_frame, text="Export Results", command=self.export_results).pack(fill="x", pady=5)
        ttk.Button(scrollable_frame, text="Run Speedtest", command=self.run_speedtest).pack(fill="x", pady=5)
        ttk.Button(scrollable_frame, text="ARP Scan", command=self.run_arp_scan).pack(fill="x", pady=5)
        ttk.Button(scrollable_frame, text="Clear Output", command=self.clear_all).pack(fill="x", pady=5)

        # If the user is a guest, disable certain features
        if self.logged_in_user == "guest":
            for widget in scrollable_frame.winfo_children():
                if isinstance(widget, ttk.Button):
                    if widget["text"] in ["Advanced Visualize Topology", "SSH Connect", "Export Results", "Clear Output"]:
                        widget.config(state="disabled")

     # Add UFW Management Button (only for admin users)
        if self.logged_in_user == "admin":
            ttk.Button(scrollable_frame, text="FrieWall", command=self.open_ufw_management).pack(fill="x", pady=5)

    def open_ufw_management(self):
        """Open the UFW management window."""
        UFWManagementWindow(self)

    def log_out(self):
        """Log out the current user and return to the login screen."""
        # Log the logout action
        self.activity_logger.log_activity(self.logged_in_user, "logged out")

        # Reset the logged-in user
        self.logged_in_user = None

        # Clear sensitive data (optional)
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state="disabled")
        self.device_listbox.delete(0, tk.END)

        # Stop any ongoing processes (e.g., bandwidth monitoring, scans)
        self.stop_bandwidth_monitor()
        self.stop_scan()

        # Hide the main window and show the login window
        self.withdraw()
        self.login_window = LoginWindow(self)
        self.login_window.deiconify()

    def run_arp_scan(self):
        """Run an ARP scan to discover devices on the local network."""
        self.append_output("Starting ARP scan...\n")

        # Function to perform ARP scan in a separate thread
        def perform_arp_scan():
            try:
                # Run the arp-scan command
                result = subprocess.run(
                    ["arp-scan", "--localnet"],  # Scan the local network
                    capture_output=True,
                    text=True
                )

                if result.returncode == 0:
                    # Parse the output and display it
                    self.append_output("ARP Scan Results:\n")
                    self.append_output(result.stdout)
                else:
                    self.append_output(f"Error during ARP scan: {result.stderr}\n")
            except FileNotFoundError:
                self.append_output("Error: arp-scan is not installed on your system.\n")
            except Exception as e:
                self.append_output(f"Error during ARP scan: {e}\n")

        # Run ARP scan in a separate thread to avoid freezing the GUI
        threading.Thread(target=perform_arp_scan).start()

    def run_speedtest(self):
        """Run a speedtest and display the results."""
        self.append_output("Running speedtest... Please wait...\n")
        # Run the speedtest in a separate thread to avoid freezing the GUI
        threading.Thread(target=self.perform_speedtest).start()

    def perform_speedtest(self):
        """Perform the speedtest and display the results."""
        try:
            st = speedtest.Speedtest()
            
            # List available servers
            self.append_output("Finding available servers...\n")
            servers = st.get_servers()
            if not servers:
                self.append_output("No servers found.\n")
                return

            # Manually select a server (e.g., the first server in the list)
            server_id = list(servers.keys())[0]
            st.get_servers([server_id])

            # Find the best server
            self.append_output("Finding the best server...\n")
            best_server = st.get_best_server()
            self.append_output(f"Selected Server: {best_server['host']} ({best_server['name']}, {best_server['country']})\n")
            self.append_output(f"Distance: {best_server['d']:.2f} km\n")
            self.append_output(f"Ping: {best_server['latency']:.2f} ms\n")

            # Measure download speed
            self.append_output("Measuring download speed...\n")
            download_speed = st.download() / 1_000_000  # Convert to Mbps
            self.append_output(f"Download Speed: {download_speed:.2f} Mbps\n")

            # Measure upload speed
            self.append_output("Measuring upload speed...\n")
            upload_speed = st.upload() / 1_000_000  # Convert to Mbps
            self.append_output(f"Upload Speed: {upload_speed:.2f} Mbps\n")

            # Measure ping
            self.append_output("Measuring ping...\n")
            ping = st.results.ping
            self.append_output(f"Ping: {ping:.2f} ms\n")

            self.append_output("Speedtest completed.\n")
        except Exception as e:
            self.append_output(f"Error during speedtest: {e}\n")

    def open_ssh_connection(self):
        if self.logged_in_user == "guest":
            messagebox.showinfo("Info", "Guest users do not have access to SSH connections.")
        else:
            SSHConnectionWindow(self)

    def traceroute_device(self):
        """Perform a traceroute to the specified target."""
        target = self.traceroute_entry.get()
        if not target:
            self.append_output("No target specified for traceroute.\n")
            return

        self.append_output(f"Performing traceroute to {target}...\n")

        # Function to perform traceroute in a separate thread
        def perform_traceroute():
            try:
                # Perform traceroute using scapy
                result, _ = traceroute(target, maxttl=30, verbose=0)  # Set maxttl to limit the number of hops
                self.append_output("Traceroute Results:\n")

                for sent, received in result:
                    if received:
                        self.append_output(f"Hop {sent.ttl}: {received.src}\n")
                    else:
                        self.append_output(f"Hop {sent.ttl}: *\n")

            except Exception as e:
                self.append_output(f"Error during traceroute: {e}\n")

        # Run traceroute in a separate thread to avoid freezing the GUI
        threading.Thread(target=perform_traceroute).start()

    def validate_ip_range(self, value):
        """Validate that the ending IP range is between 0 and 254."""
        try:
            if value == "":
                return True  # Allow empty field
            num = int(value)
            return 0 <= num <= 254
        except ValueError:
            return False

    def setup_output(self, parent):
        """Setup the output and visualization section."""
        output_frame = ttk.LabelFrame(parent, text="Scan Output", padding=10)
        output_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.output_text = tk.Text(output_frame, wrap="word", state="disabled", bg="#1e1e2f", fg="#00ff7f", font=("Courier", 12))
        self.output_text.pack(fill="both", expand=True)

        ttk.Label(output_frame, text="Active Devices:").pack(pady=5)
        self.device_listbox = tk.Listbox(output_frame, height=10, bg="#1e1e2f", fg="#00ff7f", font=("Courier", 12))
        self.device_listbox.pack(fill="both", padx=5, pady=5)

    def setup_system_info(self, parent):
        ttk.Label(parent, text="System Information", font=("Helvetica", 16, "bold")).pack(pady=10)

        system_info = self.get_system_info()
        for key, value in system_info.items():
            if key == "Network Interfaces":  # Add newlines for better readability
                ttk.Label(parent, text=f"{key}: {value}", font=("Helvetica", 12)).pack(anchor="w", pady=5)
                for interface in value.split(", "):
                    ttk.Label(parent, text=f"  {interface}", font=("Helvetica", 12)).pack(anchor="w", pady=2)
            else:
                ttk.Label(parent, text=f"{key}: {value}", font=("Helvetica", 12)).pack(anchor="w", pady=5)

    def get_system_info(self):
        # System information
        system_info = {
            "OS": platform.system() + " " + platform.release(),
            "Architecture": platform.architecture()[0],
            "Processor": platform.processor(),
            "Physical Cores": psutil.cpu_count(logical=False),
            "Logical Cores": psutil.cpu_count(logical=True),
            "Total RAM": f"{psutil.virtual_memory().total / (1024 ** 3):.2f} GB",
            "Available RAM": f"{psutil.virtual_memory().available / (1024 ** 3):.2f} GB",
            "Date & Time": datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
        }

        # Battery information
        if hasattr(psutil, "sensors_battery"):
            battery = psutil.sensors_battery()
            if battery:
                system_info["Battery"] = f"{battery.percent}% {'(Charging)' if battery.power_plugged else '(Discharging)'}"
            else:
                system_info["Battery"] = "No battery detected"
        
        # Network interface information
        network_info = []
        interfaces = psutil.net_if_addrs()
        for iface, addrs in interfaces.items():
            for addr in addrs:
                if addr.family == socket.AF_INET:  # IPv4
                    network_info.append(f"{iface}: {addr.address}")
        
        system_info["Network Interfaces"] = ", ".join(network_info) if network_info else "No active network interfaces"
            
        return system_info

    def update_font_size(self):
        """Update the font size based on the spinner value."""
        font_size = int(self.font_size_spinner.get())
        self.output_text.config(font=("Courier", font_size))

    def fetch_main_ip(self):
        """Fetch and display the local system's IP address."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                main_ip = s.getsockname()[0]
                self.local_ip_entry.config(state="normal")
                self.local_ip_entry.delete(0, tk.END)
                self.local_ip_entry.insert(0, main_ip)
                self.local_ip_entry.config(state="readonly")
        except Exception as e:
            self.append_output(f"Error fetching IP: {e}")

    def start_scan(self):
        """Start the network scan."""
        if self.scanning:
            return
        self.scanning = True

        network_prefix = self.network_prefix_entry.get()
        ip_range = self.ip_range_entry.get()
        try:
            start_ip, end_ip = map(int, ip_range.split("-"))
            if start_ip > end_ip or start_ip < 1 or end_ip > 254:
                raise ValueError("Invalid IP range")
            self.append_output(f"Starting scan on {network_prefix}.{start_ip} to {network_prefix}.{end_ip}...\n")
            threading.Thread(target=self.scan_network, args=(network_prefix, start_ip, end_ip)).start()
        except ValueError:
            self.append_output("Invalid IP range. Please enter in the format: start-end (e.g., 3-8).\n")


    def scan_network(self, prefix, start_ip, end_ip):
        """Perform the network scan."""
        self.device_graph.clear()
        self.device_graph.add_node("Router")

        try:
            for i in range(start_ip, end_ip + 1):
                if not self.auto_scanning and not self.scanning:
                    break
                target_ip = f"{prefix}.{i}"
                if self.ping_device(target_ip):
                    self.append_output(f"{target_ip} is active\n")
                    self.device_listbox.insert(tk.END, f"{target_ip} is active")
                    self.device_graph.add_node(target_ip)
                    self.device_graph.add_edge("Router", target_ip)
                else:
                    self.append_output(f"{target_ip} is inactive\n")
        except Exception as e:
            self.append_output(f"Error during scan: {e}")
        finally:
            self.scanning = False
            self.append_output("\nScan completed.\n")

            if self.auto_scanning:
                self.append_output("Auto-scanning will resume in 10 seconds...\n")
                self.auto_scan_timer = threading.Timer(10, self.start_scan)
                self.auto_scan_timer.start()


    def ping_device(self, ip):
        """Ping a device to check if it is active."""
        param = "-n 1" if platform.system().lower() == "windows" else "-c 1"
        command = f"ping {param} {ip}"
        return os.system(command) == 0

    def append_output(self, text):
        self.output_text.config(state="normal")
        self.output_text.insert(tk.END, text)
        self.output_text.config(state="disabled")
        self.output_text.yview(tk.END)

    def stop_scan(self):
        """Stop the scan."""
        self.scanning = False
        self.append_output("Scan stopped\n")

    def traceroute_device(self):
        """Perform a traceroute to the selected device."""
        selected_device = self.device_listbox.get(tk.ACTIVE)  # Get the selected device from the listbox
        if not selected_device:
            self.append_output("No device selected for traceroute.\n")
            return

        # Extract the IP address from the selected device string
        try:
            ip_address = selected_device.split()[0]  # Assuming the IP is the first part of the string
        except IndexError:
            self.append_output("Invalid device selection format.\n")
            return

        self.append_output(f"Performing traceroute to {ip_address}...\n")

        # Function to perform traceroute in a separate thread
        def perform_traceroute():
            try:
                # Perform traceroute using scapy
                result, _ = traceroute(ip_address, maxttl=30, verbose=0)  # Set maxttl to limit the number of hops
                self.append_output("Traceroute Results:\n")

                for sent, received in result:
                    if received:
                        self.append_output(f"Hop {sent.ttl}: {received.src}\n")
                    else:
                        self.append_output(f"Hop {sent.ttl}: *\n")

            except Exception as e:
                self.append_output(f"Error during traceroute: {e}\n")

        # Run traceroute in a separate thread to avoid freezing the GUI
        threading.Thread(target=perform_traceroute).start()

    def toggle_auto_scan(self):
        """Toggle auto-scan on or off."""
        if self.auto_scanning:
            self.auto_scanning = False
            if self.auto_scan_timer:
                self.auto_scan_timer.cancel()  # Cancel the scheduled timer
                self.auto_scan_timer = None
            self.append_output("Auto-scan stopped\n")
        else:
            self.auto_scanning = True
            self.append_output("Auto-scan started\n")
            self.start_scan()

    def visualize_network(self):
        """Display network topology graph."""
        if not hasattr(self, "device_graph") or self.device_graph.number_of_nodes() == 0:
            self.append_output("No network data available for visualization.\n")
            return

        plt.figure(figsize=(10, 10))
        nx.draw(self.device_graph, with_labels=True, node_color="skyblue", node_size=3000, font_size=10, font_weight="bold")
        plt.title("Network Topology")
        plt.show()

    def advanced_visualize_network(self):
        if self.logged_in_user == "guest":
            messagebox.showinfo("Info", "Guest users do not have access to advanced network visualization.")
        else:
            self.append_output("Launching EtherApe for network visualization...\n")
            try:
                # Launch EtherApe with elevated privileges
                if os.system("which etherape > /dev/null") == 0:
                    os.system("sudo etherape &")
                else:
                    self.append_output("Error: EtherApe is not installed on your system.\n")
            except Exception as e:
                self.append_output(f"Error launching EtherApe: {e}\n")

    def export_results(self):
        if self.logged_in_user == "guest":
            messagebox.showinfo("Info", "Guest users do not have access to export results.")
        else:
            filename = f"network_scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            try:
                with open(filename, "w") as file:
                    file.write("Scan Output:\n")
                    file.write(self.output_text.get("1.0", tk.END))
                    file.write("\nActive Devices:\n")
                    for i in range(self.device_listbox.size()):
                        file.write(self.device_listbox.get(i) + "\n")

                messagebox.showinfo("Export Successful", f"Results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Failed", f"Failed to export results: {e}")

    def clear_all(self):
        if self.logged_in_user == "guest":
            messagebox.showinfo("Info", "Guest users do not have access to clear the output.")
        else:
            # Clear the active devices list
            self.device_listbox.delete(0, tk.END)

            # Clear the scan output
            self.output_text.config(state="normal")
            self.output_text.delete("1.0", tk.END)
            self.output_text.config(state="disabled")

            self.append_output("All data cleared.\n")

    def open_web_scanner(self):
        if self.logged_in_user == "guest":
            messagebox.showinfo("Info", "Guest users do not have access to the Web Scanner.")
        else:
            WebScannerWindow(self)

    def start_bandwidth_monitor(self):
        """Start bandwidth monitoring."""
        self.bandwidth_monitor.start()
        self.append_output("Bandwidth monitoring started.\n")

    def stop_bandwidth_monitor(self):
        """Stop bandwidth monitoring."""
        self.bandwidth_monitor.stop()
        self.append_output("Bandwidth monitoring stopped.\n")

    def run_vulnerability_scan(self):
        if self.logged_in_user == "guest":
            messagebox.showinfo("Info", "Guest users do not have access to vulnerability scans.")
        else:
            target = self.vuln_target_entry.get()
            if not target:
                self.append_output("No target specified for vulnerability scan.\n")
                return

            self.append_output(f"Starting vulnerability scan on {target}...\nwait for few minutes...\n\n")
            self.vulnerability_scanner = VulnerabilityScanner(target)
            threading.Thread(target=self.perform_vulnerability_scan).start()

    def perform_vulnerability_scan(self):
        """Perform the vulnerability scan and display the results."""
        try:
            result = self.vulnerability_scanner.scan()
            self.append_output(f"Vulnerability Scan Results:\n{result}\n")
        except Exception as e:
            self.append_output(f"Error during vulnerability scan: {e}\n")
    
    def open_user_management(self):
        """Open the user management window if the logged-in user is an admin."""
        # Fetch user data from the database
        self.user_manager.c.execute("SELECT * FROM users WHERE username=?", (self.logged_in_user,))
        user_data = self.user_manager.c.fetchone()
        if user_data:
            user_data = {"username": user_data[0], "password": user_data[1], "role": user_data[2]}
        else:
            user_data = {}

        # Check if the user is an admin
        if user_data.get("role") == "admin":
            UserManagementWindow(self)
        else:
            messagebox.showerror("Access Denied", "You do not have permission to access this section.")

class WebScannerWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)

        self.title("Network & Web Scanner")
        self.geometry("700x500")
        self.configure(bg="#1e1e2f")

        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self.style.configure("TLabel", foreground="#ffffff", background="#1e1e2f")
        self.style.configure("TButton", background="#3e3e56", foreground="#ffffff")

        self.setup_ui()

    def setup_ui(self):
        # URL Entry
        ttk.Label(self, text="Enter Website URL (e.g., example.com):").pack(pady=5)
        self.url_entry = ttk.Entry(self, width=50)
        self.url_entry.insert(0, "www.example.com")
        self.url_entry.pack(pady=5)

        # Button Frame for horizontal layout
        button_frame = ttk.Frame(self)
        button_frame.pack(pady=5)

        # Buttons arranged left-to-right
        ttk.Button(button_frame, text="Scan Website", command=self.scan_website).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Check Open Ports", command=self.check_open_ports).pack(side="left", padx=5)
        ttk.Button(button_frame, text="SSL Certificate Info", command=self.ssl_certificate_info).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Track Route", command=self.track_route).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Export Results", command=self.export_results).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Clear Screen", command=self.clear_screen).pack(side="left", padx=5)
        # Output Text
        self.output_text = tk.Text(self, wrap="word", height=18, bg="#1e1e2f", fg="#00ff7f", font=("Courier", 12))
        self.output_text.pack(pady=5, fill="both", expand=True)

    def scan_website(self):
        url = self.url_entry.get()
        self.output_text.insert(tk.END, f"Scanning website {url}...\n")
        try:
            domain_info = whois.whois(url)
            self.output_text.insert(tk.END, f"Domain Info:\n{domain_info}\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"Error scanning website: {e}\n")

    def check_open_ports(self):
        url = self.url_entry.get()
        self.output_text.insert(tk.END, f"Checking open ports for {url}...\n")
        try:
            ip = socket.gethostbyname(url)
            open_ports = []
            for port in range(1, 1025):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex((ip, port)) == 0:
                        open_ports.append(port)

            if open_ports:
                self.output_text.insert(tk.END, f"Open ports: {open_ports}\n")
            else:
                self.output_text.insert(tk.END, "No open ports found in range 1-1024.\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"Error checking ports: {e}\n")

    def ssl_certificate_info(self):
        url = self.url_entry.get()
        self.output_text.insert(tk.END, f"Fetching SSL certificate info for {url}...\n")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((url, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=url) as ssock:
                    cert = ssock.getpeercert()
                    self.output_text.insert(tk.END, f"SSL Certificate Info:\n{cert}\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"Error fetching SSL certificate: {e}\n")

    def track_route(self):
        """Track the route to the specified website using traceroute."""
        url = self.url_entry.get()
        self.output_text.insert(tk.END, f"Tracking route to {url}...\n")

        try:
            # Resolve the IP address of the website
            ip = socket.gethostbyname(url)
            self.output_text.insert(tk.END, f"Resolved IP: {ip}\n")

            # Perform traceroute
            result, _ = traceroute(ip, maxttl=30, verbose=0)  # Set maxttl to limit the number of hops
            self.output_text.insert(tk.END, "Traceroute Results:\n")

            for sent, received in result:
                if received:
                    self.output_text.insert(tk.END, f"Hop {sent.ttl}: {received.src}\n")
                else:
                    self.output_text.insert(tk.END, f"Hop {sent.ttl}: *\n")

        except Exception as e:
            self.output_text.insert(tk.END, f"Error during traceroute: {e}\n")

    def export_results(self):
        """Export the scan results to a text file."""
        filename = f"web_scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(filename, "w") as file:
                file.write("Web Scan Results:\n")
                file.write(self.output_text.get("1.0", tk.END))  # Write all output text to the file

            messagebox.showinfo("Export Successful", f"Results exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Failed", f"Failed to export results: {e}")
            
    def clear_screen(self):
        """Clear the output text area."""
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state="disabled")

class SSHConnectionWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("SSH Connection")
        self.geometry("700x400")  # Increased height to accommodate new features
        self.configure(bg="#1e1e2f")

        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self.style.configure("TLabel", foreground="#ffffff", background="#1e1e2f")
        self.style.configure("TButton", background="#3e3e56", foreground="#ffffff")

        self.ssh_client = None  # To store the SSH client object
        self.setup_ui()

    def setup_ui(self):
        # Title Label
        ttk.Label(self, text="SSH Connection", font=("Helvetica", 16, "bold")).pack(pady=10)

        # Input Frame for horizontal layout
        input_frame = ttk.Frame(self)
        input_frame.pack(pady=10)

        # Host
        ttk.Label(input_frame, text="Host:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.host_entry = ttk.Entry(input_frame, width=20)
        self.host_entry.insert(0, "192.168.1")
        self.host_entry.grid(row=1, column=0, padx=5, pady=5)

        # Port Selection (Radio Buttons)
        ttk.Label(input_frame, text="Port:").grid(row=0, column=1, padx=5, pady=5, sticky="w")
        self.port_var = tk.IntVar(value=22)  # Default port is 22
        ttk.Radiobutton(input_frame, text="22", variable=self.port_var, value=22).grid(row=1, column=1, padx=5, pady=5, sticky="w")
        ttk.Radiobutton(input_frame, text="8022", variable=self.port_var, value=8022).grid(row=1, column=2, padx=5, pady=5, sticky="w")

        # Username
        ttk.Label(input_frame, text="Username:").grid(row=0, column=3, padx=5, pady=5, sticky="w")
        self.username_entry = ttk.Entry(input_frame, width=20)
        self.username_entry.grid(row=1, column=3, padx=5, pady=5)

        # Password
        ttk.Label(input_frame, text="Password:").grid(row=0, column=4, padx=5, pady=5, sticky="w")
        self.password_entry = ttk.Entry(input_frame, width=20, show="*")
        self.password_entry.grid(row=1, column=4, padx=5, pady=5)

        # Connect Button
        ttk.Button(input_frame, text="Connect", command=self.connect_ssh).grid(row=1, column=5, padx=10, pady=5)

        # Command Execution Frame
        command_frame = ttk.Frame(self)
        command_frame.pack(pady=10)

        ttk.Label(command_frame, text="Command:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.command_entry = ttk.Entry(command_frame, width=50)
        self.command_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Button(command_frame, text="Execute", command=self.execute_command).grid(row=0, column=2, padx=5, pady=5)
        ttk.Button(command_frame, text="Clear Screen", command=self.clear_screen).grid(row=0, column=3, padx=5, pady=5)

        # Output Text
        self.output_text = tk.Text(self, wrap="word", height=15, bg="#1e1e2f", fg="#00ff7f", font=("Courier", 12))
        self.output_text.pack(pady=10, fill="both", expand=True)

    def connect_ssh(self):
        """Connect to the remote server using SSH."""
        host = self.host_entry.get()
        port = self.port_var.get()  # Get the selected port from the radio button
        username = self.username_entry.get()
        password = self.password_entry.get()

        self.output_text.insert(tk.END, f"Connecting to {host}:{port}...\n")

        try:
            # Create an SSH client
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(host, port=port, username=username, password=password)

            self.output_text.insert(tk.END, "SSH connection established.\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"Error connecting via SSH: {e}\n")

    def execute_command(self):
        """Execute a command on the remote server."""
        if not self.ssh_client:
            self.output_text.insert(tk.END, "Error: Not connected to SSH.\n")
            return

        command = self.command_entry.get()
        if not command:
            self.output_text.insert(tk.END, "Error: No command entered.\n")
            return

        self.output_text.insert(tk.END, f"Executing command: {command}\n")

        try:
            # Execute the command
            stdin, stdout, stderr = self.ssh_client.exec_command(command)
            output = stdout.read().decode()
            errors = stderr.read().decode()

            if output:
                self.output_text.insert(tk.END, f"Command Output:\n{output}\n")
            if errors:
                self.output_text.insert(tk.END, f"Command Errors:\n{errors}\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"Error executing command: {e}\n")

    def clear_screen(self):
        """Clear the output text area."""
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state="disabled")

class BandwidthMonitor:
    def __init__(self, master, interval=1):
        self.master = master
        self.interval = interval
        self.running = False
        self.time_data = []  # Store time points
        self.usage_data = []  # Store bandwidth usage

    def start(self):
        self.running = True
        threading.Thread(target=self.monitor).start()

    def stop(self):
        self.running = False

    def monitor(self):
        old_value = psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv
        while self.running:
            new_value = psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv
            bandwidth_usage = new_value - old_value
            old_value = new_value

            # Update data
            self.time_data.append(len(self.time_data))  # Incremental time points
            self.usage_data.append(bandwidth_usage)

            # Update GUI
            self.master.update_bandwidth_output(f"Bandwidth Usage: {bandwidth_usage} bytes\n")
            self.master.update_bandwidth_graph(self.time_data, self.usage_data)

            time.sleep(self.interval)

class VulnerabilityScanner:
    def __init__(self, target):
        self.target = target

    def scan(self):
        try:
            result = subprocess.run(["nmap", "-sV", "--script=vuln", self.target], capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            return f"Error during scan: {e}"

class WebInterface:
    def __init__(self, network_scanner):
        self.network_scanner = network_scanner
        self.app = Flask(__name__)
        self.setup_routes()

    def setup_routes(self):
        @self.app.route("/")
        def index():
            return render_template("index.html")

        @self.app.route("/start_scan", methods=["POST"])
        def start_scan():
            network_prefix = request.json.get("network_prefix", "192.168.1")
            ip_range = request.json.get("ip_range", "1-254")
            self.network_scanner.start_scan(network_prefix, ip_range)
            return jsonify({"status": "Scan started"})

        @self.app.route("/stop_scan", methods=["POST"])
        def stop_scan():
            self.network_scanner.stop_scan()
            return jsonify({"status": "Scan stopped"})

        @self.app.route("/get_output", methods=["GET"])
        def get_output():
            if hasattr(self.network_scanner, "output_text") and self.network_scanner.output_text:
                output = self.network_scanner.output_text.get("1.0", tk.END)
                return jsonify({"output": output})
            return jsonify({"output": "Output not available"})

    def run(self, host="0.0.0.0", port=5000):
        self.app.run(host=host, port=port)

class UFWManagementWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("UFW Management")
        self.geometry("600x400")
        self.configure(bg="#1e1e2f")

        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self.style.configure("TLabel", foreground="#ffffff", background="#1e1e2f")
        self.style.configure("TButton", background="#3e3e56", foreground="#ffffff")

        self.setup_ui()

    def setup_ui(self):
        # UFW Status Frame
        status_frame = ttk.LabelFrame(self, text="UFW Status", padding=10)
        status_frame.pack(fill="x", padx=10, pady=10)

        # Buttons for UFW Status
        ttk.Button(status_frame, text="Enable UFW", command=self.enable_ufw).pack(side="left", padx=5, pady=5)
        ttk.Button(status_frame, text="Disable UFW", command=self.disable_ufw).pack(side="left", padx=5, pady=5)
        ttk.Button(status_frame, text="Check UFW Status", command=self.check_ufw_status).pack(side="left", padx=5, pady=5)
        ttk.Button(status_frame, text="Show Raw Rules", command=self.show_raw_rules).pack(side="left", padx=5, pady=5)

        # Clear Screen Button (placed below Show Raw Rules)
        ttk.Button(status_frame, text="Clear Screen", command=self.clear_screen).pack(side="left", padx=5, pady=5)

        # UFW Rules Frame
        rules_frame = ttk.LabelFrame(self, text="UFW Rules", padding=10)
        rules_frame.pack(fill="x", padx=10, pady=10)

        ttk.Label(rules_frame, text="Port:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.port_entry = ttk.Entry(rules_frame, width=10)
        self.port_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(rules_frame, text="Protocol:").grid(row=0, column=2, padx=5, pady=5, sticky="w")
        self.protocol_var = tk.StringVar(value="tcp")  # Default protocol is TCP
        ttk.Radiobutton(rules_frame, text="TCP", variable=self.protocol_var, value="tcp").grid(row=0, column=3, padx=5, pady=5, sticky="w")
        ttk.Radiobutton(rules_frame, text="UDP", variable=self.protocol_var, value="udp").grid(row=0, column=4, padx=5, pady=5, sticky="w")

        ttk.Button(rules_frame, text="Allow Port", command=self.allow_port).grid(row=1, column=0, columnspan=2, padx=5, pady=5)
        ttk.Button(rules_frame, text="Deny Port", command=self.deny_port).grid(row=1, column=2, columnspan=2, padx=5, pady=5)

        # Output Text
        self.output_text = tk.Text(self, wrap="word", height=15, bg="#1e1e2f", fg="#00ff7f", font=("Courier", 12))
        self.output_text.pack(pady=10, fill="both", expand=True)

    def run_command(self, command):
        """Run a shell command and return the output."""
        try:
            result = subprocess.run(command, capture_output=True, text=True, shell=True)
            if result.returncode == 0:
                return result.stdout
            else:
                return result.stderr
        except Exception as e:
            return f"Error: {e}"

    def enable_ufw(self):
        """Enable UFW."""
        output = self.run_command("sudo ufw enable")
        self.output_text.insert(tk.END, f"Enabling UFW...\n{output}\n")

    def disable_ufw(self):
        """Disable UFW."""
        output = self.run_command("sudo ufw disable")
        self.output_text.insert(tk.END, f"Disabling UFW...\n{output}\n")

    def check_ufw_status(self):
        """Check UFW status."""
        output = self.run_command("sudo ufw status verbose")
        self.output_text.insert(tk.END, f"UFW Status:\n{output}\n")

    def allow_port(self):
        """Allow a specific port."""
        port = self.port_entry.get()
        protocol = self.protocol_var.get()
        if not port:
            self.output_text.insert(tk.END, "Error: Port is required.\n")
            return

        output = self.run_command(f"sudo ufw allow {port}/{protocol}")
        self.output_text.insert(tk.END, f"Allowing port {port}/{protocol}...\n{output}\n")

    def deny_port(self):
        """Deny a specific port."""
        port = self.port_entry.get()
        protocol = self.protocol_var.get()
        if not port:
            self.output_text.insert(tk.END, "Error: Port is required.\n")
            return

        output = self.run_command(f"sudo ufw deny {port}/{protocol}")
        self.output_text.insert(tk.END, f"Denying port {port}/{protocol}...\n{output}\n")

    def show_raw_rules(self):
        """Show raw iptables rules managed by UFW."""
        output = self.run_command("sudo ufw show raw")
        self.output_text.insert(tk.END, f"Raw UFW Rules:\n{output}\n")

    def clear_screen(self):
        """Clear the output text area."""
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state="disabled")

if __name__ == "__main__":
    app = NetworkScanner()
    app.mainloop()
