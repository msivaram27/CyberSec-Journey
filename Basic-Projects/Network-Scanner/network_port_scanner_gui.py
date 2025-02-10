import socket
from ipaddress import ip_network
import tkinter as tk
from tkinter import scrolledtext
import subprocess


# Check if a host is active by pinging it using subprocess
def is_host_active(ip):
    try:
        print(f"Attempting to ping {ip}...")  # Debug statement
        response = subprocess.run(["ping", "-n", "1", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if response.returncode == 0:
            print(f"{ip} is UP.")  # Debug statement
            return True
        else:
            print(f"{ip} is DOWN.")  # Debug statement
            return False
    except Exception as e:
        print(f"Error while pinging {ip}: {str(e)}")  # Debug statement
        return False


# Function to scan common ports on an IP address
def scan_ports(ip):
    common_ports = [22, 80, 443, 21, 53, 25, 110, 8080]  # Define common ports
    open_ports = []
    for port in common_ports:
        try:
            print(f"Attempting to scan port {port} on {ip}...")  # Debug statement
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # Timeout after 1 second
            result = sock.connect_ex((ip, port))  # Try connecting to the port
            if result == 0:  # If the connection is successful, the port is open
                open_ports.append(port)
                print(f"Port {port} on {ip} is open.")  # Debug statement
            sock.close()  # Always close the socket after checking
        except Exception as e:
            print(f"Error while scanning port {port} on {ip}: {str(e)}")  # Debug statement
    return open_ports


# Function to start the scan when the user clicks the 'Scan' button
def start_scan():
    ip_range = entry_network.get()  # Get network range input from user
    ip_parts = ip_range.split('-')

    # Extract the start and end IPs from input range (e.g., 10.123.53.84-100)
    try:
        start_ip = ip_parts[0]
        start_ip_parts = start_ip.split('.')
        end_ip = ip_parts[1]

        # Loop through the IP range
        output_text.delete(1.0, tk.END)  # Clear previous output

        for last_octet in range(int(start_ip_parts[3]), int(end_ip) + 1):
            ip_to_scan = f"{start_ip_parts[0]}.{start_ip_parts[1]}.{start_ip_parts[2]}.{last_octet}"

            print(f"Scanning IP: {ip_to_scan}")  # Debug statement
            if is_host_active(ip_to_scan):  # Check if the host is active
                output_text.insert(tk.END, f"{ip_to_scan} is UP.\n")
                open_ports = scan_ports(ip_to_scan)
                if open_ports:
                    open_ports_str = ', '.join(map(str, open_ports))  # Join the open ports in string format
                    output_text.insert(tk.END, f"Active Ports on {ip_to_scan}: {open_ports_str}\n")
                else:
                    output_text.insert(tk.END, f"No active ports found on {ip_to_scan}\n")
            else:
                output_text.insert(tk.END, f"{ip_to_scan} is DOWN.\n")  # If the host is not active

    except Exception as e:
        output_text.insert(tk.END, f"Error: {str(e)}")
        print(f"Error in range parsing: {str(e)}")  # Debug statement


# Setting up the GUI using Tkinter
root = tk.Tk()
root.title("Network Port Scanner")

# Create and place labels and entry fields
label_network = tk.Label(root, text="Enter IP Range (e.g., 10.123.53.84-100):")
label_network.pack(padx=10, pady=5)

entry_network = tk.Entry(root, width=40)
entry_network.pack(padx=10, pady=5)

# Create and place the Scan Button
scan_button = tk.Button(root, text="Start Scan", command=start_scan)
scan_button.pack(pady=10)

# Create and place the output text area
output_text = scrolledtext.ScrolledText(root, width=60, height=20)
output_text.pack(padx=10, pady=5)

# Start the Tkinter main loop
root.mainloop()
