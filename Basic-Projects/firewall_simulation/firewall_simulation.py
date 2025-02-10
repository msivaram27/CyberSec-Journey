import random
import time
import threading
import tkinter as tk
from tkinter import messagebox


# Define Packet Class
class Packet:
    def __init__(self, source_ip, dest_ip, port, protocol):
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.port = port
        self.protocol = protocol


# Define Firewall Rule Class
class FirewallRule:
    def __init__(self, source_ip, dest_ip, port, protocol, action):
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.port = port
        self.protocol = protocol
        self.action = action

    def matches(self, packet):
        if (self.source_ip == "ANY" or self.source_ip == packet.source_ip) and \
                (self.dest_ip == "ANY" or self.dest_ip == packet.dest_ip) and \
                (self.port == "ANY" or self.port == packet.port) and \
                (self.protocol == "ANY" or self.protocol == packet.protocol):
            return True
        return False


# Function for Random Packet Generation
def generate_random_packet():
    source_ips = ["192.168.0.1", "10.0.0.1", "172.16.0.1"]
    dest_ips = ["192.168.0.2", "8.8.8.8", "172.16.0.2"]
    ports = [80, 443, 22, 53]
    protocols = ["TCP", "UDP", "ICMP"]

    source_ip = random.choice(source_ips)
    dest_ip = random.choice(dest_ips)
    port = random.choice(ports)
    protocol = random.choice(protocols)

    packet = Packet(source_ip, dest_ip, port, protocol)
    return packet


# Function to Apply Firewall Rules to Packets
def apply_firewall_rules(packet, firewall_rules):
    matched = False
    for rule in firewall_rules:
        if rule.matches(packet):
            matched = True
            if rule.action == "ALLOW":
                return f"Packet ALLOWED by rule: {rule.__dict__}"
            else:
                return f"Packet DENIED by rule: {rule.__dict__}"
    if not matched:
        return "No matching rule found. Packet DENIED by default."


# Function to Update Random Packets Periodically
def generate_random_packets_periodically(interval, firewall_rules, result_text_widget):
    while True:
        packet = generate_random_packet()
        result = apply_firewall_rules(packet, firewall_rules)
        result_text_widget.insert(tk.END, f"Generated Packet: {packet.__dict__}\n{result}\n\n")
        time.sleep(interval)


# Function to Handle Manual Packet Submission
def submit_manual_packet(firewall_rules, result_text_widget, source_ip_entry, dest_ip_entry, port_entry,
                         protocol_entry):
    source_ip = source_ip_entry.get()
    dest_ip = dest_ip_entry.get()
    port = port_entry.get()
    protocol = protocol_entry.get()

    if not source_ip or not dest_ip or not port or not protocol:
        messagebox.showwarning("Input Error", "Please fill in all fields.")
        return

    packet = Packet(source_ip, dest_ip, port, protocol)
    result = apply_firewall_rules(packet, firewall_rules)
    result_text_widget.insert(tk.END, f"Manually Created Packet: {packet.__dict__}\n{result}\n\n")


# Function to Handle Rule Submission
def add_firewall_rule(firewall_rules, source_ip_rule, dest_ip_rule, port_rule, protocol_rule, action_rule):
    source_ip = source_ip_rule.get()
    dest_ip = dest_ip_rule.get()
    port = port_rule.get()
    protocol = protocol_rule.get()
    action = action_rule.get()

    if not source_ip or not dest_ip or not port or not protocol or not action:
        messagebox.showwarning("Input Error", "Please fill in all fields.")
        return

    # Add the rule to the list of firewall rules
    new_rule = FirewallRule(source_ip, dest_ip, port, protocol, action)
    firewall_rules.append(new_rule)
    messagebox.showinfo("Success", "Firewall rule added successfully!")


# Main GUI Function
def create_gui():
    # Define initial firewall rules
    firewall_rules = [
        FirewallRule("192.168.0.1", "ANY", "80", "TCP", "ALLOW"),
        FirewallRule("ANY", "8.8.8.8", "ANY", "ANY", "DENY"),
        FirewallRule("ANY", "ANY", "22", "TCP", "ALLOW")
    ]

    # Create main window
    window = tk.Tk()
    window.title("Firewall Rules Simulation")
    window.geometry("600x500")

    # --- Firewall Rule Inputs Section ---
    tk.Label(window, text="Set Firewall Rule").grid(row=0, column=0, columnspan=2, pady=10)

    tk.Label(window, text="Source IP:").grid(row=1, column=0, padx=10, pady=5)
    source_ip_rule = tk.Entry(window)
    source_ip_rule.grid(row=1, column=1, padx=10, pady=5)

    tk.Label(window, text="Destination IP:").grid(row=2, column=0, padx=10, pady=5)
    dest_ip_rule = tk.Entry(window)
    dest_ip_rule.grid(row=2, column=1, padx=10, pady=5)

    tk.Label(window, text="Port:").grid(row=3, column=0, padx=10, pady=5)
    port_rule = tk.Entry(window)
    port_rule.grid(row=3, column=1, padx=10, pady=5)

    tk.Label(window, text="Protocol:").grid(row=4, column=0, padx=10, pady=5)
    protocol_rule = tk.Entry(window)
    protocol_rule.grid(row=4, column=1, padx=10, pady=5)

    tk.Label(window, text="Action (ALLOW/DENY):").grid(row=5, column=0, padx=10, pady=5)
    action_rule = tk.Entry(window)
    action_rule.grid(row=5, column=1, padx=10, pady=5)

    # Add rule button
    add_rule_button = tk.Button(window, text="Add Firewall Rule",
                                command=lambda: add_firewall_rule(firewall_rules, source_ip_rule, dest_ip_rule,
                                                                  port_rule, protocol_rule, action_rule))
    add_rule_button.grid(row=6, column=0, columnspan=2, pady=10)

    # --- Manual Packet Input Section ---
    tk.Label(window, text="Enter Manual Packet").grid(row=7, column=0, columnspan=2, pady=10)

    tk.Label(window, text="Source IP:").grid(row=8, column=0, padx=10, pady=5)
    source_ip_entry = tk.Entry(window)
    source_ip_entry.grid(row=8, column=1, padx=10, pady=5)

    tk.Label(window, text="Destination IP:").grid(row=9, column=0, padx=10, pady=5)
    dest_ip_entry = tk.Entry(window)
    dest_ip_entry.grid(row=9, column=1, padx=10, pady=5)

    tk.Label(window, text="Port:").grid(row=10, column=0, padx=10, pady=5)
    port_entry = tk.Entry(window)
    port_entry.grid(row=10, column=1, padx=10, pady=5)

    tk.Label(window, text="Protocol:").grid(row=11, column=0, padx=10, pady=5)
    protocol_entry = tk.Entry(window)
    protocol_entry.grid(row=11, column=1, padx=10, pady=5)

    # Submit button for manual packet input
    submit_button = tk.Button(window, text="Submit Manual Packet",
                              command=lambda: submit_manual_packet(firewall_rules, result_text_widget, source_ip_entry,
                                                                   dest_ip_entry, port_entry, protocol_entry))
    submit_button.grid(row=12, column=0, columnspan=2, pady=10)

    # --- Results Section ---
    result_text_widget = tk.Text(window, height=10, width=70)
    result_text_widget.grid(row=13, column=0, columnspan=2, padx=10, pady=10)

    # Start random packet generation in a separate thread
    threading.Thread(target=generate_random_packets_periodically, args=(2, firewall_rules, result_text_widget),
                     daemon=True).start()

    # Start the GUI loop
    window.mainloop()


# Run the program
if __name__ == "__main__":
    create_gui()
