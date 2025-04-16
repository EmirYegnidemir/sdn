from scapy.all import *
import Tkinter as tk
import ttk
import subprocess
import socket
import os
import sys
import logging
import threading
import json
import datetime


class DefenderApp:
    def __init__(self, root):
        self.script_choices = ["sql_injection.py", "receive_mac.py", "mitm.py", "ddos.py"]
        self.defender_ip = ''
        self.defender_port = 54321
        self.blocked_hosts = []
        self.defender_socket = None
        self.root = root
        self.setup_ui()
        logging.basicConfig(filename='defender.log', level=logging.INFO)

    def setup_ui(self):
        self.root.geometry('1200x400')
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # defender tab
        self.tab1 = ttk.Frame(self.notebook)
        self.notebook.add(self.tab1, text='Defender')

        self.paned_window = tk.PanedWindow(self.tab1, orient=tk.HORIZONTAL)
        self.paned_window.pack(fill=tk.BOTH, expand=True)

        self.frame1 = tk.Frame(self.paned_window, width=200, height=300, relief=tk.SUNKEN)
        self.paned_window.add(self.frame1)

        self.frame2 = tk.Frame(self.paned_window, width=600, height=400, relief=tk.SUNKEN)
        self.paned_window.add(self.frame2)

        self.script_label = tk.Label(self.frame1, text="Select the attack type to defend against:")
        self.script_label.grid(row=0, column=0, padx=10, pady=10)

        self.script_var = tk.StringVar(self.root)
        self.script_var.set(self.script_choices[0])

        self.script_menu = tk.OptionMenu(self.frame1, self.script_var, *self.script_choices)
        self.script_menu.grid(row=1, column=0, padx=10, pady=10)

        self.run_button = tk.Button(self.frame1, text="Run Script", command=self.run_script)
        self.run_button.grid(row=2, column=0, padx=10, pady=10)

        self.result_text = tk.Text(self.frame2, width=80, height=20)
        self.result_text.grid(row=0, column=0, padx=10, pady=10)

        # blocked hosts tab
        self.tab2 = ttk.Frame(self.notebook)
        self.notebook.add(self.tab2, text='Blocked Hosts')

        # Add a new column for the checkboxes
        self.blocked_hosts_list = ttk.Treeview(self.tab2, columns=('IP Address', 'Reason', 'Date/Time'), show='headings')
        self.blocked_hosts_list.heading('IP Address', text='IP Address')
        self.blocked_hosts_list.heading('Reason', text='Reason')
        self.blocked_hosts_list.heading('Date/Time', text='Date/Time')
        self.blocked_hosts_list.pack(fill=tk.BOTH, expand=True)

        # Create the button
        self.unblock_button = tk.Button(self.tab2, text="Unblock Selected", command=self.unblock_selected)
        self.unblock_button.pack()


    def unblock_selected(self):
        for item in self.blocked_hosts_list.selection():
            client = self.blocked_hosts_list.set(item, 'IP Address')
            custom_packet = Ether(src="00:00:00:00:00:03", dst="00:00:00:00:00:06") / IP(dst=client) / UDP(dport=12345) / "unblock"
            sendp(custom_packet, iface="h3-eth0")
            self.blocked_hosts_list.delete(item)

    def execute_script(self, script_name, msg):
        try:
            if script_name == "sql_injection.py":  # HANDLE SQL INJECTION SCRIPT!!!!!!
                process = subprocess.Popen(["python2.7", script_name, msg], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
                stdout, stderr = process.communicate()
                return stdout.strip()
            else:
                process = subprocess.Popen(["python2.7", script_name])
        except Exception as e:
            print("Error executing script:", str(e))
            return "Error"


    def run_script(self):
        # Clear the text widget
        self.result_text.delete('1.0', tk.END)

        # Close the socket if it's open
        if self.defender_socket:
            self.defender_socket.close()

        # Increment the port number
        self.defender_port += 1
        with open('port.txt', 'w') as f:
            f.write(str(self.defender_port))

        # Display and log the messageexecute_script
        self.log_and_display_message("Defender is ready to receive and inspect messages for {}\n".format(self.script_var.get())[:-3])

        # Start a new thread for the script logic
        threading.Thread(target=self.script_logic).start()


        # If the selected script is "sql_injection.py", schedule this method to be called again in 10 seconds
        if self.script_var.get() == "sql_injection.py":
            self.root.after(10000, self.run_script)  # 10000 milliseconds = 10 seconds

    def script_logic(self): # why we separated script_logic from run_script? - to run the script in a separate thread because it is a blocking operation
        self.setup_socket()

        while True:
            selected_script = self.script_var.get()
            if self.defender_socket: # If the socket is not closed
                if selected_script == "sql_injection.py":
                    connection, address = self.defender_socket.accept()
                    message = connection.recv(1024).decode()
                    self.handle_sql_injection_script(message)
                elif selected_script == "receive_mac.py":
                    self.handle_receive_mac_script()
                elif selected_script == "mitm.py":
                    connection, address = self.defender_socket.accept()
                    message = connection.recv(1024).decode()
                    self.handle_mitm_script(message)
                elif selected_script == "ddos.py":
                    connection, address = self.defender_socket.accept()
                    message = connection.recv(1024).decode()
                    self.handle_ddos_script(message)

            self.defender_socket.close()
            break

    def setup_socket(self):

        self.defender_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.defender_socket.bind((self.defender_ip, self.defender_port))
        self.defender_socket.listen(5)
        self.defender_port = self.defender_port + 1

    def handle_sql_injection_script(self, message):
        ml_result = self.execute_script("sql_injection.py", message)
        current_time = datetime.datetime.now()
        self.log_and_display_message("\nTime: " + str(current_time) + " Machine Learning Result: " + ml_result + "\n")

        if ml_result == "ALERT :::: This can be SQLi attack":
            self.send_alert_packet('SQLi')
            self.log_and_display_message("\nTime: " + str(current_time) + " Packet sent to controller\n")
        else:
            self.log_and_display_message("\nTime: " + str(current_time) + " No packet sent to controller\n")

    def handle_mitm_script(self, message):
        ml_result = self.execute_script("../mitm/mitm.py", message)
        current_time = datetime.datetime.now()
        self.log_and_display_message("\nTime: " + str(current_time) + " Machine Learning Result: " + ml_result + "\n")
        
        if ml_result == "ALERT :::: This can be MitM attack":
            self.send_alert_packet('MitM')
            self.log_and_display_message("\nTime: " + str(current_time) + " Packet sent to controller\n")
        else:
            self.log_and_display_message("\nTime: " + str(current_time) + " No packet sent to controller\n")

    def handle_ddos_script(self, message):
        ml_result = self.execute_script("../ddos/ddos.py", message)
        current_time = datetime.datetime.now()
        self.log_and_display_message("\nTime: " + str(current_time) + " Machine Learning Result: " + ml_result + "\n")
        
        if ml_result == "ALERT :::: This can be DDoS attack":
            self.send_alert_packet('DDoS')
            self.log_and_display_message("\nTime: " + str(current_time) + " Packet sent to controller\n")
        else:
            self.log_and_display_message("\nTime: " + str(current_time) + " No packet sent to controller\n")


    def handle_receive_mac_script(self):
        self.execute_script("receive_mac.py", "")
        
        # Read the JSON string from the file
        with open('arp_table.json', 'r') as f:
            arp_table_json = f.read()

        # Convert the JSON string to a dictionary
        arp_table = json.loads(arp_table_json)


    def log_and_display_message(self, message):
        # Log the message
        logging.info(message)
        # Display the message
        self.result_text.insert(tk.END, message)
        self.result_text.see(tk.END)  # Auto-scroll to the end

    def send_alert_packet(self, reason):
        with open('client_ip.txt', 'r') as f:
            client = str(f.read())
        custom_packet = Ether(src="00:00:00:00:00:03", dst="00:00:00:00:00:05") / IP(dst=client) / UDP(dport=12345) / "block"
        sendp(custom_packet, iface="h3-eth0")
        # Add the client IP, reason, and current date and time to the blocked hosts list
        self.blocked_hosts_list.insert('', 'end', values=(client, reason, datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        
    def stop_script(self):
        self.continue_loop = False
        if self.defender_socket is not None:
            self.defender_socket.close()
        self.result_text.insert(tk.END, "Script stopped\n")


root = tk.Tk()
app = DefenderApp(root)
root.mainloop()