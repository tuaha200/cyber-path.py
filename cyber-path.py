from netmiko import ConnectHandler
import difflib

# Device connection details
device = {
    'device_type': 'cisco_ios',
    'host': '192.168.56.101',      # IP address
    'username': 'prne',            # Username
    'password': 'cisco123!',       # Password
    'secret': 'cisco12345!',       # Enable secret password
}

# Define Cisco hardening advice 
hardening_advice = """
service password-encryption
no ip http server
no ip http secure-server
ip ssh version 2
no service telnet
logging buffered
ntp server 192.168.1.100
"""

# Syslog server IP
syslog_server = '192.168.1.100' 


def fetch_running_config(device):
    """Fetch the running config from the device."""
    net_connect = ConnectHandler(**device)
    net_connect.enable()

    # Fetch the running configuration
    running_config = net_connect.send_command('show running-config')
    return running_config

def compare_configurations(running_config, hardening_advice):
    """Compare running configuration with the hardening advice."""
    diff = difflib.unified_diff(
        running_config.splitlines(),
        hardening_advice.splitlines(),
        fromfile='Running Config',
        tofile='Hardening Advice',
    )
    print("\nConfiguration Comparison (Task 1):\n")
    for line in diff:
        print(line)


def enable_syslog_on_device(device, syslog_server):
    """Configure the device to send syslog messages to a syslog server."""
    net_connect = ConnectHandler(**device)
    net_connect.enable()

    # Configure syslog on the device
    config_commands = [
        f'logging {syslog_server}',        # Set syslog server IP
        'logging trap informational',      # Set the logging level (Informational)
        'logging source-interface Vlan1',  
        'logging on'                       # Enable logging
    ]
    
    # Send configuration commands to the device
    net_connect.send_config_set(config_commands)
    print("\nSyslog Configuration Applied (Task 2):\nSyslog server:", syslog_server)

def main():
    # Task 1: Compare the running config with hardening advice
    running_config = fetch_running_config(device)
    compare_configurations(running_config, hardening_advice)

    # Task 2: Enable syslog on the device
    enable_syslog_on_device(device, syslog_server)

    # Hardening checks dictionary (improvements can be made here to be more dynamic)
    hardening_checks = {
        "SSH enabled": "ip ssh version 2",
        "Telnet disabled": "no service telnet",
        "Password encryption": "service password-encryption",
        "Logging enabled": "logging buffered",
        "NTP configured": "ntp server"
    }

    def check_hardening(running_config):
        # Loop through the hardening checks
        for check, rule in hardening_checks.items():
            if rule in running_config:
                print(f"[PASS] {check}")
            else:
                print(f"[FAIL] {check}")

    # Perform hardening checks
    check_hardening(running_config)

if __name__ == "__main__":
    main()