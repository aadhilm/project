import os
import subprocess

def run_command(command):
    """Run a shell command and handle errors."""
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        exit(1)

def install_python_debian():
    print("Installing Python3 and related packages for Debian/Ubuntu...")
    run_command("sudo apt update && sudo apt upgrade -y")
    run_command("sudo apt install -y python3-pip sqlitebrowser arp-scan nmap")
    run_command("pip3 install pyparsing six scapy networkx matplotlib psutil bcrypt paramiko speedtest-cli flask whois tk")
    print("\nInstallation complete for Debian/Ubuntu. Now run your Python scripts...!!!")

def install_python_arch():
    print("Installing Python3 and related packages for Arch Linux...")
    run_command("sudo pacman -Syu --noconfirm")
    run_command("sudo pacman -S --noconfirm python-pip sqlitebrowser arp-scan nmap")
    run_command("pip3 install pyparsing six scapy networkx matplotlib psutil bcrypt paramiko speedtest-cli flask whois tk")
    print("\nInstallation complete for Arch Linux. Now run your Python scripts...!!!")

def install_python_fedora():
    print("Installing Python3 and related packages for Fedora...")
    run_command("sudo dnf update -y")
    run_command("sudo dnf install -y python3-pip sqlitebrowser arp-scan nmap")
    run_command("pip3 install pyparsing six scapy networkx matplotlib psutil bcrypt paramiko speedtest-cli flask whois tk")
    print("\nInstallation complete for Fedora. Now run your Python scripts...!!!")

def detect_distro():
    if os.path.exists("/etc/debian_version"):
        install_python_debian()
    elif os.path.exists("/etc/arch-release"):
        install_python_arch()
    elif os.path.exists("/etc/fedora-release"):
        install_python_fedora()
    else:
        print("Unsupported Linux distribution.")
        exit(1)

if __name__ == "__main__":
    detect_distro()
