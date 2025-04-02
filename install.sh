#!/bin/bash

# Function to run a command and handle errors
run_command() {
    echo "Executing: $1"
    if ! eval "$1"; then
        echo "Error executing command: $1"
        exit 1
    fi
}

install_python_debian() {
    echo "Installing Python3 and related packages for Debian/Ubuntu..."
    run_command "sudo apt update && sudo apt upgrade -y"
    run_command "sudo apt install -y python3-pip sqlitebrowser arp-scan nmap"
    run_command "pip3 install pyparsing six scapy networkx matplotlib psutil bcrypt paramiko speedtest-cli flask whois tk"
    echo -e "\nInstallation complete for Debian/Ubuntu. Now run your Python scripts...!!!"
}

install_python_arch() {
    echo "Installing Python3 and related packages for Arch Linux..."
    run_command "sudo pacman -Syu --noconfirm"
    run_command "sudo pacman -S --noconfirm python-pip sqlitebrowser arp-scan nmap"
    run_command "pip3 install pyparsing six scapy networkx matplotlib psutil bcrypt paramiko speedtest-cli flask whois tk"
    echo -e "\nInstallation complete for Arch Linux. Now run your Python scripts...!!!"
}

install_python_fedora() {
    echo "Installing Python3 and related packages for Fedora..."
    run_command "sudo dnf update -y"
    run_command "sudo dnf install -y python3-pip sqlitebrowser arp-scan nmap"
    run_command "pip3 install pyparsing six scapy networkx matplotlib psutil bcrypt paramiko speedtest-cli flask whois tk"
    echo -e "\nInstallation complete for Fedora. Now run your Python scripts...!!!"
}

detect_distro() {
    if [ -f "/etc/debian_version" ]; then
        install_python_debian
    elif [ -f "/etc/arch-release" ]; then
        install_python_arch
    elif [ -f "/etc/fedora-release" ]; then
        install_python_fedora
    else
        echo "Unsupported Linux distribution."
        exit 1
    fi
}

# Main execution
detect_distro
