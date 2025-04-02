#!/bin/bash

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

run_command() {
    echo -e "${YELLOW}Executing: $1${NC}"
    if ! eval "$1"; then
        echo -e "${RED}Error executing command: $1${NC}"
        exit 1
    fi
}

detect_distro() {
    if [ -f "/etc/debian_version" ]; then
        echo "debian"
    elif [ -f "/etc/arch-release" ]; then
        echo "arch"
    elif [ -f "/etc/fedora-release" ]; then
        echo "fedora"
    else
        echo "unknown"
    fi
}

is_system_package_installed() {
    local pkg=$1
    case $(detect_distro) in
        "debian")
            dpkg -l "$pkg" | grep -q '^ii' >/dev/null 2>&1
            return $?
            ;;
        "arch")
            pacman -Qi "$pkg" >/dev/null 2>&1
            return $?
            ;;
        "fedora")
            rpm -q "$pkg" >/dev/null 2>&1
            return $?
            ;;
        *)
            return 1
            ;;
    esac
}

is_pip_package_installed() {
    pip3 show "$1" >/dev/null 2>&1
    return $?
}

print_package_status() {
    local pkg=$1
    local pkg_type=$2
    local installed=$3
    
    if [ "$installed" -eq 0 ]; then
        printf "%-20s %-10s ${GREEN}%s${NC}\n" "$pkg" "$pkg_type" "INSTALLED"
    else
        printf "%-20s %-10s ${RED}%s${NC}\n" "$pkg" "$pkg_type" "NOT INSTALLED"
    fi
}

verify_installation() {
    declare -A packages_to_check=(
        # System packages
        ["python3"]="system"
        ["python3-pip"]="system"
        ["sqlitebrowser"]="system"
        ["arp-scan"]="system"
        ["nmap"]="system"
        
        # Python packages
        ["scapy"]="pip"
        ["matplotlib"]="pip"
        ["flask"]="pip"
        ["paramiko"]="pip"
        ["requests"]="pip"
        ["pyparsing"]="pip"
        ["six"]="pip"
        ["networkx"]="pip"
        ["psutil"]="pip"
        ["bcrypt"]="pip"
        ["speedtest-cli"]="pip"
        ["whois"]="pip"
    )

    echo -e "\nVerifying package installation..."
    echo -e "Package             Type       Status"
    echo -e "----------------------------------------"

    for pkg in "${!packages_to_check[@]}"; do
        pkg_type="${packages_to_check[$pkg]}"
        
        if [ "$pkg_type" == "system" ]; then
            is_system_package_installed "$pkg"
        else
            is_pip_package_installed "$pkg"
        fi
        print_package_status "$pkg" "$pkg_type" $?
    done
}

install_debian() {
    echo -e "${YELLOW}Installing Python3 and related packages for Debian/Ubuntu...${NC}"
    run_command "sudo apt update && sudo apt upgrade -y"
    run_command "sudo apt install -y python3-pip sqlitebrowser arp-scan nmap"
    run_command "pip3 install pyparsing six scapy networkx matplotlib psutil bcrypt paramiko speedtest-cli flask whois"
    echo -e "\n${GREEN}Installation complete for Debian/Ubuntu. Now run your Python scripts...!!!${NC}"
}

install_arch() {
    echo -e "${YELLOW}Installing Python3 and related packages for Arch Linux...${NC}"
    run_command "sudo pacman -Syu --noconfirm"
    run_command "sudo pacman -S --noconfirm python-pip sqlitebrowser arp-scan nmap"
    run_command "pip3 install pyparsing six scapy networkx matplotlib psutil bcrypt paramiko speedtest-cli flask whois"
    echo -e "\n${GREEN}Installation complete for Arch Linux. Now run your Python scripts...!!!${NC}"
}

install_fedora() {
    echo -e "${YELLOW}Installing Python3 and related packages for Fedora...${NC}"
    run_command "sudo dnf update -y"
    run_command "sudo dnf install -y python3-pip sqlitebrowser arp-scan nmap"
    run_command "pip3 install pyparsing six scapy networkx matplotlib psutil bcrypt paramiko speedtest-cli flask whois"
    echo -e "\n${GREEN}Installation complete for Fedora. Now run your Python scripts...!!!${NC}"
}

main() {
    distro=$(detect_distro)
    
    case $distro in
        "debian")
            install_debian
            ;;
        "arch")
            install_arch
            ;;
        "fedora")
            install_fedora
            ;;
        *)
            echo -e "${RED}Unsupported Linux distribution.${NC}"
            exit 1
            ;;
    esac
    
    verify_installation
    echo -e "\n${GREEN}All operations completed successfully! You can now use all the installed tools.${NC}"
}

main "$@"
