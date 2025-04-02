import os
import subprocess
from typing import List, Tuple, Dict

def run_command(command):
    """Run a shell command and handle errors."""
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        exit(1)

def detect_package_manager() -> str:
    """Detect the system's package manager."""
    if os.path.exists("/etc/debian_version"):
        return "apt"
    elif os.path.exists("/etc/arch-release"):
        return "pacman"
    elif os.path.exists("/etc/fedora-release"):
        return "dnf"
    else:
        return "unknown"

def is_system_package_installed(package: str, package_manager: str) -> bool:
    """Check if a system package is installed."""
    try:
        if package_manager == "apt":
            result = subprocess.run(
                f"dpkg -l {package} | grep '^ii'",
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return bool(result.stdout.strip())
        elif package_manager == "pacman":
            result = subprocess.run(
                f"pacman -Qi {package}",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return result.returncode == 0
        elif package_manager == "dnf":
            result = subprocess.run(
                f"rpm -q {package}",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return result.returncode == 0
        else:
            return False
    except subprocess.CalledProcessError:
        return False

def is_pip_package_installed(package: str) -> bool:
    """Check if a Python package is installed via pip."""
    try:
        result = subprocess.run(
            f"pip3 show {package}",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.returncode == 0
    except subprocess.CalledProcessError:
        return False

def check_packages(packages: Dict[str, str]) -> List[Tuple[str, str, bool]]:
    """
    Check multiple packages and return their installation status.
    packages: Dict where key is package name and value is type ('system' or 'pip')
    """
    package_manager = detect_package_manager()
    if package_manager == "unknown":
        print("Unsupported Linux distribution")
        return []
    
    results = []
    for pkg, pkg_type in packages.items():
        if pkg_type == "system":
            installed = is_system_package_installed(pkg, package_manager)
        elif pkg_type == "pip":
            installed = is_pip_package_installed(pkg)
        else:
            installed = False
        results.append((pkg, pkg_type, installed))
    
    return results

def print_package_status(package_status: List[Tuple[str, str, bool]]):
    """Print the installation status of packages."""
    if not package_status:
        print("No packages to check.")
        return
    
    print("\nPackage Installation Status:")
    print("{:<20} {:<10} {}".format("Package", "Type", "Status"))
    print("-" * 40)
    
    for pkg, pkg_type, installed in package_status:
        status = "INSTALLED" if installed else "NOT INSTALLED"
        print("{:<20} {:<10} {}".format(pkg, pkg_type, status))

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
        return "debian"
    elif os.path.exists("/etc/arch-release"):
        return "arch"
    elif os.path.exists("/etc/fedora-release"):
        return "fedora"
    else:
        return "unknown"

def verify_installation():
    """Verify all required packages are installed."""
    packages_to_check = {
        # System packages
        "python3": "system",
        "python3-pip": "system",
        "sqlitebrowser": "system",
        "arp-scan": "system",
        "nmap": "system",
        
        # Python packages (installed via pip)
        "scapy": "pip",
        "matplotlib": "pip",
        "flask": "pip",
        "paramiko": "pip",
        "requests": "pip",
        "pyparsing": "pip",
        "six": "pip",
        "networkx": "pip",
        "psutil": "pip",
        "bcrypt": "pip",
        "speedtest-cli": "pip",
        "whois": "pip"
    }
    
    print("\nVerifying package installation...")
    status = check_packages(packages_to_check)
    print_package_status(status)

def main():
    distro = detect_distro()
    
    if distro == "debian":
        install_python_debian()
    elif distro == "arch":
        install_python_arch()
    elif distro == "fedora":
        install_python_fedora()
    else:
        print("Unsupported Linux distribution.")
        exit(1)
    
    verify_installation()
    print("\nAll operations completed successfully! You can now use all the installed tools.")

if __name__ == "__main__":
    main()
