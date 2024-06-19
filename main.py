import subprocess
import os

def clear_screen():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

def run_command(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        result.check_returncode()
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error executing comamand: {e}\nError details: {e.stderr}"
    except Exception as e:
        return f"Unknown Error: {str(e)}"  

def check_antivirus():
    output = subprocess.run(['wmic', '/namespace:\\\\root\\SecurityCenter2', 'path', 'AntiVirusProduct', 'get', 'displayName'], capture_output=True, text=True)
    if "displayName" in output.stdout:
        return f"Antivírus Installed: {output.stdout.split()[1]}"
    return "No antivírus installed."

def check_windows_updates():
    output = subprocess.run(['powershell', '-Command', '(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0").Updates.Count'], capture_output=True, text=True)
    updates = int(output.stdout.strip())
    if updates > 0:
        return f"Pending updates: {updates}"
    return "No update pending."

def check_firewall():
    output = subprocess.run(['powershell', '-Command', 'Get-NetFirewallProfile -Profile Domain,Public,Private | Select-Object -ExpandProperty Enabled'], capture_output=True, text=True)
    if 'True' in output.stdout:
        return "Firewall is activated."
    return "Firewall is deactivated."

def check_uac():
    output = subprocess.run(['powershell', '-Command', 'Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System | Select-Object -ExpandProperty EnableLUA'], capture_output=True, text=True)
    if '1' in output.stdout.strip():
        return "UAC is activated."
    return "UAC is deactivated."

def check_startup_programs():
    output = subprocess.run(['powershell', '-Command', 'Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User'], capture_output=True, text=True)
    return f"Inicialization programs: {output.stdout}"

def check_windows_services():
    output = subprocess.run(['powershell', '-Command', 'Get-Service | Where-Object {$_.Status -eq "Running"} | Format-Table Name, DisplayName, StartType, Status -AutoSize'], capture_output=True, text=True)
    return f"Running windows services:\n{output.stdout}"

def check_open_ports():
    output = subprocess.run(['powershell', '-Command', 'Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"}'], capture_output=True, text=True)
    return f"Open/Available ports:\n{output.stdout}"

def check_security_patches():
    output = subprocess.run(['powershell', '-Command', 'Get-HotFix | Select-Object Description, HotFixID, InstalledOn'], capture_output=True, text=True)
    return f"Security patches installed:\n{output.stdout}"

def check_user_accounts():
    output = run_command(['powershell', '-Command', 'Get-LocalUser | Select-Object Name,Enabled,PasswordNeverExpires'])
    return f"Windows user accounts:\n{output}"

def check_password_policies():
    output = run_command(['powershell', '-Command', 'Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters" | Select-Object RequireStrongKey,MaximumPasswordAge,MinimumPasswordAge,MinimumPasswordLength,PasswordHistorySize'])
    return f"Password politics:\n{output}"

def check_installed_software():
    output = run_command(['powershell', '-Command', 'Get-WmiObject -Class Win32_Product | Select-Object Name,Version,Vendor'])
    return f"Installed sotfware:\n{output}"

def check_network_shares():
    output = run_command(['powershell', '-Command', 'Get-SmbShare | Select-Object Name,Path,Description'])
    return f"Network shares:\n{output}"

def check_disk_encryption():
    try:
        command = ['powershell', '-Command', 'Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,ProtectionStatus']
        result = subprocess.run(command, capture_output=True, text=True)
        result.check_returncode()
        if "MountPoint" in result.stdout:
            return f"Disk encryption:\n{result.stdout}"
        else:
            return "No volume with BitLocker (encryption) found."
    except subprocess.CalledProcessError as e:
        return f"Error executing command: {e}\nError details: {e.stderr.decode() if e.stderr else 'No details available.'}"
    except Exception as e:
        return f"Unknown error: {str(e)}"

def check_critical_services():
    services = ["wuauserv", "windefend"]
    results = []
    for service in services:
        command = ['powershell', '-Command', f'Get-Service -Name {service} | Select-Object Name, Status']
        output = run_command(command)
        results.append(output)
    return "Critical services status:\n" + "\n".join(results)

def check_all():
    results = [
        "Antivírus: " + check_antivirus(),
        "Windows Update: " + check_windows_updates(),
        "Firewall: " + check_firewall(),
        "UAC: " + check_uac(),
        "Inicialization programs: " + check_startup_programs(),
        "Windows services: " + check_windows_services(),
        "Open ports: " + check_open_ports(),
        "Security patches: " + check_security_patches(),
        "User accounts: " + check_user_accounts(),
        "Password politics: " + check_password_policies(),
        "Installed software: " + check_installed_software(),
        "Network shares: " + check_network_shares(),
        "Disk encryption: " + check_disk_encryption(),
        "Windows critical services: " + check_critical_services()
    ]
    return "\n\n".join(results)

def menu():
    functions = {
        '1': check_antivirus,
        '2': check_windows_updates,
        '3': check_firewall,
        '4': check_uac,
        '5': check_startup_programs,
        '6': check_windows_services,
        '7': check_open_ports,
        '8': check_security_patches,
        '9': check_user_accounts,
        '10': check_password_policies,
        '11': check_installed_software,
        '12': check_network_shares,
        '13': check_disk_encryption,
        '14': check_critical_services,
        '15': check_all
    }
    while True:
        clear_screen()
        print("\nSecurity checkout verification menu:")
        for i in range(1, 16):
            print(f"{i}. {functions[str(i)].__name__.replace('_', ' ').capitalize()}")
        print("0. Close program")
        choice = input("Choose an option: ")
        if choice == '0':
            break
        elif choice in functions:
            result = functions[choice]()
            print(result)
            input("Press Enter to continue...")
            clear_screen()
        else:
            print("Invalid option, try again.")

if __name__ == "__main__":
    menu()
