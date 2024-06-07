import subprocess

def check_antivirus():
    antivirus_installed = False
    output = subprocess.run(['wmic', '/namespace:\\\\root\\SecurityCenter2', 'path', 'AntiVirusProduct', 'get', 'displayName'], capture_output=True, text=True)
    if "displayName" in output.stdout and len(output.stdout.split('\n')) > 1:
        antivirus_installed = True
    return antivirus_installed

def check_windows_updates():
    output = subprocess.run(['powershell', '-Command', '(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0").Updates.Count'], capture_output=True, text=True)
    return output.stdout.strip() != "0"

def check_firewall():
    firewall_status = False
    output = subprocess.run(['powershell', '-Command', 'Get-NetFirewallProfile -Profile Domain,Public,Private | Select-Object -ExpandProperty Enabled'], capture_output=True, text=True)
    if 'True' in output.stdout:
        firewall_status = True
    return firewall_status

def check_uac():
    output = subprocess.run(['powershell', '-Command', 'Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System | Select-Object -ExpandProperty EnableLUA'], capture_output=True, text=True)
    return "Ativado" if output.stdout.strip() == "1" else "Desativado"

def check_startup_programs():
    output = subprocess.run(['powershell', '-Command', 'Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User'], capture_output=True, text=True)
    return output.stdout.strip()

def check_windows_services():
    output = subprocess.run(['powershell', '-Command', 'Get-Service | Where-Object {$_.Status -eq "Running"} | Format-Table Name, DisplayName, StartType, Status -AutoSize'], capture_output=True, text=True)
    return output.stdout.strip()

def check_open_ports():
    output = subprocess.run(['powershell', '-Command', 'Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"}'], capture_output=True, text=True)
    return output.stdout.strip()

def check_security_patches():
    output = subprocess.run(['powershell', '-Command', 'Get-HotFix | Select-Object Description, HotFixID, InstalledOn'], capture_output=True, text=True)
    return output.stdout.strip()

def main():
    print("Análise de Segurança do Windows\n")
    print("1. Antivírus Ativo:", "Sim" if check_antivirus() else "Não")
    print("2. Atualizações do Windows:", "Pendentes" if check_windows_updates() else "Nenhuma pendente")
    print("3. Firewall do Windows:", "Ativado" if check_firewall() else "Desativado")
    print("4. Controlo do Conta do utilizador (UAC):", "Ativado" if check_uac() else "Desativado")
    print("5. Programas de Inicialização:", check_startup_programs())
    print("6. Serviços do Windows:", check_windows_services())
    print("7. Portas Abertas:", check_open_ports())
    print("8. Patches de Segurança:", check_security_patches())

if __name__ == "__main__":
    main()