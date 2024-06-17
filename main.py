import subprocess

def run_command(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8')
        result.check_returncode()  # Ensure the command was successful
        return result.stdout
    except UnicodeDecodeError:
        result = subprocess.run(command, capture_output=True, text=True, encoding='cp1252')
        result.check_returncode()
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Erro na execução do comando: {e}"

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
    return output.stdout.strip() == "1"

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

def check_user_accounts():
    output = run_command(['powershell', '-Command', 'Get-LocalUser | Select-Object Name,Enabled,PasswordNeverExpires'])
    return output.strip() if output else "Nenhuma"

#'''
def check_password_policies():
    output = run_command(['powershell', '-Command', 'Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters" | Select-Object RequireStrongKey,MaximumPasswordAge,MinimumPasswordAge,MinimumPasswordLength,PasswordHistorySize'])
    return output.strip() if output else "Nenhuma"
    #'''

'''
def check_password_policies():
    try:
        output = subprocess.run(
            ['powershell', '-Command', 'Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters" | Select-Object RequireStrongKey,MaximumPasswordAge,MinimumPasswordAge,MinimumPasswordLength,PasswordHistorySize'],
            capture_output=True,
            text=True,
            encoding='latin-1'  # Change the encoding to 'latin-1'
        )
        return output.stdout.strip() if output.stdout else "Nenhuma"
    except subprocess.CalledProcessError as e:
        return f"Erro ao executar o comando: {str(e)}"
    except UnicodeDecodeError as e:
        return f"Erro de decodificação: {str(e)}"
'''
        
def check_security_event_logs():
    output = run_command(['powershell', '-Command', 'Get-EventLog -LogName Security -Newest 10 | Select-Object TimeGenerated,EntryType,Message'])
    return output.strip() if output else "Nenhum"

def check_installed_software():
    output = run_command(['powershell', '-Command', 'Get-WmiObject -Class Win32_Product | Select-Object Name,Version,Vendor'])
    return output.strip() if output else "Nenhum"

def check_network_shares():
    output = run_command(['powershell', '-Command', 'Get-SmbShare | Select-Object Name,Path,Description'])
    return output.strip() if output else "Nenhuma"

def check_disk_encryption():
    output = run_command(['powershell', '-Command', 'Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,ProtectionStatus'])
    return output.strip() if output else "Nenhuma"

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
    print("9. Contas de Utilizador:", check_user_accounts())
    print("10. Políticas de Password:", check_password_policies())
    print("11. Logs de Eventos de Segurança:", check_security_event_logs())
    print("12. Software Instalado:", check_installed_software())
    print("13. Compartilhamentos de Rede:", check_network_shares())
    print("14. Criptografia de Disco:", check_disk_encryption())

if __name__ == "__main__":
    main()
