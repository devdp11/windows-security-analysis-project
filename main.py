import subprocess

def run_command(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        result.check_returncode()
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Erro na execução do comando: {e}\nDetalhes do Erro: {e.stderr}"
    except Exception as e:
        return f"Erro desconhecido: {str(e)}"  

def check_antivirus():
    output = subprocess.run(['wmic', '/namespace:\\\\root\\SecurityCenter2', 'path', 'AntiVirusProduct', 'get', 'displayName'], capture_output=True, text=True)
    if "displayName" in output.stdout:
        return f"Antivírus instalado: {output.stdout.split()[1]}"
    return "Nenhum antivírus instalado."

def check_windows_updates():
    output = subprocess.run(['powershell', '-Command', '(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0").Updates.Count'], capture_output=True, text=True)
    updates = int(output.stdout.strip())
    if updates > 0:
        return f"Atualizações pendentes: {updates}"
    return "Nenhuma atualização pendente."

def check_firewall():
    output = subprocess.run(['powershell', '-Command', 'Get-NetFirewallProfile -Profile Domain,Public,Private | Select-Object -ExpandProperty Enabled'], capture_output=True, text=True)
    if 'True' in output.stdout:
        return "Firewall está ativado."
    return "Firewall está desativado."

def check_uac():
    output = subprocess.run(['powershell', '-Command', 'Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System | Select-Object -ExpandProperty EnableLUA'], capture_output=True, text=True)
    if '1' in output.stdout.strip():
        return "UAC está ativado."
    return "UAC está desativado."

def check_startup_programs():
    output = subprocess.run(['powershell', '-Command', 'Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User'], capture_output=True, text=True)
    return f"Programas de inicialização: {output.stdout}"

def check_windows_services():
    output = subprocess.run(['powershell', '-Command', 'Get-Service | Where-Object {$_.Status -eq "Running"} | Format-Table Name, DisplayName, StartType, Status -AutoSize'], capture_output=True, text=True)
    return f"Serviços do Windows em execução:\n{output.stdout}"

def check_open_ports():
    output = subprocess.run(['powershell', '-Command', 'Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"}'], capture_output=True, text=True)
    return f"Portas abertas:\n{output.stdout}"

def check_security_patches():
    output = subprocess.run(['powershell', '-Command', 'Get-HotFix | Select-Object Description, HotFixID, InstalledOn'], capture_output=True, text=True)
    return f"Patches de segurança instalados:\n{output.stdout}"

def check_user_accounts():
    output = run_command(['powershell', '-Command', 'Get-LocalUser | Select-Object Name,Enabled,PasswordNeverExpires'])
    return f"Contas de usuário:\n{output}"

def check_password_policies():
    output = run_command(['powershell', '-Command', 'Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters" | Select-Object RequireStrongKey,MaximumPasswordAge,MinimumPasswordAge,MinimumPasswordLength,PasswordHistorySize'])
    return f"Políticas de senha:\n{output}"

def check_installed_software():
    output = run_command(['powershell', '-Command', 'Get-WmiObject -Class Win32_Product | Select-Object Name,Version,Vendor'])
    return f"Software instalado:\n{output}"

def check_network_shares():
    output = run_command(['powershell', '-Command', 'Get-SmbShare | Select-Object Name,Path,Description'])
    return f"Compartilhamentos de rede:\n{output}"

def check_disk_encryption():
    try:
        command = ['powershell', '-Command', 'Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,ProtectionStatus']
        result = subprocess.run(command, capture_output=True, text=True)
        result.check_returncode()
        if "MountPoint" in result.stdout:
            return f"Criptografia de disco:\n{result.stdout}"
        else:
            return "Nenhum volume com BitLocker encontrado."
    except subprocess.CalledProcessError as e:
        return f"Erro na execução do comando: {e}\nDetalhes do Erro: {e.stderr.decode() if e.stderr else 'Nenhum detalhe disponível.'}"
    except Exception as e:
        return f"Erro desconhecido: {str(e)}"

def check_all():
    results = [
        "Antivírus: " + check_antivirus(),
        "Atualizações do Windows: " + check_windows_updates(),
        "Firewall: " + check_firewall(),
        "UAC: " + check_uac(),
        "Programas de Inicialização: " + check_startup_programs(),
        "Serviços do Windows: " + check_windows_services(),
        "Portas Abertas: " + check_open_ports(),
        "Patches de Segurança: " + check_security_patches(),
        "Contas de Usuário: " + check_user_accounts(),
        "Políticas de Senha: " + check_password_policies(),
        "Software Instalado: " + check_installed_software(),
        "Compartilhamentos de Rede: " + check_network_shares(),
        "Criptografia de Disco: " + check_disk_encryption()
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
        '14': check_all
    }
    while True:
        print("\nMenu de Verificações de Segurança:")
        for i in range(1, 15):
            print(f"{i}. {functions[str(i)].__name__.replace('_', ' ').capitalize()}")
        print("0. Sair")
        choice = input("Escolha uma opção: ")
        if choice == '0':
            break
        elif choice in functions:
            print(functions[choice]())
        else:
            print("Opção inválida, tente novamente.")

if __name__ == "__main__":
    menu()
