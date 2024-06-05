import subprocess

def run_command(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, shell=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return str(e)

def check_antivirus():
    # Verifica se há um antivírus instalado e em execução
    output = run_command(['wmic', 'product', 'get', 'name'])
    return "Antivirus" in output

def check_windows_updates():
    # Verifica se há atualizações do Windows pendentes
    output = run_command(['powershell', '-Command', 'Get-WindowsUpdate'])
    return "No updates available" not in output

def check_firewall():
    # Verifica se o Firewall do Windows está ativado
    output = run_command(['netsh', 'advfirewall', 'show', 'allprofiles'])
    return "State ON" in output

def check_windows_defender():
    # Verifica se o Windows Defender está ativo
    output = run_command(['powershell', '-Command', 'Get-MpComputerStatus'])
    return "RealTimeProtectionEnabled: True" in output

def check_firewall_rule(rule_name):
    # Verifica se uma regra específica da Firewall está ativa
    output = run_command(['netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name={rule_name}'])
    return "No rules match the specified criteria" not in output

def check_bitlocker():
    # Verifica se o BitLocker está ativado nas unidades
    output = run_command(['manage-bde', '-status'])
    return "Protection On" in output

def main():
    print("Análise de Segurança do Windows\n")
    print("1. Antivírus Ativo:", "Sim" if check_antivirus() else "Não")
    print("2. Atualizações do Windows:", "Pendentes" if check_windows_updates() else "Nenhuma pendente")
    print("3. Firewall do Windows:", "Ativado" if check_firewall() else "Desativado")
    print("4. Windows Defender Ativo:", "Sim" if check_windows_defender() else "Não")
    print("5. Regra específica da Firewall 'Allow RDP':", "Ativada" if check_firewall_rule('Allow RDP') else "Desativada")
    print("6. BitLocker Ativo:", "Sim" if check_bitlocker() else "Não")

if __name__ == "__main__":
    main()
