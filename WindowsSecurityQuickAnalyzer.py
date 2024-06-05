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

def main():
    print("Análise de Segurança do Windows\n")
    print("1. Antivírus Ativo:", "Sim" if check_antivirus() else "Não")
    print("2. Atualizações do Windows:", "Pendentes" if check_windows_updates() else "Nenhuma pendente")
    print("3. Firewall do Windows:", "Ativado" if check_firewall() else "Desativado")

if __name__ == "__main__":
    main()