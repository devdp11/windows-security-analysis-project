import os
import platform
import subprocess


def check_antivirus():
    # Verifica se há um antivírus instalado e em execução
    antivirus_installed = False
    output = subprocess.run(
        ['wmic', 'product', 'get', 'name'], capture_output=True, text=True)
    if "Antivirus" in output.stdout:
        antivirus_installed = True
    return antivirus_installed


def check_windows_updates():
    # Verifica se há atualizações do Windows pendentes
    output = subprocess.run(
        ['powershell', 'Get-WindowsUpdate'], capture_output=True, text=True)
    return "No updates available" not in output.stdout


def check_firewall():
    # Verifica se o Firewall do Windows está ativado
    output = subprocess.run(
        ['netsh', 'advfirewall', 'show', 'allprofiles'], capture_output=True, text=True)
    return "Firewall status: ON" in output.stdout


def main():
    print("Análise de Segurança do Windows\n")
    print("1. Antivírus Ativo:", "Sim" if check_antivirus() else "Não")
    print("2. Atualizações do Windows:",
          "Pendentes" if check_windows_updates() else "Nenhuma pendente")
    print("3. Firewall do Windows:",
          "Ativado" if check_firewall() else "Desativado")


if __name__ == "__main__":
    main()
