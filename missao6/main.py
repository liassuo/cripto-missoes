import os
import sys

PASTA = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(PASTA, "demos"))

import demo_01_problema
import demo_02_hash
import demo_03_rsa
import demo_04_dsa
import demo_05_ecdsa
import demo_06_assinar_contrato
import demo_07_ataques
import demo_08_comparacao
import demo_09_certificado

PROBLEMA = [
    ("O hash está certo, mas quem enviou? (hash x HMAC x assinatura)", demo_01_problema),
]

ALGORITMOS_ASSINATURA = [
    ("Função hash: SHA-1 x SHA-256", demo_02_hash),
    ("Assinatura RSA (de livro, PKCS#1 v1.5 e PSS)", demo_03_rsa),
    ("DSA - Digital Signature Algorithm", demo_04_dsa),
    ("ECDSA - curvas elípticas", demo_05_ecdsa),
]

EXPERIMENTO = [
    ("Assinar e verificar o contrato (arquivo)", demo_06_assinar_contrato),
    ("Atacando as assinaturas", demo_07_ataques),
    ("Comparação e a escolha", demo_08_comparacao),
]

DESCOBERTA = [
    ("A chave pública é mesmo da TechSecure? (certificado)", demo_09_certificado),
]

ALGORITMOS = PROBLEMA + ALGORITMOS_ASSINATURA + EXPERIMENTO + DESCOBERTA


def mostrar_menu():
    print()
    print("=" * 58)
    print(" SecureDocs - Missão 6: quem realmente enviou o contrato?")
    print("=" * 58)
    i = 1
    for titulo, grupo in (("O PROBLEMA", PROBLEMA), ("A SOLUÇÃO: assinatura digital", ALGORITMOS_ASSINATURA),
                          ("O EXPERIMENTO E A ESCOLHA", EXPERIMENTO), ("NOVA DESCOBERTA", DESCOBERTA)):
        print("\n " + titulo)
        for nome, _ in grupo:
            print(" %2d - %s" % (i, nome))
            i += 1
    print()
    print("  0 - Sair")


def escolher_modo(nome, modulo):
    print("\n%s" % nome)
    print("  1 - ver o exemplo pronto")
    print("  2 - digitar meus próprios valores")
    opcao = input("  opção: ").strip()
    print()
    if opcao == "1":
        modulo.main()
    elif opcao == "2":
        modulo.interativo()
    else:
        print("opção inválida")


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # acentos no terminal do Windows

    while True:
        mostrar_menu()
        escolha = input("\nescolha: ").strip()

        if escolha == "0":
            break
        elif escolha.isdigit() and 1 <= int(escolha) <= len(ALGORITMOS):
            nome, modulo = ALGORITMOS[int(escolha) - 1]
            escolher_modo(nome, modulo)
        else:
            print("opção inválida")
            continue

        input("\n[enter para voltar ao menu] ")


if __name__ == "__main__":
    main()
