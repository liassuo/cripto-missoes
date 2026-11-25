import os
import sys
MISSAO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, MISSAO)
sys.path.insert(0, os.path.dirname(MISSAO))

from entrada import ler_texto
from missao3.securedocs_simetrica import arquivo
from securedocs_assinatura import rsa
from securedocs_assinatura.sha256 import sha256_hex
from textos import CONTRATO, CONTRATO_FALSO

CHAVE_RSA = []


def chave_techsecure():
    # gerar RSA de 2048 bits leva um tempinho: gera uma vez
    if not CHAVE_RSA:
        CHAVE_RSA.append(rsa.gerar_chaves(2048))
    return CHAVE_RSA[0]


def mostrar(original, falso):
    print("--- tentativa 1: mandar o contrato junto com o hash (Missão 5) ---")
    h = sha256_hex(original)
    print("TechSecure envia: contrato + SHA-256 = %s..." % h[:32])
    h_falso = sha256_hex(falso)
    print("Eva intercepta, troca o contrato e calcula o hash do falso: %s..." % h_falso[:32])
    print("cliente confere: SHA-256(contrato recebido) == hash recebido? %s"
          % (sha256_hex(falso) == h_falso))
    print("-> o hash é público, qualquer um calcula. Ele pega erro de transmissão,")
    print("   mas não diz QUEM mandou.\n")

    print("--- tentativa 2: cifrar com AES e uma chave que só os dois conhecem (Missão 3) ---")
    chave = arquivo.gerar_chave(256)
    cifrado = arquivo.cifrar_dados(original.encode("utf-8"), chave)
    print("TechSecure envia o contrato cifrado: %s..." % cifrado[22:38].hex().upper())
    print("Eva não tem a chave: não lê e não consegue montar um cifrado válido.")
    falso_cliente = arquivo.cifrar_dados(falso.encode("utf-8"), chave)
    print("só que o CLIENTE também tem a chave. Ele cifra o contrato falso")
    print("(%s...) e diz que recebeu assim da TechSecure." % falso_cliente[22:38].hex().upper())
    print("-> com chave simétrica os dois podem ter gerado: SEM não repúdio")
    print("   (slide: a criptografia simétrica \"não oferece assinatura digital\").\n")

    print("--- tentativa 3: assinatura digital (chave privada só da TechSecure) ---")
    privada = chave_techsecure()
    s = rsa.assinar(original.encode("utf-8"), privada)
    print("TechSecure: contrato -> SHA-256 -> RSA com a chave PRIVADA")
    print("  assinatura = %X..." % (s >> (s.bit_length() - 64)))
    print("cliente confere com a chave PÚBLICA da TechSecure:")
    print("  contrato original : %s" % rsa.verificar(original.encode("utf-8"), s, privada.publica))
    print("  contrato trocado  : %s" % rsa.verificar(falso.encode("utf-8"), s, privada.publica))
    print("o cliente não tem a chave privada, então não consegue fabricar uma assinatura")
    print("da TechSecure. Se a assinatura confere, só a TechSecure pode ter assinado -> não repúdio.")


def main():
    print("=== 1. O PROBLEMA: O HASH ESTÁ CERTO, MAS QUEM ENVIOU? ===\n")
    mostrar(CONTRATO, CONTRATO_FALSO)
    print()
    print("resumo:")
    print("%-26s %-12s %-14s %-12s" % ("", "integridade", "autenticidade", "não repúdio"))
    print("%-26s %-12s %-14s %-12s" % ("hash sozinho", "acidental", "não", "não"))
    print("%-26s %-12s %-14s %-12s" % ("AES com chave dos dois", "sim", "entre os 2", "não"))
    print("%-26s %-12s %-14s %-12s" % ("assinatura digital", "sim", "sim", "sim"))


def interativo():
    original = ler_texto("contrato original: ", CONTRATO)
    falso = ler_texto("contrato que o invasor quer colocar no lugar: ", CONTRATO_FALSO)
    print()
    mostrar(original, falso)


if __name__ == "__main__":
    main()
