import os
import sys
MISSAO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, MISSAO)
sys.path.insert(0, os.path.dirname(MISSAO))

from entrada import ler_texto
from securedocs_assinatura import ecdsa
from securedocs_assinatura.hmac import hmac_sha256, verificar_hmac
from securedocs_assinatura.sha256 import sha256_hex
from textos import CONTRATO, CONTRATO_FALSO


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

    print("--- tentativa 2: HMAC com uma chave que só TechSecure e cliente conhecem ---")
    chave = b"chave-combinada-entre-os-dois"
    etiqueta = hmac_sha256(chave, original)
    print("TechSecure envia: contrato + HMAC = %s..." % etiqueta.hex().upper()[:32])
    print("Eva troca o contrato, mas não tem a chave: HMAC confere? %s"
          % verificar_hmac(chave, falso, etiqueta))
    etiqueta_cliente = hmac_sha256(chave, falso)
    print("só que o CLIENTE também tem a chave. Ele pode criar o contrato falso, gerar")
    print("o HMAC (%s...) e dizer no tribunal que veio da TechSecure." % etiqueta_cliente.hex().upper()[:16])
    print("HMAC confere? %s -> não dá para provar quem gerou: SEM não repúdio.\n"
          % verificar_hmac(chave, falso, etiqueta_cliente))

    print("--- tentativa 3: assinatura digital (chave privada só da TechSecure) ---")
    privada = ecdsa.gerar_chaves()
    assinatura = ecdsa.assinar(original.encode("utf-8"), privada)
    print("TechSecure: contrato -> hash -> assinatura com a chave PRIVADA")
    print("  assinatura (r, s) = (%X..., %X...)" % (assinatura[0] >> 192, assinatura[1] >> 192))
    print("cliente confere com a chave PÚBLICA da TechSecure:")
    print("  contrato original : %s" % ecdsa.verificar(original.encode("utf-8"), assinatura, privada.publica))
    print("  contrato trocado  : %s" % ecdsa.verificar(falso.encode("utf-8"), assinatura, privada.publica))
    print("o cliente não tem a chave privada, então não consegue fabricar uma assinatura")
    print("da TechSecure. Se a assinatura confere, só a TechSecure pode ter assinado -> não repúdio.")


def main():
    print("=== 1. O PROBLEMA: O HASH ESTÁ CERTO, MAS QUEM ENVIOU? ===\n")
    mostrar(CONTRATO, CONTRATO_FALSO)
    print()
    print("resumo:")
    print("%-22s %-12s %-14s %-12s" % ("", "integridade", "autenticidade", "não repúdio"))
    print("%-22s %-12s %-14s %-12s" % ("hash sozinho", "acidental", "não", "não"))
    print("%-22s %-12s %-14s %-12s" % ("HMAC (chave secreta)", "sim", "sim (entre 2)", "não"))
    print("%-22s %-12s %-14s %-12s" % ("assinatura digital", "sim", "sim", "sim"))


def interativo():
    original = ler_texto("contrato original: ", CONTRATO)
    falso = ler_texto("contrato que o invasor quer colocar no lugar: ", CONTRATO_FALSO)
    print()
    mostrar(original, falso)


if __name__ == "__main__":
    main()
