import os
import sys
import time
MISSAO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, MISSAO)
sys.path.insert(0, os.path.dirname(MISSAO))

from entrada import ler_int
from securedocs_assinatura import ataques, rsa, pkcs1, ecdsa
from securedocs_assinatura.util import resumir, int_para_bytes
from textos import CONTRATO, CONTRATO_FALSO


def ataque_rsa_sem_hash():
    print("--- ataque 1: RSA assinando a mensagem direto (sem hash, sem enchimento) ---")
    chave = rsa.gerar_chaves(1024)
    pub = chave.publica
    m, s = ataques.rsa_falsificacao_existencial(pub)
    print("Eva escolhe s e calcula m = s^e mod n, sem a chave privada:")
    print("  m = %s" % resumir(m))
    print("  s^e mod n == m ? %s  -> 'assinatura válida' (de uma mensagem lixo)"
          % (rsa.operacao_publica(s, pub) == m))
    m1, m2 = 2, 50000
    s1, s2 = rsa.operacao_privada(m1, chave), rsa.operacao_privada(m2, chave)
    s3 = ataques.rsa_multiplicativa(s1, s2, pub)
    print("com as assinaturas de %d e de %d, Eva monta a de %d sem a chave:" % (m1, m2, m1 * m2))
    print("  (s1 * s2)^e mod n == %d ? %s" % (m1 * m2, rsa.operacao_publica(s3, pub) == m1 * m2))
    print("defesa: assinar o HASH com enchimento (PKCS#1 / PSS). O mesmo s agora:")
    print("  verificar_pss(s) = %s" % pkcs1.verificar_pss(int_para_bytes(m, 128), int_para_bytes(s, 128), pub))


def ataque_k_repetido(mensagem1, mensagem2):
    print("\n--- ataque 2: ECDSA com o mesmo k em duas assinaturas (caso PS3, 2010) ---")
    chave = ecdsa.gerar_chaves()
    n = ecdsa.P256.n
    k = 123456789                       # "número aleatório" fixo, como a Sony fez
    d1, d2 = mensagem1.encode("utf-8"), mensagem2.encode("utf-8")
    z1, z2 = ecdsa.resumo(d1, n), ecdsa.resumo(d2, n)
    a1 = ecdsa.assinar(d1, chave, k=k)
    a2 = ecdsa.assinar(d2, chave, k=k)
    print("assinatura 1: r = %X..." % (a1[0] >> 192))
    print("assinatura 2: r = %X...  (r igual: Eva percebe que k repetiu)" % (a2[0] >> 192))
    k_achado, d_achado = ataques.recuperar_chave_k_repetido(z1, a1, z2, a2, n)
    print("k = (z1 - z2) / (s1 - s2) mod n = %d" % k_achado)
    print("d = (s1 k - z1) / r mod n       = %s" % resumir(d_achado))
    print("chave privada real              = %s" % resumir(chave.d))
    print("achou? %s -> Eva agora assina o que quiser como TechSecure:" % (d_achado == chave.d))
    falsa = ecdsa.assinar(CONTRATO_FALSO.encode("utf-8"), ecdsa.ChavePrivada(ecdsa.P256, d_achado))
    print("  contrato falso verifica com a pública da TechSecure? %s"
          % ecdsa.verificar(CONTRATO_FALSO.encode("utf-8"), falsa, chave.publica))
    b1, b2 = ecdsa.assinar(d1, chave), ecdsa.assinar(d2, chave)
    print("defesa: k pela RFC 6979 (muda com a mensagem): r1 == r2 ? %s" % (b1[0] == b2[0]))


def ataque_colisao(bits):
    print("\n--- ataque 3: colisão de hash (hash cortado em %d bits) ---" % bits)
    print("Eva gera versões do contrato bom e do falso trocando espaço simples por duplo")
    inicio = time.time()
    bom, ruim, h, tentativas = ataques.colisao(CONTRATO, CONTRATO_FALSO, bits, posicoes=bits // 2 + 4)
    if bom is None:
        print("  não achou com essas versões, tente mais bits de variação")
        return
    print("  achou em %.1f s com %d hashes (da ordem de 2^(%d/2) = %d por lado)"
          % (time.time() - inicio, tentativas, bits, 2 ** (bits // 2)))
    print("  hash cortado do bom  : %0*X" % (bits // 4, ataques.hash_cortado(bom, bits)))
    print("  hash cortado do falso: %0*X" % (bits // 4, ataques.hash_cortado(ruim, bits)))
    print("  o cliente assina a versão boa e a assinatura também vale para a de R$ 120.000,00")
    print("  com o SHA-256 inteiro seriam 2^128 hashes: impossível. Por isso o hash")
    print("  precisa ser resistente a colisão (o SHA-1 já não é).")


def ataque_troca_chave():
    print("\n--- ataque 4: Eva troca a chave pública ---")
    ts = ecdsa.gerar_chaves()
    eva = ecdsa.gerar_chaves()
    dados = CONTRATO_FALSO.encode("utf-8")
    assinatura = ecdsa.assinar(dados, eva)
    print("Eva manda o contrato falso assinado por ela e, junto, a chave pública DELA")
    print("dizendo 'esta é a chave da TechSecure'.")
    print("  verificar com a chave que veio no e-mail: %s" % ecdsa.verificar(dados, assinatura, eva.publica))
    print("  verificar com a chave real da TechSecure: %s" % ecdsa.verificar(dados, assinatura, ts.publica))
    print("a matemática está certa; o problema é saber de quem é a chave pública.")
    print("-> nova descoberta: certificado digital (demo 9)")


def main():
    print("=== 7. ATACANDO AS ASSINATURAS ===\n")
    ataque_rsa_sem_hash()
    ataque_k_repetido(CONTRATO, CONTRATO_FALSO)
    ataque_colisao(20)
    ataque_troca_chave()


def interativo():
    bits = ler_int("colisão: cortar o hash em quantos bits? (16 a 28): ", 16, 28)
    ataque_colisao(bits)


if __name__ == "__main__":
    main()
