import os
import sys
MISSAO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, MISSAO)
sys.path.insert(0, os.path.dirname(MISSAO))

import hashlib

from entrada import ler_texto
from securedocs_assinatura import sha256 as s256
from securedocs_assinatura.sha1 import sha1_hex
from securedocs_assinatura.util import para_hex


def bits_diferentes(a, b):
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def avalanche(texto):
    trocado = texto[:-1] + chr(ord(texto[-1]) ^ 1)        # muda 1 bit do último caractere
    h1, h2 = s256.sha256(texto), s256.sha256(trocado)
    print("  '%s'" % texto)
    print("    %s" % para_hex(h1, 4))
    print("  '%s'  (só 1 bit diferente)" % trocado)
    print("    %s" % para_hex(h2, 4))
    print("  bits que mudaram no hash: %d de 256 (ideal ~128)" % bits_diferentes(h1, h2))


def main():
    print("=== 2. FUNÇÃO HASH: SHA-1 x SHA-256 ===\n")
    print("o hash é o primeiro passo da assinatura: Documento -> Hash -> Assinatura")
    print("(assinar o hash de 32 bytes é muito mais rápido que assinar o documento todo)\n")

    print("as constantes do SHA-256 saem das raízes dos primos (nada escondido):")
    print("  H0 = parte fracionária de raiz(2)  = %08X" % s256.H_INICIAL[0])
    print("  K0 = parte fracionária de cbrt(2)  = %08X" % s256.K[0])
    print("  K63 = parte fracionária de cbrt(311) = %08X" % s256.K[63])

    print("\nenchimento de 'abc' (3 bytes -> 1 bloco de 64 bytes):")
    bloco = s256.preencher(b"abc")
    print("  " + para_hex(bloco, 4))
    print("  'abc' | 80 (o bit 1) | zeros | tamanho = 24 bits no fim")

    passos = []
    resultado = s256.sha256(b"abc", passos)
    print("\nrodadas do bloco (a, e = palavras que mais mudam):")
    for t, w, estado in passos:
        if t < 4 or t > 61:
            print("  t = %2d  W = %08X  a = %08X  e = %08X" % (t, w, estado[0], estado[4]))
        elif t == 4:
            print("  ...")
    print("\nSHA-256('abc') = %s" % para_hex(resultado, 4))
    print("hashlib        = %s" % para_hex(hashlib.sha256(b"abc").digest(), 4))
    print("SHA-1('abc')   = %s  (o dos slides, 160 bits)" % sha1_hex("abc"))

    print("\nefeito avalanche:")
    avalanche("contrato de R$ 12.000,00")

    print("\nresistência à colisão (slide): achar dois textos com o mesmo hash custa ~2^(n/2)")
    print("  MD5 (128 bits)  -> 2^64   (já considerado fraco nos slides)")
    print("  SHA-1 (160)     -> 2^80")
    print("  SHA-256 (256)   -> 2^128  -> é o que usamos no RSA do SecureDocs")
    print("  se dois contratos tiverem o mesmo hash, assinar um = assinar o outro (demo 6)")


def interativo():
    texto = ler_texto("texto: ", "contrato de R$ 12.000,00")
    print()
    print("SHA-1  : %s" % sha1_hex(texto))
    print("SHA-256: %s" % s256.sha256_hex(texto))
    print()
    avalanche(texto)


if __name__ == "__main__":
    main()
