import os
import sys
MISSAO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, MISSAO)
sys.path.insert(0, os.path.dirname(MISSAO))

from entrada import ler_int
from missao1.securedocs_math.primos import eh_primo
from securedocs_assinatura import rsa
from securedocs_assinatura.sha256 import sha256
from securedocs_assinatura.util import para_hex, resumir
from textos import CONTRATO, CONTRATO_FALSO


def pequeno(p, q, e, h):
    try:
        chave = rsa.chaves_de_primos(p, q, e)
    except ValueError as erro:
        print("  não deu: %s" % erro)
        return
    n = chave.n
    print("p = %d, q = %d, n = %d, phi(n) = %d" % (p, q, n, (p - 1) * (q - 1)))
    print("e = %d, d = e^-1 mod phi(n) = %d" % (e, chave.d))
    print("chave pública KU = {%d, %d}   chave privada KR = {%d, %d}" % (e, n, chave.d, n))
    h %= n
    s = rsa.operacao_privada(h, chave)
    print("\nassinar  (com a PRIVADA): s = H^d mod n = %d^%d mod %d = %d" % (h, chave.d, n, s))
    v = rsa.operacao_publica(s, chave.publica)
    print("verificar (com a PÚBLICA): s^e mod n = %d^%d mod %d = %d" % (s, e, n, v))
    print("%d == H(M) = %d ? %s" % (v, h, "OK" if v == h else "FALHOU"))


def main():
    print("=== 3. ASSINATURA COM RSA ===\n")
    print("é o RSA da cifra ao contrário: a chave PRIVADA assina, a PÚBLICA confere.\n")

    print("exemplo dos slides (p = 7, q = 17, e = 5, d = 77), com H(M) = 19:")
    pequeno(7, 17, 5, 19)

    print("\ncom chave de verdade (2048 bits, primos pelo Miller-Rabin da Missão 1):")
    chave = rsa.gerar_chaves(2048)
    print("  n = %s" % resumir(chave.n))
    dados = CONTRATO.encode("utf-8")
    h = sha256(dados)
    print("  documento -> SHA-256 = %s..." % para_hex(h)[:32])
    s = rsa.assinar(dados, chave)
    print("  assinatura = H^d mod n (feita pelo TCR) = %s" % resumir(s))
    print("  verificar contrato original: %s" % rsa.verificar(dados, s, chave.publica))
    print("  verificar contrato trocado : %s"
          % rsa.verificar(CONTRATO_FALSO.encode("utf-8"), s, chave.publica))
    print("\npor que assinar o hash e não o documento?")
    print("  o documento tem %d bytes e o hash só 32; a conta com d (2048 bits) é cara,"
          % len(dados))
    print("  então assina-se uma vez só, o hash (slide: \"a codificação é feita sobre o hash\").")


def interativo():
    p = ler_int("primo p: ", 3)
    q = ler_int("primo q: ", 3)
    if not (eh_primo(p) and eh_primo(q)):
        print("  p e q precisam ser primos")
        return
    e = ler_int("expoente público e: ", 3)
    h = ler_int("hash da mensagem H(M) (menor que n): ", 0)
    print()
    pequeno(p, q, e, h)


if __name__ == "__main__":
    main()
