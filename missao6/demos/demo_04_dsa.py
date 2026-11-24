import os
import sys
MISSAO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, MISSAO)
sys.path.insert(0, os.path.dirname(MISSAO))

from entrada import ler_int
from missao1.securedocs_math.exponenciacao_modular import exp_mod
from missao1.securedocs_math.inverso_multiplicativo import inverso_multiplicativo
from missao1.securedocs_math.primos import eh_primo
from securedocs_assinatura import dsa
from securedocs_assinatura.util import resumir
from textos import CONTRATO, CONTRATO_FALSO


def passo_a_passo(p, q, g, x, k, h):
    par = dsa.Parametros(p, q, g)
    chave = dsa.ChavePrivada(par, x)
    y = chave.y
    print("chave pública global: p = %d, q = %d, g = %d" % (p, q, g))
    print("chave privada x = %d   chave pública y = g^x mod p = %d^%d mod %d = %d"
          % (x, g, x, p, y))
    print("H(M) = %d   k (secreto) = %d" % (h, k))

    k_inv = inverso_multiplicativo(k, q)
    r = exp_mod(g, k, p) % q
    s = k_inv * (h + x * r) % q
    print("\nASSINATURA")
    print("  k^-1 mod q = %d^-1 mod %d = %d" % (k, q, k_inv))
    print("  r = (g^k mod p) mod q = (%d^%d mod %d) mod %d = %d" % (g, k, p, q, r))
    print("  s = [k^-1 (H(M) + x r)] mod q = [%d (%d + %d*%d)] mod %d = %d"
          % (k_inv, h, x, r, q, s))
    print("  envia (M, r, s) -> (%d, %d, %d)" % (h, r, s))
    if r == 0 or s == 0:
        print("  r ou s deu zero: escolha outro k")
        return

    w = inverso_multiplicativo(s, q)
    u1 = h * w % q
    u2 = r * w % q
    v = exp_mod(g, u1, p) * exp_mod(y, u2, p) % p % q
    print("\nVERIFICAÇÃO")
    print("  w = s^-1 mod q = %d^-1 mod %d = %d" % (s, q, w))
    print("  u1 = [H(M) w] mod q = [%d*%d] mod %d = %d" % (h, w, q, u1))
    print("  u2 = (r w) mod q = %d*%d mod %d = %d" % (r, w, q, u2))
    print("  v = [(g^u1 y^u2) mod p] mod q = [(%d^%d * %d^%d) mod %d] mod %d = %d"
          % (g, u1, y, u2, p, q, v))
    print("  v = r ? %d = %d -> %s" % (v, r, "OK" if v == r else "FALHOU"))


def main():
    print("=== 4. DSA - DIGITAL SIGNATURE ALGORITHM (DSS) ===\n")
    print("exemplo resolvido em aula: p = 59, q = 29, g = 3, x = 7, k = 10, H(M) = 26\n")
    passo_a_passo(59, 29, 3, 7, 10, 26)

    print("\ncom parâmetros de verdade (FIPS 186-4: p de 2048 bits, q de 256, SHA-256)")
    print("(nos slides: p de 512 a 1024 bits, q de 160 e SHA-1 - foi atualizado pelo NIST)")
    par = dsa.parametros_padrao()
    print("  p = %s" % resumir(par.p))
    print("  q = %s" % resumir(par.q))
    print("  q divide p - 1? %s   g^q mod p = %d" % ((par.p - 1) % par.q == 0, exp_mod(par.g, par.q, par.p)))
    chave = dsa.gerar_chaves(par)
    dados = CONTRATO.encode("utf-8")
    r, s = dsa.assinar(dados, chave)
    print("  r = %s" % resumir(r))
    print("  s = %s" % resumir(s))
    print("  assinatura: 2 x 256 bits = 64 bytes (o RSA de 2048 bits dá 256)")
    print("  verificar original: %s" % dsa.verificar(dados, (r, s), chave.publica))
    print("  verificar trocado : %s" % dsa.verificar(CONTRATO_FALSO.encode("utf-8"), (r, s),
                                                    chave.publica))
    print("\nobs.: o k aqui sai da RFC 6979 (HMAC da chave com o hash), não do sorteio.")
    print("se k repetir, a chave privada vaza (demo 7).")


def interativo():
    p = ler_int("primo p: ", 5)
    q = ler_int("primo q (divisor de p - 1): ", 2)
    if not (eh_primo(p) and eh_primo(q)) or (p - 1) % q:
        print("  p e q precisam ser primos e q precisa dividir p - 1")
        return
    h = ler_int("h para calcular g = h^((p-1)/q) mod p: ", 2, p - 2)
    g = exp_mod(h, (p - 1) // q, p)
    if g == 1:
        print("  deu g = 1, escolha outro h")
        return
    print("  g = %d" % g)
    x = ler_int("chave privada x (0 < x < q): ", 1, q - 1)
    k = ler_int("k secreto (0 < k < q): ", 1, q - 1)
    hm = ler_int("H(M): ", 0)
    print()
    passo_a_passo(p, q, g, x, k, hm % q)


if __name__ == "__main__":
    main()
