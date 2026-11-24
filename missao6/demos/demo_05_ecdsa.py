import os
import sys
MISSAO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, MISSAO)
sys.path.insert(0, os.path.dirname(MISSAO))

from entrada import ler_int
from missao1.securedocs_math.inverso_multiplicativo import inverso_multiplicativo
from securedocs_assinatura import ecdsa
from securedocs_assinatura.util import resumir
from textos import CONTRATO, CONTRATO_FALSO

C = ecdsa.PEQUENA


def ponto(P):
    return "infinito" if P is None else "(%d, %d)" % P


def pequeno(d, k, z):
    Q = ecdsa.multiplicar(d, C.G, C)
    print("chave privada d = %d   chave pública Q = d G = %s" % (d, ponto(Q)))
    R = ecdsa.multiplicar(k, C.G, C)
    if R is None:
        print("k G deu infinito, escolha outro k")
        return
    r = R[0] % C.n
    s = inverso_multiplicativo(k, C.n) * (z + d * r) % C.n
    print("\nassinar H(M) = %d com k = %d:" % (z, k))
    print("  k G = %s  ->  r = x mod n = %d" % (ponto(R), r))
    print("  s = k^-1 (H + d r) mod n = %d (%d + %d*%d) mod 19 = %d"
          % (inverso_multiplicativo(k, C.n), z, d, r, s))
    if r == 0 or s == 0:
        print("  r ou s deu zero: escolha outro k")
        return
    w = inverso_multiplicativo(s, C.n)
    u1, u2 = z * w % C.n, r * w % C.n
    X = ecdsa.somar(ecdsa.multiplicar(u1, C.G, C), ecdsa.multiplicar(u2, Q, C), C)
    print("\nverificar: w = %d, u1 = %d, u2 = %d" % (w, u1, u2))
    print("  u1 G + u2 Q = %s -> x mod n = %s == r = %d ? %s"
          % (ponto(X), "-" if X is None else X[0] % C.n, r,
             ecdsa.verificar_numero(z, (r, s), ecdsa.ChavePublica(C, Q))))


def main():
    print("=== 5. ECDSA - ASSINATURA COM CURVAS ELÍPTICAS ===\n")
    print("curva de brinquedo: %s, G = (5, 1)" % C.nome)
    pontos = ecdsa.todos_os_pontos(C)
    print("a curva tem %d pontos (contando o infinito)" % len(pontos))
    print("múltiplos de G (somar G com ele mesmo):")
    linha = []
    for i in range(1, C.n + 1):
        linha.append("%dG=%s" % (i, ponto(ecdsa.multiplicar(i, C.G, C))))
    for i in range(0, len(linha), 5):
        print("  " + "  ".join(linha[i:i + 5]))
    print("-> 19G = infinito: G tem ordem n = 19. Achar d a partir de dG é o log discreto.\n")

    pequeno(7, 10, 13)

    print("\ncom a curva P-256 (a do HTTPS):")
    print("  G está na curva? %s   n G = infinito? %s"
          % (ecdsa.P256.contem(ecdsa.P256.G), ecdsa.multiplicar(ecdsa.P256.n, ecdsa.P256.G, ecdsa.P256) is None))
    chave = ecdsa.gerar_chaves()
    print("  d = %s" % resumir(chave.d))
    print("  Q = (%s, %s)" % (resumir(chave.Q[0]), resumir(chave.Q[1])))
    dados = CONTRATO.encode("utf-8")
    r, s = ecdsa.assinar(dados, chave)
    print("  r = %s" % resumir(r))
    print("  s = %s" % resumir(s))
    print("  verificar original: %s" % ecdsa.verificar(dados, (r, s), chave.publica))
    print("  verificar trocado : %s" % ecdsa.verificar(CONTRATO_FALSO.encode("utf-8"), (r, s),
                                                      chave.publica))

    print("\nconferindo com o vetor de teste da RFC 6979 (A.2.5, mensagem 'sample'):")
    teste = ecdsa.ChavePrivada(ecdsa.P256, 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721)
    r, s = ecdsa.assinar(b"sample", teste)
    esperado_r = 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
    esperado_s = 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8
    print("  r = %X... %s" % (r >> 192, "OK" if r == esperado_r else "ERRO"))
    print("  s = %X... %s" % (s >> 192, "OK" if s == esperado_s else "ERRO"))
    print("\nchave de 256 bits na curva ~ segurança do RSA de 3072 bits.")


def interativo():
    print("curva %s, G = (5, 1), n = 19" % C.nome)
    d = ler_int("chave privada d (1 a 18): ", 1, 18)
    k = ler_int("k secreto (1 a 18): ", 1, 18)
    z = ler_int("H(M) (0 a 18): ", 0, 18)
    print()
    pequeno(d, k, z)


if __name__ == "__main__":
    main()
