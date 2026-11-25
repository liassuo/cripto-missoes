# SHA-1 (NIST, FIPS 180-1, 1995) - o hash dos slides da disciplina e do DSS
# Seguindo os slides: enchimento até L + 1 + k = 448 mod 512, blocos de 512 bits
# em 16 palavras, valores iniciais H0..H4, funções f(0)..f(79) e constantes
# K(0)..K(79). Saída de 160 bits. Usado aqui no DSA, como no FIPS 186.

from .sha256 import preencher

MASCARA = 0xFFFFFFFF
H_INICIAL = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
K = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]   # raiz(2), raiz(3), raiz(5), raiz(10) * 2^30


def rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & MASCARA


def f(t, b, c, d):
    if t < 20:
        return (b & c) | (~b & MASCARA & d)        # Ch
    if t < 40:
        return b ^ c ^ d                           # Parity
    if t < 60:
        return (b & c) | (b & d) | (c & d)         # Maj
    return b ^ c ^ d                               # Parity


def comprimir(estado, bloco):
    w = [int.from_bytes(bloco[i:i + 4], "big") for i in range(0, 64, 4)]
    for t in range(16, 80):
        w.append(rotl(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1))
    a, b, c, d, e = estado
    for t in range(80):
        temp = (rotl(a, 5) + f(t, b, c, d) + e + K[t // 20] + w[t]) & MASCARA
        a, b, c, d, e = temp, a, rotl(b, 30), c, d
    return [(x + y) & MASCARA for x, y in zip(estado, (a, b, c, d, e))]


def sha1(dados):
    if isinstance(dados, str):
        dados = dados.encode("utf-8")
    estado = list(H_INICIAL)
    mensagem = preencher(bytes(dados))      # o enchimento é o mesmo do SHA-256
    for i in range(0, len(mensagem), 64):
        estado = comprimir(estado, mensagem[i:i + 64])
    return b"".join(x.to_bytes(4, "big") for x in estado)


def sha1_hex(dados):
    return sha1(dados).hex().upper()
