# SHA-256 (NIST, FIPS 180-4)
# Construção de Merkle-Damgård: a mensagem é completada até um múltiplo de 512 bits
# e processada bloco a bloco. Cada bloco passa por 64 rodadas de uma função de
# compressão que mistura 8 palavras de 32 bits (a..h) usando só soma mod 2^32,
# xor, and, not e rotação. A saída é o estado final: 8 x 32 = 256 bits.

MASCARA = 0xFFFFFFFF
TAMANHO_BLOCO = 64      # bytes
TAMANHO_HASH = 32       # bytes


def primeiros_primos(quantos):
    primos = []
    n = 2
    while len(primos) < quantos:
        if all(n % p for p in primos if p * p <= n):
            primos.append(n)
        n += 1
    return primos


def raiz_inteira(x, k):
    # maior r com r^k <= x (Newton partindo de cima)
    r = 1 << ((x.bit_length() + k - 1) // k)
    while True:
        novo = ((k - 1) * r + x // r ** (k - 1)) // k
        if novo >= r:
            return r
        r = novo


# As constantes não são "números mágicos" (nothing-up-my-sleeve): são os 32 primeiros
# bits da parte fracionária das raízes quadradas dos 8 primeiros primos (estado
# inicial) e das raízes cúbicas dos 64 primeiros primos (constantes de rodada).
#   raiz(p * 2^64) = raiz(p) * 2^32 -> os 32 bits de baixo são a parte fracionária
H_INICIAL = [raiz_inteira(p << 64, 2) & MASCARA for p in primeiros_primos(8)]
K = [raiz_inteira(p << 96, 3) & MASCARA for p in primeiros_primos(64)]


def girar_dir(x, n):
    return ((x >> n) | (x << (32 - n))) & MASCARA


def ch(e, f, g):
    # "choose": cada bit de e escolhe o bit de f (1) ou de g (0)
    return (e & f) ^ (~e & MASCARA & g)


def maj(a, b, c):
    # "majority": o bit que aparece em pelo menos dois dos três
    return (a & b) ^ (a & c) ^ (b & c)


def soma0(a):
    return girar_dir(a, 2) ^ girar_dir(a, 13) ^ girar_dir(a, 22)


def soma1(e):
    return girar_dir(e, 6) ^ girar_dir(e, 11) ^ girar_dir(e, 25)


def sigma0(x):
    return girar_dir(x, 7) ^ girar_dir(x, 18) ^ (x >> 3)


def sigma1(x):
    return girar_dir(x, 17) ^ girar_dir(x, 19) ^ (x >> 10)


def preencher(dados):
    # acrescenta o bit 1, zeros até sobrar 64 bits no bloco e o tamanho original em bits.
    # Gravar o tamanho no fim (fortalecimento de Merkle-Damgård) impede que duas
    # mensagens de tamanhos diferentes fiquem iguais depois do enchimento.
    tamanho_bits = 8 * len(dados)
    dados = dados + b"\x80"
    dados += bytes((56 - len(dados) % 64) % 64)
    return dados + tamanho_bits.to_bytes(8, "big")


def expandir(bloco):
    # as 16 palavras do bloco viram 64 (uma por rodada)
    w = [int.from_bytes(bloco[i:i + 4], "big") for i in range(0, 64, 4)]
    for t in range(16, 64):
        w.append((sigma1(w[t - 2]) + w[t - 7] + sigma0(w[t - 15]) + w[t - 16]) & MASCARA)
    return w


def comprimir(estado, bloco, passos=None):
    w = expandir(bloco)
    a, b, c, d, e, f, g, h = estado
    for t in range(64):
        t1 = (h + soma1(e) + ch(e, f, g) + K[t] + w[t]) & MASCARA
        t2 = (soma0(a) + maj(a, b, c)) & MASCARA
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & MASCARA, c, b, a, (t1 + t2) & MASCARA
        if passos is not None:
            passos.append((t, w[t], (a, b, c, d, e, f, g, h)))
    # soma com o estado de entrada (Davies-Meyer): a compressão não pode ser invertida
    return [(x + y) & MASCARA for x, y in zip(estado, (a, b, c, d, e, f, g, h))]


def sha256(dados, passos=None):
    """Resumo de 32 bytes. Se passos for uma lista, guarda as rodadas do 1o bloco."""
    if isinstance(dados, str):
        dados = dados.encode("utf-8")
    estado = list(H_INICIAL)
    mensagem = preencher(bytes(dados))
    for i in range(0, len(mensagem), TAMANHO_BLOCO):
        estado = comprimir(estado, mensagem[i:i + TAMANHO_BLOCO], passos if i == 0 else None)
    return b"".join(x.to_bytes(4, "big") for x in estado)


def sha256_hex(dados):
    return sha256(dados).hex().upper()


def sha256_arquivo(caminho):
    with open(caminho, "rb") as f:
        return sha256(f.read())
