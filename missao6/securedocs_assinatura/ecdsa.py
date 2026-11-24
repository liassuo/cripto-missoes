# ECDSA - DSA sobre curvas elípticas (ANSI X9.62, 1999; FIPS 186-4)
# Curva y^2 = x^3 + a x + b (mod p). Os pontos da curva, com a "soma de pontos",
# formam um grupo. Multiplicar k * G (somar G com ele mesmo k vezes) é fácil;
# achar k a partir de k * G (logaritmo discreto na curva) é muito difícil, e
# não existe o atalho (index calculus) que existe em Z_p*. Resultado: chave
# de 256 bits na curva ~ RSA de 3072 bits.
#
# chaves:     d aleatório em [1, n-1] (privada)    Q = d G (pública, um ponto)
# assinar:    k secreto,  (x1, y1) = k G,  r = x1 mod n
#             s = k^-1 (H(m) + d r) mod n
# verificar:  w = s^-1,  u1 = H(m) w,  u2 = r w,  (x1, y1) = u1 G + u2 Q
#             x1 mod n == r ?
# É exatamente o DSA trocando "g^k mod p" por "k G".

import secrets

from missao1.securedocs_math.inverso_multiplicativo import inverso_multiplicativo

from .rfc6979 import bits2int, candidatos_k
from .sha256 import sha256

INFINITO = None     # o "zero" do grupo: ponto no infinito


class Curva:
    def __init__(self, nome, p, a, b, gx, gy, n, h=1):
        self.nome = nome
        self.p, self.a, self.b = p, a, b
        self.G = (gx, gy)
        self.n = n          # ordem de G (n G = infinito)
        self.h = h          # cofator: número de pontos = h * n

    def contem(self, ponto):
        if ponto is INFINITO:
            return True
        x, y = ponto
        return 0 <= x < self.p and 0 <= y < self.p and \
            (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0

    @property
    def tamanho(self):
        return (self.p.bit_length() + 7) // 8


# NIST P-256 (secp256r1, FIPS 186-4 D.1.2.3): a curva mais usada no TLS
P256 = Curva(
    "P-256",
    p=2 ** 256 - 2 ** 224 + 2 ** 192 + 2 ** 96 - 1,
    a=-3,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
)

# curva de brinquedo para fazer as contas na mão (exemplo do livro de Paar e Pelzl):
# y^2 = x^3 + 2x + 2 mod 17, G = (5, 1) gera os 19 pontos
PEQUENA = Curva("y^2 = x^3 + 2x + 2 (mod 17)", p=17, a=2, b=2, gx=5, gy=1, n=19)


def negativo(ponto, curva):
    if ponto is INFINITO:
        return INFINITO
    return ponto[0], (-ponto[1]) % curva.p


def somar(P, Q, curva):
    if P is INFINITO:
        return Q
    if Q is INFINITO:
        return P
    p = curva.p
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return INFINITO                                     # P + (-P) = infinito
    if P == Q:
        # dobrar: inclinação da tangente  (3x^2 + a) / 2y
        lam = (3 * x1 * x1 + curva.a) * inverso_multiplicativo(2 * y1, p) % p
    else:
        # somar: inclinação da reta por P e Q  (y2 - y1) / (x2 - x1)
        lam = (y2 - y1) * inverso_multiplicativo(x2 - x1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p                         # reflete no eixo x
    return x3, y3


def multiplicar(k, P, curva, passos=None):
    """k P por "dobra e soma": a mesma ideia do exp_mod da Missão 1 (bits de k)."""
    if k < 0:
        return multiplicar(-k, negativo(P, curva), curva, passos)
    resultado = INFINITO
    for bit in bin(k)[2:] if k else "":
        resultado = somar(resultado, resultado, curva)
        if bit == "1":
            resultado = somar(resultado, P, curva)
        if passos is not None:
            passos.append((bit, resultado))
    return resultado


def todos_os_pontos(curva):
    # só para curvas pequenas
    pontos = [INFINITO]
    for x in range(curva.p):
        for y in range(curva.p):
            if curva.contem((x, y)):
                pontos.append((x, y))
    return pontos


class ChavePublica:
    def __init__(self, curva, Q):
        if Q is INFINITO or not curva.contem(Q):
            # sem isso o atacante manda um ponto de outra curva (invalid curve attack)
            raise ValueError("o ponto não está na curva")
        self.curva = curva
        self.Q = Q

    def __eq__(self, outra):
        return isinstance(outra, ChavePublica) and (self.curva.nome, self.Q) == (outra.curva.nome, outra.Q)


class ChavePrivada:
    def __init__(self, curva, d):
        self.curva = curva
        self.d = d
        self.Q = multiplicar(d, curva.G, curva)

    @property
    def publica(self):
        return ChavePublica(self.curva, self.Q)


def gerar_chaves(curva=P256):
    return ChavePrivada(curva, secrets.randbelow(curva.n - 1) + 1)


def resumo(dados, n):
    return bits2int(sha256(dados), n.bit_length())


def assinar_numero(z, privada, k=None, aleatorio=False, h1=None):
    curva = privada.curva
    n = curva.n
    if k is not None:
        fontes = iter([k])
    elif aleatorio:
        fontes = iter(lambda: secrets.randbelow(n - 1) + 1, None)
    else:
        fontes = candidatos_k(privada.d, n, h1 if h1 is not None else z.to_bytes(32, "big"))
    for k in fontes:
        x1, _ = multiplicar(k, curva.G, curva)
        r = x1 % n
        s = inverso_multiplicativo(k, n) * (z + privada.d * r) % n
        if r != 0 and s != 0:
            return r, s
    raise ValueError("k inválido (r ou s deu zero): escolha outro")


def verificar_numero(z, assinatura, publica):
    r, s = assinatura
    curva = publica.curva
    n = curva.n
    if not (0 < r < n and 0 < s < n):
        return False
    w = inverso_multiplicativo(s, n)
    ponto = somar(multiplicar(z * w % n, curva.G, curva),
                  multiplicar(r * w % n, publica.Q, curva), curva)
    return ponto is not INFINITO and ponto[0] % n == r


def assinar(dados, privada, k=None, aleatorio=False):
    """k=None: RFC 6979 (determinístico). aleatorio=True: k do gerador do sistema."""
    h1 = sha256(dados)
    return assinar_numero(bits2int(h1, privada.curva.n.bit_length()), privada, k, aleatorio, h1)


def verificar(dados, assinatura, publica):
    return verificar_numero(resumo(dados, publica.curva.n), assinatura, publica)


# ---------------------------------------------------------------- bytes e texto

def assinatura_para_bytes(assinatura, curva=P256):
    n = (curva.n.bit_length() + 7) // 8
    return assinatura[0].to_bytes(n, "big") + assinatura[1].to_bytes(n, "big")


def assinatura_de_bytes(dados, curva=P256):
    n = (curva.n.bit_length() + 7) // 8
    if len(dados) != 2 * n:
        return (0, 0)
    return int.from_bytes(dados[:n], "big"), int.from_bytes(dados[n:], "big")


def ponto_para_bytes(Q, curva=P256):
    # formato "não comprimido" do SEC 1: 04 || x || y
    return b"\x04" + Q[0].to_bytes(curva.tamanho, "big") + Q[1].to_bytes(curva.tamanho, "big")


def publica_para_dict(publica):
    return {"curva": publica.curva.nome, "Qx": "%X" % publica.Q[0], "Qy": "%X" % publica.Q[1]}


def publica_de_dict(campos):
    if campos.get("curva") != P256.nome:
        raise ValueError("curva desconhecida: %s" % campos.get("curva"))
    return ChavePublica(P256, (int(campos["Qx"], 16), int(campos["Qy"], 16)))


def privada_para_dict(privada):
    return {"curva": privada.curva.nome, "d": "%X" % privada.d}


def privada_de_dict(campos):
    if campos.get("curva") != P256.nome:
        raise ValueError("curva desconhecida: %s" % campos.get("curva"))
    return ChavePrivada(P256, int(campos["d"], 16))
