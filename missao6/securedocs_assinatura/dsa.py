# DSA - Digital Signature Algorithm (NIST, 1991; padrão DSS, FIPS 186)
# Seguindo o slide da aula:
#   chave pública global: p primo com 2^(L-1) < p < 2^L (L de 512 a 1024, múltiplo de 64)
#                         q primo de 160 bits que divide p - 1
#                         g = h^((p-1)/q) mod p, com g > 1
#   chave do usuário:     x aleatório com 0 < x < q (privada)   y = g^x mod p (pública)
#   número secreto:       k aleatório com 0 < k < q, um NOVO para cada mensagem
#   assinar:              r = (g^k mod p) mod q
#                         s = [k^-1 (H(M) + x r)] mod q
#   verificar:            w = s^-1 mod q, u1 = [H(M) w] mod q, u2 = (r w) mod q
#                         v = [(g^u1 y^u2) mod p] mod q      teste: v = r ?
#   porque g^u1 y^u2 = g^(w (H + x r)) = g^(k s s^-1) = g^k
# H = SHA-1, como no FIPS 186 do slide (160 bits, o mesmo tamanho de q).

import secrets

from missao1.securedocs_math.exponenciacao_modular import exp_mod
from missao1.securedocs_math.inverso_multiplicativo import inverso_multiplicativo
from missao1.securedocs_math.primos import gerar_primo, miller_rabin, PRIMOS_PEQUENOS

from .sha1 import sha1


class Parametros:
    def __init__(self, p, q, g):
        self.p, self.q, self.g = p, q, g


class ChavePublica:
    def __init__(self, parametros, y):
        self.parametros = parametros
        self.y = y


class ChavePrivada:
    def __init__(self, parametros, x):
        self.parametros = parametros
        self.x = x
        self.y = exp_mod(parametros.g, x, parametros.p)

    @property
    def publica(self):
        return ChavePublica(self.parametros, self.y)


def gerar_parametros(bits_p=1024, bits_q=160):
    # primeiro q, depois procura p = 1 (mod 2q) que seja primo
    q = gerar_primo(bits_q)
    while True:
        x = secrets.randbits(bits_p) | (1 << (bits_p - 1))
        p = x - (x % (2 * q)) + 1          # p - 1 é múltiplo de 2q
        if p.bit_length() != bits_p:
            continue
        if any(p % primo == 0 for primo in PRIMOS_PEQUENOS):
            continue
        if miller_rabin(p, 1) and miller_rabin(p):
            break
    # g = h^((p-1)/q) mod p, trocando h enquanto der 1
    h = 2
    while True:
        g = exp_mod(h, (p - 1) // q, p)
        if g > 1:
            return Parametros(p, q, g)
        h += 1


def parametros_validos(par):
    return (miller_rabin(par.q) and miller_rabin(par.p) and (par.p - 1) % par.q == 0
            and 1 < par.g < par.p and exp_mod(par.g, par.q, par.p) == 1)


def parametros_padrao():
    # gerados uma vez por gerar_parametros() e guardados em parametros.py
    from . import parametros
    return Parametros(parametros.P, parametros.Q, parametros.G)


def gerar_chaves(parametros=None):
    if parametros is None:
        parametros = parametros_padrao()
    return ChavePrivada(parametros, secrets.randbelow(parametros.q - 1) + 1)


def resumo(dados):
    return int.from_bytes(sha1(dados), "big")


def assinar_numero(h, privada, k=None):
    par = privada.parametros
    p, q, g = par.p, par.q, par.g
    while True:
        # k secreto e novo para cada mensagem (o slide: "número secreto por msg")
        k_usado = k if k is not None else secrets.randbelow(q - 1) + 1
        r = exp_mod(g, k_usado, p) % q
        s = inverso_multiplicativo(k_usado, q) * (h + privada.x * r) % q
        if r != 0 and s != 0:
            return r, s
        if k is not None:
            raise ValueError("com esse k, r ou s deu zero: escolha outro")


def verificar_numero(h, assinatura, publica):
    r, s = assinatura
    par = publica.parametros
    p, q, g = par.p, par.q, par.g
    if not (0 < r < q and 0 < s < q):
        return False
    w = inverso_multiplicativo(s, q)
    u1 = h * w % q
    u2 = r * w % q
    v = exp_mod(g, u1, p) * exp_mod(publica.y, u2, p) % p % q
    return v == r


def assinar(dados, privada, k=None):
    return assinar_numero(resumo(dados), privada, k)


def verificar(dados, assinatura, publica):
    return verificar_numero(resumo(dados), assinatura, publica)


# ---------------------------------------------------------------- bytes e texto

def assinatura_para_bytes(assinatura, q):
    n = (q.bit_length() + 7) // 8
    return assinatura[0].to_bytes(n, "big") + assinatura[1].to_bytes(n, "big")


def assinatura_de_bytes(dados, q):
    n = (q.bit_length() + 7) // 8
    if len(dados) != 2 * n:
        return (0, 0)
    return int.from_bytes(dados[:n], "big"), int.from_bytes(dados[n:], "big")


def parametros_para_dict(par):
    return {"p": "%X" % par.p, "q": "%X" % par.q, "g": "%X" % par.g}


def parametros_de_dict(campos):
    return Parametros(int(campos["p"], 16), int(campos["q"], 16), int(campos["g"], 16))


def publica_para_dict(publica):
    campos = parametros_para_dict(publica.parametros)
    campos["y"] = "%X" % publica.y
    return campos


def publica_de_dict(campos):
    return ChavePublica(parametros_de_dict(campos), int(campos["y"], 16))


def privada_para_dict(privada):
    campos = parametros_para_dict(privada.parametros)
    campos["x"] = "%X" % privada.x
    return campos


def privada_de_dict(campos):
    return ChavePrivada(parametros_de_dict(campos), int(campos["x"], 16))
