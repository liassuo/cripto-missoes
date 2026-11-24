# DSA - Digital Signature Algorithm (NIST, FIPS 186, 1994; FIPS 186-4)
# Vem da assinatura de ElGamal (1985), mas as contas são feitas num subgrupo
# de ordem q (256 bits) dentro de Z_p* (p de 2048 bits): a assinatura fica
# com 2 x 256 bits = 64 bytes.
#
# parâmetros públicos: p, q primos com q | p - 1, e g de ordem q
# chaves:      x aleatório em [1, q-1] (privada)    y = g^x mod p (pública)
# assinar:     k aleatório e secreto em [1, q-1]
#              r = (g^k mod p) mod q
#              s = k^-1 (H(m) + x r) mod q
# verificar:   w = s^-1, u1 = H(m) w, u2 = r w (mod q)
#              v = (g^u1 y^u2 mod p) mod q  ==  r ?
#   porque g^u1 y^u2 = g^(w (H + x r)) = g^(k s s^-1) = g^k

import secrets

from missao1.securedocs_math.exponenciacao_modular import exp_mod
from missao1.securedocs_math.inverso_multiplicativo import inverso_multiplicativo
from missao1.securedocs_math.primos import gerar_primo, miller_rabin, PRIMOS_PEQUENOS

from .rfc6979 import bits2int, candidatos_k
from .sha256 import sha256


class Parametros:
    def __init__(self, p, q, g):
        self.p, self.q, self.g = p, q, g

    def __eq__(self, outro):
        return isinstance(outro, Parametros) and (self.p, self.q, self.g) == (outro.p, outro.q, outro.g)


class ChavePublica:
    def __init__(self, parametros, y):
        self.parametros = parametros
        self.y = y

    def __eq__(self, outra):
        return isinstance(outra, ChavePublica) and (self.parametros, self.y) == (outra.parametros, outra.y)


class ChavePrivada:
    def __init__(self, parametros, x):
        self.parametros = parametros
        self.x = x
        self.y = exp_mod(parametros.g, x, parametros.p)

    @property
    def publica(self):
        return ChavePublica(self.parametros, self.y)


def gerar_parametros(bits_p=2048, bits_q=256):
    """FIPS 186-4, A.1.1 (simplificado): primeiro q, depois p = 1 (mod 2q)."""
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
    # g = h^((p-1)/q) tem ordem q (ou 1, aí troca h)
    h = 2
    while True:
        g = exp_mod(h, (p - 1) // q, p)
        if g != 1:
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


def resumo(dados, q):
    # z = os bits mais à esquerda do hash, no máximo o tamanho de q
    return bits2int(sha256(dados), q.bit_length())


def assinar_numero(z, privada, k=None):
    par = privada.parametros
    p, q, g = par.p, par.q, par.g
    if k is not None:
        fontes = iter([k])
    else:
        fontes = candidatos_k(privada.x, q, z.to_bytes(32, "big"))
    for k in fontes:
        r = exp_mod(g, k, p) % q
        s = inverso_multiplicativo(k, q) * (z + privada.x * r) % q
        if r != 0 and s != 0:
            return r, s
    raise ValueError("k inválido (r ou s deu zero): escolha outro")


def verificar_numero(z, assinatura, publica):
    r, s = assinatura
    par = publica.parametros
    p, q, g = par.p, par.q, par.g
    if not (0 < r < q and 0 < s < q):
        return False
    w = inverso_multiplicativo(s, q)
    u1 = z * w % q
    u2 = r * w % q
    v = exp_mod(g, u1, p) * exp_mod(publica.y, u2, p) % p % q
    return v == r


def assinar(dados, privada, k=None, aleatorio=False):
    """k=None: RFC 6979 (determinístico). aleatorio=True: k do gerador do sistema."""
    q = privada.parametros.q
    if aleatorio and k is None:
        k = secrets.randbelow(q - 1) + 1
    return assinar_numero(resumo(dados, q), privada, k)


def verificar(dados, assinatura, publica):
    return verificar_numero(resumo(dados, publica.parametros.q), assinatura, publica)


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
