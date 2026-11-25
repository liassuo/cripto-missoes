# Assinatura com RSA (Rivest, Shamir e Adleman, 1977)
# Na Missão 3 a chave pública trancava (cifrava) e a privada abria.
# Na assinatura é o contrário: só o dono da chave PRIVADA consegue produzir
#   s = H(M)^d mod n
# e qualquer um confere com a chave PÚBLICA:
#   s^e mod n == H(M) ?
# Como no slide da aula: Mensagem -> hash -> RSA com a chave privada do emissor.
# Toda a matemática vem da Missão 1: primos (Miller-Rabin), inverso (Euclides
# estendido), exponenciação modular e Teorema Chinês do Resto.

from missao1.securedocs_math.exponenciacao_modular import exp_mod
from missao1.securedocs_math.inverso_multiplicativo import inverso_multiplicativo
from missao1.securedocs_math.mdc import coprimos
from missao1.securedocs_math.primos import gerar_primo
from missao1.securedocs_math.tcr import tcr

from .sha256 import sha256
from .util import bytes_para_int, int_para_bytes, tamanho_bytes

E_PADRAO = 65537        # 2^16 + 1: primo, só dois bits em 1 -> verificação rápida


class ChavePublica:
    def __init__(self, n, e):
        self.n = n
        self.e = e

    @property
    def bits(self):
        return self.n.bit_length()


class ChavePrivada:
    def __init__(self, n, e, d, p, q):
        self.n, self.e, self.d, self.p, self.q = n, e, d, p, q
        # valores do TCR: contas mod p e mod q (números com metade do tamanho)
        self.dp = d % (p - 1)
        self.dq = d % (q - 1)

    @property
    def bits(self):
        return self.n.bit_length()

    @property
    def publica(self):
        return ChavePublica(self.n, self.e)


def chaves_de_primos(p, q, e=E_PADRAO):
    if p == q:
        raise ValueError("p e q precisam ser diferentes")
    phi_n = (p - 1) * (q - 1)
    if not coprimos(e, phi_n):
        raise ValueError("e = %d não é coprimo com phi(n) = %d" % (e, phi_n))
    d = inverso_multiplicativo(e, phi_n)
    return ChavePrivada(p * q, e, d, p, q)


def gerar_chaves(bits=2048, e=E_PADRAO):
    while True:
        p = gerar_primo(bits // 2)
        q = gerar_primo(bits - bits // 2)
        if p == q or (p * q).bit_length() != bits:
            continue
        if coprimos(e, (p - 1) * (q - 1)):
            return chaves_de_primos(p, q, e)


def operacao_privada(m, privada):
    # m^d mod n pelo TCR: m^dp mod p e m^dq mod q, juntados (cerca de 3x mais rápido)
    if not 0 <= m < privada.n:
        raise ValueError("o número precisa estar entre 0 e n - 1")
    s, _ = tcr([exp_mod(m, privada.dp, privada.p), exp_mod(m, privada.dq, privada.q)],
               [privada.p, privada.q])
    return s


def operacao_publica(s, publica):
    if not 0 <= s < publica.n:
        raise ValueError("o número precisa estar entre 0 e n - 1")
    return exp_mod(s, publica.e, publica.n)


def hash_como_numero(dados, n):
    return bytes_para_int(sha256(dados)) % n


def assinar(dados, privada):
    """Documento -> SHA-256 -> H^d mod n. Devolve a assinatura como número."""
    return operacao_privada(hash_como_numero(dados, privada.n), privada)


def verificar(dados, assinatura, publica):
    if not 0 < assinatura < publica.n:
        return False
    return operacao_publica(assinatura, publica) == hash_como_numero(dados, publica.n)


# ---------------------------------------------------------------- bytes e texto

def assinatura_para_bytes(s, chave):
    return int_para_bytes(s, tamanho_bytes(chave.n))


def assinatura_de_bytes(dados):
    return bytes_para_int(dados)


def publica_para_dict(publica):
    return {"n": "%X" % publica.n, "e": "%X" % publica.e}


def publica_de_dict(campos):
    return ChavePublica(int(campos["n"], 16), int(campos["e"], 16))


def privada_para_dict(privada):
    return {"n": "%X" % privada.n, "e": "%X" % privada.e, "d": "%X" % privada.d,
            "p": "%X" % privada.p, "q": "%X" % privada.q}


def privada_de_dict(campos):
    return ChavePrivada(*(int(campos[c], 16) for c in ("n", "e", "d", "p", "q")))
