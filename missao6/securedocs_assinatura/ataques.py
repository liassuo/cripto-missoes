# Testando (atacando) as assinaturas, como pede o item 6 do PBL

import secrets

from missao1.securedocs_math.exponenciacao_modular import exp_mod
from missao1.securedocs_math.inverso_multiplicativo import inverso_multiplicativo

from .sha256 import sha256


# ---------------------------------------------------------------- RSA sem hash
# Se o RSA assinar a mensagem direto (s = m^d), sem passar pelo hash:

def rsa_falsificacao(publica):
    # escolhe a "assinatura" primeiro e calcula a mensagem que ela assina.
    # A mensagem sai aleatória (lixo), mas o par (m, s) é válido sem a chave privada.
    s = secrets.randbelow(publica.n - 2) + 2
    m = exp_mod(s, publica.e, publica.n)
    return m, s


def rsa_multiplicativa(s1, s2, publica):
    # (m1^d)(m2^d) = (m1 m2)^d: com duas assinaturas, sai a de m1*m2 de graça
    return s1 * s2 % publica.n


# ---------------------------------------------------------------- k repetido no DSA
# s = k^-1 (H + x r) mod q. O slide diz que k é um número secreto POR MENSAGEM.
# Se duas mensagens usam o MESMO k, r sai igual e dá para isolar k e depois x:
#   s1 - s2 = k^-1 (H1 - H2)   ->   k = (H1 - H2) / (s1 - s2)
#   x = (s1 k - H1) / r                                  (tudo mod q)

def recuperar_chave_k_repetido(h1, assinatura1, h2, assinatura2, q):
    r1, s1 = assinatura1
    r2, s2 = assinatura2
    if r1 != r2:
        raise ValueError("r diferente: o k não foi repetido")
    k = (h1 - h2) * inverso_multiplicativo(s1 - s2, q) % q
    x = (s1 * k - h1) * inverso_multiplicativo(r1, q) % q
    return k, x


# ---------------------------------------------------------------- colisão de hash
# A assinatura é feita sobre o HASH. Se o atacante achar dois contratos com o
# mesmo hash, a assinatura de um vale para o outro. Pelo slide, achar uma colisão
# custa 2^(n/2): com o SHA-256 inteiro, 2^128. Aqui o hash é cortado em poucos
# bits só para mostrar que, com hash fraco, o ataque funciona.

def variantes(texto, quantas_posicoes):
    # cada espaço pode virar dois espaços: 2^n versões com o mesmo sentido
    partes = texto.split(" ")
    posicoes = list(range(min(quantas_posicoes, len(partes) - 1)))
    for i in range(2 ** len(posicoes)):
        saida = partes[0]
        for j, parte in enumerate(partes[1:]):
            duplo = j in posicoes and (i >> j) & 1
            saida += ("  " if duplo else " ") + parte
        yield saida


def hash_cortado(texto, bits):
    return int.from_bytes(sha256(texto), "big") >> (256 - bits)


def colisao(contrato_bom, contrato_ruim, bits=20, posicoes=16):
    # vai gerando uma versão boa e uma ruim por vez, guardando os hashes das duas.
    # Paradoxo do aniversário: com ~2^(bits/2) de cada lado já aparece um hash igual.
    boas = {}
    ruins = {}
    tentativas = 0
    for bom, ruim in zip(variantes(contrato_bom, posicoes), variantes(contrato_ruim, posicoes)):
        h = hash_cortado(bom, bits)
        boas[h] = bom
        if h in ruins:
            return bom, ruins[h], h, tentativas + 1
        h = hash_cortado(ruim, bits)
        ruins[h] = ruim
        tentativas += 2
        if h in boas:
            return boas[h], ruim, h, tentativas
    return None, None, None, tentativas
