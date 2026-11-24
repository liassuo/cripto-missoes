# k determinístico (Pornin, RFC 6979, 2013)
# DSA e ECDSA precisam de um número k secreto e ÚNICO por assinatura.
# Se k se repetir ou for previsível, a chave privada vaza (ataques.py, caso PS3).
# A RFC 6979 tira k de um HMAC da chave privada com o hash da mensagem:
# não depende do gerador aleatório e nunca se repete para mensagens diferentes.

from .hmac import hmac_sha256


def bits2int(dados, qlen):
    # os qlen bits mais à esquerda de dados
    x = int.from_bytes(dados, "big")
    excesso = 8 * len(dados) - qlen
    return x >> excesso if excesso > 0 else x


def int2octets(x, rlen):
    return x.to_bytes(rlen, "big")


def bits2octets(dados, q, qlen, rlen):
    z = bits2int(dados, qlen)
    return int2octets(z - q if z >= q else z, rlen)


def candidatos_k(x, q, h1):
    """Gera os valores de k em ordem (o primeiro quase sempre serve)."""
    qlen = q.bit_length()
    rlen = (qlen + 7) // 8
    v = b"\x01" * 32
    k = b"\x00" * 32
    semente = int2octets(x, rlen) + bits2octets(h1, q, qlen, rlen)
    k = hmac_sha256(k, v + b"\x00" + semente)
    v = hmac_sha256(k, v)
    k = hmac_sha256(k, v + b"\x01" + semente)
    v = hmac_sha256(k, v)
    while True:
        t = b""
        while 8 * len(t) < qlen:
            v = hmac_sha256(k, v)
            t += v
        candidato = bits2int(t, qlen)
        if 1 <= candidato < q:
            yield candidato
        k = hmac_sha256(k, v + b"\x00")
        v = hmac_sha256(k, v)
