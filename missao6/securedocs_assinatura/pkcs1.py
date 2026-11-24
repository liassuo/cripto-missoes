# PKCS#1 v2.2 (RFC 8017): como o RSA assina de verdade
# O RSA "de livro" assina o número H(m) direto. O PKCS#1 primeiro monta um bloco
# EM do tamanho de n (enchimento) e só então calcula EM^d mod n.
#
# v1.5 (1993):  EM = 00 01 FF FF ... FF 00 || DigestInfo(SHA-256) || H(m)
#               determinístico; o DigestInfo diz qual hash foi usado.
# PSS  (Bellare e Rogaway, 1996): EM = maskedDB || H' || BC
#               com sal aleatório -> cada assinatura sai diferente; tem prova de
#               segurança (é o recomendado para sistemas novos).

import secrets

from .rsa import operacao_privada, operacao_publica
from .sha256 import sha256, TAMANHO_HASH
from .util import bytes_para_int, int_para_bytes, tamanho_bytes, xor_bytes, iguais

# DER de: SEQUENCE { SEQUENCE { OID sha256 (2.16.840.1.101.3.4.2.1), NULL }, OCTET STRING (32) }
DIGEST_INFO_SHA256 = bytes.fromhex("3031300D060960864801650304020105000420")


# ---------------------------------------------------------------- v1.5

def codificar_v15(dados, k):
    t = DIGEST_INFO_SHA256 + sha256(dados)
    if k < len(t) + 11:
        raise ValueError("chave pequena demais para o PKCS#1 v1.5")
    return b"\x00\x01" + b"\xFF" * (k - len(t) - 3) + b"\x00" + t


def assinar_v15(dados, privada):
    k = tamanho_bytes(privada.n)
    em = codificar_v15(dados, k)
    return int_para_bytes(operacao_privada(bytes_para_int(em), privada), k)


def abrir(assinatura, publica):
    # s^e mod n como bytes do tamanho de n (o que o verificador "enxerga")
    k = tamanho_bytes(publica.n)
    s = bytes_para_int(assinatura)
    if len(assinatura) != k or s >= publica.n:
        return None
    return int_para_bytes(operacao_publica(s, publica), k)


def verificar_v15(dados, assinatura, publica):
    em = abrir(assinatura, publica)
    if em is None:
        return False
    # monta o bloco esperado e compara INTEIRO (não "procura o hash lá dentro":
    # foi assim que o ataque de Bleichenbacher de 2006 falsificou assinaturas com e = 3)
    return iguais(em, codificar_v15(dados, len(em)))


# ---------------------------------------------------------------- PSS

def mgf1(semente, tamanho):
    # gerador de máscara: H(semente || 0) || H(semente || 1) || ...
    saida = b""
    contador = 0
    while len(saida) < tamanho:
        saida += sha256(semente + contador.to_bytes(4, "big"))
        contador += 1
    return saida[:tamanho]


def codificar_pss(dados, em_bits, sal=None, tamanho_sal=TAMANHO_HASH):
    em_len = (em_bits + 7) // 8
    h_m = sha256(dados)
    if em_len < TAMANHO_HASH + tamanho_sal + 2:
        raise ValueError("chave pequena demais para o PSS")
    if sal is None:
        sal = secrets.token_bytes(tamanho_sal)
    h = sha256(bytes(8) + h_m + sal)
    db = bytes(em_len - tamanho_sal - TAMANHO_HASH - 2) + b"\x01" + sal
    masked_db = bytearray(xor_bytes(db, mgf1(h, em_len - TAMANHO_HASH - 1)))
    masked_db[0] &= 0xFF >> (8 * em_len - em_bits)       # garante EM < n
    return bytes(masked_db) + h + b"\xBC"


def conferir_pss(dados, em, em_bits, tamanho_sal=TAMANHO_HASH):
    em_len = (em_bits + 7) // 8
    if len(em) != em_len or em_len < TAMANHO_HASH + tamanho_sal + 2 or em[-1] != 0xBC:
        return False
    masked_db, h = em[:em_len - TAMANHO_HASH - 1], em[em_len - TAMANHO_HASH - 1:-1]
    sobra = 0xFF >> (8 * em_len - em_bits)
    if masked_db[0] & ~sobra & 0xFF:
        return False
    db = bytearray(xor_bytes(masked_db, mgf1(h, em_len - TAMANHO_HASH - 1)))
    db[0] &= sobra
    inicio = em_len - TAMANHO_HASH - tamanho_sal - 2
    if any(db[:inicio]) or db[inicio] != 0x01:
        return False
    sal = bytes(db[-tamanho_sal:])
    return iguais(h, sha256(bytes(8) + sha256(dados) + sal))


def assinar_pss(dados, privada, sal=None):
    em_bits = privada.n.bit_length() - 1
    em = codificar_pss(dados, em_bits, sal)
    return int_para_bytes(operacao_privada(bytes_para_int(em), privada), tamanho_bytes(privada.n))


def verificar_pss(dados, assinatura, publica):
    k = tamanho_bytes(publica.n)
    s = bytes_para_int(assinatura)
    if len(assinatura) != k or s >= publica.n:
        return False
    em_bits = publica.n.bit_length() - 1
    m = operacao_publica(s, publica)
    if m.bit_length() > em_bits:
        return False
    return conferir_pss(dados, int_para_bytes(m, (em_bits + 7) // 8), em_bits)
