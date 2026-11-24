# Junta todos os algoritmos com as mesmas funções, para o assinador de
# documentos (documento.py) e a comparação funcionarem com qualquer um:
#   gerar_chaves() -> privada   (privada.publica é a pública)
#   assinar(dados, privada) -> bytes
#   verificar(dados, assinatura, publica) -> True / False

from . import rsa, pkcs1, dsa, ecdsa


# o RSA "de livro" devolve um número; aqui vira bytes
def rsa_livro_assinar(dados, privada):
    s = rsa.assinar_livro(dados, privada)
    return s.to_bytes((privada.n.bit_length() + 7) // 8, "big")


def rsa_livro_verificar(dados, assinatura, publica):
    return rsa.verificar_livro(dados, int.from_bytes(assinatura, "big"), publica)


# DSA e ECDSA devolvem o par (r, s); aqui vira bytes r || s
def dsa_assinar(dados, privada):
    return dsa.assinatura_para_bytes(dsa.assinar(dados, privada), privada.parametros.q)


def dsa_verificar(dados, assinatura, publica):
    q = publica.parametros.q
    return dsa.verificar(dados, dsa.assinatura_de_bytes(assinatura, q), publica)


def ecdsa_assinar(dados, privada):
    return ecdsa.assinatura_para_bytes(ecdsa.assinar(dados, privada))


def ecdsa_verificar(dados, assinatura, publica):
    return ecdsa.verificar(dados, ecdsa.assinatura_de_bytes(assinatura), publica)


def rsa_2048():
    return rsa.gerar_chaves(2048)


# nome: (família, módulo das chaves, gerar, assinar, verificar)
ESQUEMAS = {
    "RSA-livro-SHA256": ("fatoração", rsa, rsa_2048, rsa_livro_assinar, rsa_livro_verificar),
    "RSA-PKCS1v15-SHA256": ("fatoração", rsa, rsa_2048, pkcs1.assinar_v15, pkcs1.verificar_v15),
    "RSA-PSS-SHA256": ("fatoração", rsa, rsa_2048, pkcs1.assinar_pss, pkcs1.verificar_pss),
    "DSA-2048-256-SHA256": ("log discreto", dsa, dsa.gerar_chaves, dsa_assinar, dsa_verificar),
    "ECDSA-P256-SHA256": ("curvas elípticas", ecdsa, ecdsa.gerar_chaves,
                          ecdsa_assinar, ecdsa_verificar),
}


def pegar(nome):
    if nome not in ESQUEMAS:
        raise ValueError("algoritmo desconhecido: %s" % nome)
    return ESQUEMAS[nome]
