# Junta os dois algoritmos com as mesmas funções, para o assinador de
# documentos (documento.py) e a comparação funcionarem com qualquer um:
#   gerar_chaves() -> privada   (privada.publica é a pública)
#   assinar(dados, privada) -> bytes
#   verificar(dados, assinatura, publica) -> True / False

from . import rsa, dsa


def rsa_2048():
    return rsa.gerar_chaves(2048)


def rsa_assinar(dados, privada):
    return rsa.assinatura_para_bytes(rsa.assinar(dados, privada), privada)


def rsa_verificar(dados, assinatura, publica):
    return rsa.verificar(dados, rsa.assinatura_de_bytes(assinatura), publica)


def dsa_assinar(dados, privada):
    return dsa.assinatura_para_bytes(dsa.assinar(dados, privada), privada.parametros.q)


def dsa_verificar(dados, assinatura, publica):
    q = publica.parametros.q
    return dsa.verificar(dados, dsa.assinatura_de_bytes(assinatura, q), publica)


# nome: (módulo das chaves, gerar, assinar, verificar)
ESQUEMAS = {
    "RSA-2048-SHA256": (rsa, rsa_2048, rsa_assinar, rsa_verificar),
    "DSA-1024-SHA1": (dsa, dsa.gerar_chaves, dsa_assinar, dsa_verificar),
}


def pegar(nome):
    if nome not in ESQUEMAS:
        raise ValueError("algoritmo desconhecido: %s" % nome)
    return ESQUEMAS[nome]
