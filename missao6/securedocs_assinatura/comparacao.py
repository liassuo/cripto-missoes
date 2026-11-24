import time

from . import esquemas

# algoritmo, ano, problema difícil, chave para ~128 bits de segurança, tamanho da assinatura
CARACTERISTICAS = [
    ("RSA (PKCS#1 / PSS)", 1977, "fatoração", "3072 bits", "384 bytes"),
    ("DSA", 1991, "log discreto em Z_p*", "p 3072 / q 256", "64 bytes"),
    ("ECDSA", 1999, "log discreto em curva", "256 bits", "64 bytes"),
]


def medir(nome, repeticoes=5):
    _, _, gerar, assinar, verificar = esquemas.pegar(nome)
    inicio = time.perf_counter()
    privada = gerar()
    t_chave = time.perf_counter() - inicio

    dados = b"contrato de teste"
    inicio = time.perf_counter()
    for _ in range(repeticoes):
        assinatura = assinar(dados, privada)
    t_assinar = (time.perf_counter() - inicio) / repeticoes

    inicio = time.perf_counter()
    for _ in range(repeticoes):
        ok = verificar(dados, assinatura, privada.publica)
    t_verificar = (time.perf_counter() - inicio) / repeticoes
    return t_chave, t_assinar, t_verificar, len(assinatura), ok
