import time

from . import esquemas

# algoritmo, ano, problema difícil, chave usada, hash, tamanho da assinatura
CARACTERISTICAS = [
    ("RSA", "1977", "fatorar n = p q", "n de 2048 bits", "SHA-256", "256 bytes"),
    ("DSA (DSS)", "1991", "logaritmo discreto mod p", "p 1024 / q 160 bits", "SHA-1", "40 bytes"),
]


def medir(nome, repeticoes=5):
    _, gerar, assinar, verificar = esquemas.pegar(nome)
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
