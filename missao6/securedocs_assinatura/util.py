def tamanho_bytes(n):
    return (n.bit_length() + 7) // 8


def int_para_bytes(x, n_bytes=None):
    if n_bytes is None:
        n_bytes = max(1, tamanho_bytes(x))
    return x.to_bytes(n_bytes, "big")


def bytes_para_int(dados):
    return int.from_bytes(dados, "big")


def para_hex(dados, grupo=0):
    texto = dados.hex().upper()
    if not grupo:
        return texto
    return " ".join(texto[i:i + 2 * grupo] for i in range(0, len(texto), 2 * grupo))


def resumir(x, n=16):
    # número grande na tela: só o começo e o tamanho
    texto = "%X" % x
    if len(texto) <= 2 * n:
        return texto
    return "%s... (%d bits)" % (texto[:n], x.bit_length())
