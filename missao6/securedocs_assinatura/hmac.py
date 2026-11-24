# HMAC (Bellare, Canetti e Krawczyk, 1996; RFC 2104)
#   HMAC(K, m) = H((K xor opad) || H((K xor ipad) || m))
# Garante integridade e autenticidade entre quem COMPARTILHA a chave K.
# Não dá não repúdio: o destinatário tem a mesma chave e poderia ter
# gerado a etiqueta sozinho. É exatamente o que a assinatura digital resolve.

from .sha256 import sha256, TAMANHO_BLOCO
from .util import iguais

IPAD = 0x36
OPAD = 0x5C


def hmac_sha256(chave, mensagem):
    if isinstance(mensagem, str):
        mensagem = mensagem.encode("utf-8")
    if len(chave) > TAMANHO_BLOCO:
        chave = sha256(chave)
    chave = chave.ljust(TAMANHO_BLOCO, b"\x00")
    interno = sha256(bytes(b ^ IPAD for b in chave) + mensagem)
    return sha256(bytes(b ^ OPAD for b in chave) + interno)


def verificar_hmac(chave, mensagem, etiqueta):
    return iguais(hmac_sha256(chave, mensagem), etiqueta)
