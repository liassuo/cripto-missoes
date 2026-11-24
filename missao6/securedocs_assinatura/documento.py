# Experimento da missão: assinar e verificar um arquivo de verdade
#   assinar:    documento -> hash -> assinatura com a chave privada -> arquivo .sig
#   verificar:  documento + .sig + chave pública -> válida ou não
#
# O .sig é um texto simples para dar para abrir e mostrar na apresentação.
# O que é assinado não é só o hash do documento: junta quem assinou e quando,
# senão alguém poderia trocar o nome ou a data no .sig sem invalidar nada.

import os
import time

from . import esquemas
from .sha256 import sha256

INICIO_SIG = "-----SECUREDOCS ASSINATURA-----"
INICIO_PUB = "-----SECUREDOCS CHAVE PUBLICA-----"
INICIO_KEY = "-----SECUREDOCS CHAVE PRIVADA (NAO COMPARTILHAR)-----"


def ler_campos(caminho):
    campos = {}
    with open(caminho, encoding="utf-8") as f:
        for linha in f:
            if ":" in linha:
                nome, valor = linha.split(":", 1)
                campos[nome.strip()] = valor.strip()
    return campos


def gravar_campos(caminho, cabecalho, campos):
    with open(caminho, "w", encoding="utf-8") as f:
        f.write(cabecalho + "\n")
        for nome, valor in campos.items():
            f.write("%s: %s\n" % (nome, valor))


# ---------------------------------------------------------------- chaves

def salvar_chaves(pasta, dono, algoritmo, privada):
    _, modulo, _, _, _ = esquemas.pegar(algoritmo)
    nome = dono.lower().replace(" ", "_")
    caminho_pub = os.path.join(pasta, nome + ".pub")
    caminho_key = os.path.join(pasta, nome + ".key")
    campos = {"algoritmo": algoritmo, "dono": dono}
    campos.update(modulo.publica_para_dict(privada.publica))
    gravar_campos(caminho_pub, INICIO_PUB, campos)
    campos = {"algoritmo": algoritmo, "dono": dono}
    campos.update(modulo.privada_para_dict(privada))
    gravar_campos(caminho_key, INICIO_KEY, campos)
    return caminho_pub, caminho_key


def ler_publica(caminho):
    campos = ler_campos(caminho)
    _, modulo, _, _, _ = esquemas.pegar(campos["algoritmo"])
    return campos["algoritmo"], campos.get("dono", "?"), modulo.publica_de_dict(campos)


def ler_privada(caminho):
    campos = ler_campos(caminho)
    _, modulo, _, _, _ = esquemas.pegar(campos["algoritmo"])
    return campos["algoritmo"], campos.get("dono", "?"), modulo.privada_de_dict(campos)


# ---------------------------------------------------------------- assinatura

def mensagem_assinada(hash_documento, algoritmo, assinante, data):
    # o que de fato entra no algoritmo de assinatura
    texto = "SecureDocs\nsha256: %s\nalgoritmo: %s\nassinante: %s\ndata: %s\n" % (
        hash_documento.hex().upper(), algoritmo, assinante, data)
    return texto.encode("utf-8")


def assinar_dados(dados, nome_documento, algoritmo, privada, assinante, data=None):
    if data is None:
        data = time.strftime("%Y-%m-%d %H:%M:%S")
    _, _, _, assinar, _ = esquemas.pegar(algoritmo)
    h = sha256(dados)
    assinatura = assinar(mensagem_assinada(h, algoritmo, assinante, data), privada)
    return {
        "documento": nome_documento,
        "tamanho": str(len(dados)),
        "sha256": h.hex().upper(),
        "algoritmo": algoritmo,
        "assinante": assinante,
        "data": data,
        "assinatura": assinatura.hex().upper(),
    }


def verificar_dados(dados, campos, algoritmo_chave, publica):
    """Devolve (válida?, lista de mensagens explicando cada conferência)."""
    mensagens = []
    algoritmo = campos.get("algoritmo", "")
    if algoritmo != algoritmo_chave:
        mensagens.append("a assinatura é %s mas a chave é %s" % (algoritmo, algoritmo_chave))
        return False, mensagens

    h = sha256(dados)
    integro = h.hex().upper() == campos.get("sha256", "")
    if integro:
        mensagens.append("integridade: o SHA-256 do documento bate com o do .sig")
    else:
        mensagens.append("integridade: FALHOU - o documento não é o mesmo que foi assinado")

    _, _, _, _, verificar = esquemas.pegar(algoritmo)
    try:
        assinatura = bytes.fromhex(campos.get("assinatura", ""))
    except ValueError:
        assinatura = b""
    msg = mensagem_assinada(h, algoritmo, campos.get("assinante", ""), campos.get("data", ""))
    autentico = verificar(msg, assinatura, publica)
    if autentico:
        mensagens.append("autenticidade: a assinatura confere com a chave pública informada")
    else:
        mensagens.append("autenticidade: FALHOU - a assinatura não confere com essa chave pública")
    return integro and autentico, mensagens


def assinar_arquivo(caminho, algoritmo, privada, assinante):
    with open(caminho, "rb") as f:
        dados = f.read()
    campos = assinar_dados(dados, os.path.basename(caminho), algoritmo, privada, assinante)
    caminho_sig = caminho + ".sig"
    gravar_campos(caminho_sig, INICIO_SIG, campos)
    return caminho_sig, campos


def verificar_arquivo(caminho, caminho_sig, caminho_pub):
    with open(caminho, "rb") as f:
        dados = f.read()
    algoritmo, _, publica = ler_publica(caminho_pub)
    return verificar_dados(dados, ler_campos(caminho_sig), algoritmo, publica)
