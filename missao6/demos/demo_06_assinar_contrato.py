import os
import shutil
import sys
MISSAO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, MISSAO)
sys.path.insert(0, os.path.dirname(MISSAO))

from entrada import ler_int, ler_texto
from missao3.securedocs_simetrica import arquivo, troca_chaves
from securedocs_assinatura import documento, esquemas, rsa
from securedocs_assinatura.util import para_hex
from pasta import PASTA, limpar_caminho
from textos import CONTRATO

ALGORITMO_ESCOLHIDO = "ECDSA-P256-SHA256"


def mostrar_arquivo(caminho):
    print("  ----- %s -----" % os.path.basename(caminho))
    with open(caminho, encoding="utf-8") as f:
        for linha in f:
            linha = linha.rstrip("\n")
            print("  " + (linha if len(linha) <= 90 else linha[:87] + "..."))


def mostrar_verificacao(titulo, caminho, sig, pub):
    ok, mensagens = documento.verificar_arquivo(caminho, sig, pub)
    print("%s -> %s" % (titulo, "ASSINATURA VÁLIDA" if ok else "ASSINATURA INVÁLIDA"))
    for m in mensagens:
        print("    " + m)


def experimento(original, algoritmo):
    os.makedirs(PASTA, exist_ok=True)
    _, _, gerar, _, _ = esquemas.pegar(algoritmo)

    print("1) a TechSecure gera seu par de chaves (%s)" % algoritmo)
    privada = gerar()
    pub, key = documento.salvar_chaves(PASTA, "TechSecure", algoritmo, privada)
    print("   %s  (pública: vai para o site / para o cliente)" % pub)
    print("   %s  (privada: fica só com a TechSecure)\n" % key)

    print("2) documento -> hash -> assinatura com a chave privada")
    sig, _ = documento.assinar_arquivo(original, algoritmo, privada, "TechSecure - Diretoria")
    mostrar_arquivo(sig)

    print("\n3) o cliente verifica: documento + assinatura + chave pública")
    mostrar_verificacao("   contrato recebido", original, sig, pub)

    print("\n4) Eva muda o contrato no caminho e manda junto o .sig original")
    nome, ext = os.path.splitext(os.path.basename(original))
    alterado = os.path.join(PASTA, nome + "_alterado" + ext)
    shutil.copyfile(original, alterado)
    with open(alterado, "r+b") as f:
        primeiro = f.read(1) or b"\x00"
        f.seek(0)
        f.write(bytes([primeiro[0] ^ 1]))             # troca 1 bit do 1o byte
    print("   (%s: só 1 bit diferente)" % os.path.basename(alterado))
    shutil.copyfile(sig, alterado + ".sig")
    mostrar_verificacao("   contrato alterado", alterado, alterado + ".sig", pub)

    print("\n5) Eva assina o contrato alterado com a chave DELA e diz que é da TechSecure")
    chave_eva = gerar()
    documento.salvar_chaves(PASTA, "Eva", algoritmo, chave_eva)
    documento.assinar_arquivo(alterado, algoritmo, chave_eva, "TechSecure - Diretoria")
    mostrar_verificacao("   com a chave pública da TechSecure", alterado, alterado + ".sig", pub)
    print("   (o nome no .sig é só texto; quem decide é a chave pública usada na verificação)")
    print("\n(arquivos em %s)" % PASTA)


def assinatura_secreta():
    print("\n--- ASSINATURA SECRETA (slide: AES + RSA + hash) ---")
    print("a assinatura sozinha não esconde nada: o contrato vai aberto. Juntando com a Missão 3:")
    dados = CONTRATO.encode("utf-8")
    privada_ts = esquemas.pegar(ALGORITMO_ESCOLHIDO)[2]()
    cliente = rsa.gerar_chaves(2048)
    publica_cliente = (cliente.n, cliente.e)
    privada_cliente = (cliente.n, cliente.d)

    campos = documento.assinar_dados(dados, "contrato.txt", ALGORITMO_ESCOLHIDO, privada_ts,
                                     "TechSecure - Diretoria")
    print("  1. hash assinado (ECDSA)                   : %s..." % campos["assinatura"][:32])
    chave_aes = arquivo.gerar_chave(256)
    cifrado = arquivo.cifrar_dados(dados, chave_aes)
    print("  2. contrato cifrado com AES-256-CBC         : %s..." % para_hex(cifrado[22:38]))
    envelope = troca_chaves.envelope_fechar(chave_aes, publica_cliente)
    print("  3. chave AES no envelope RSA do cliente     : %X..." % (envelope >> (envelope.bit_length() - 64)))
    print("  -> vai para o cliente: cifrado + envelope + assinatura")

    print("  o cliente abre o envelope com a privada dele, decifra e verifica:")
    chave_aberta = troca_chaves.envelope_abrir(envelope, privada_cliente, 32)
    recebido = arquivo.decifrar_dados(cifrado, chave_aberta)
    ok, _ = documento.verificar_dados(recebido, campos, ALGORITMO_ESCOLHIDO, privada_ts.publica)
    print("     '%s...'" % recebido.decode("utf-8")[:50])
    print("     assinatura da TechSecure: %s" % ("VÁLIDA" if ok else "INVÁLIDA"))
    print("  confidencialidade (AES), integridade + autenticidade + não repúdio (assinatura)")


def main():
    print("=== 6. EXPERIMENTO: ASSINAR E VERIFICAR O CONTRATO ===\n")
    os.makedirs(PASTA, exist_ok=True)
    original = os.path.join(PASTA, "contrato.txt")
    with open(original, "w", encoding="utf-8") as f:
        f.write(CONTRATO + "\n")
    experimento(original, ALGORITMO_ESCOLHIDO)
    assinatura_secreta()


def interativo():
    caminho = ler_texto("caminho do arquivo (enter = contrato de exemplo): ")
    nomes = list(esquemas.ESQUEMAS)
    print("algoritmo:")
    for i, nome in enumerate(nomes, 1):
        print("  %d - %s" % (i, nome))
    algoritmo = nomes[ler_int("opção: ", 1, len(nomes)) - 1]
    if caminho:
        caminho = limpar_caminho(caminho)
        if not os.path.isfile(caminho):
            print("arquivo não encontrado")
            return
        os.makedirs(PASTA, exist_ok=True)
        copia = os.path.join(PASTA, os.path.basename(caminho))
        if os.path.abspath(copia) != os.path.abspath(caminho):
            shutil.copyfile(caminho, copia)
        caminho = copia
    else:
        os.makedirs(PASTA, exist_ok=True)
        caminho = os.path.join(PASTA, "contrato.txt")
        with open(caminho, "w", encoding="utf-8") as f:
            f.write(CONTRATO + "\n")
    print()
    experimento(caminho, algoritmo)


if __name__ == "__main__":
    main()
