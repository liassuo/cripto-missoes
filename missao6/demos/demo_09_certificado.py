import os
import sys
MISSAO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, MISSAO)
sys.path.insert(0, os.path.dirname(MISSAO))

from entrada import ler_texto
from securedocs_assinatura import certificado, ecdsa
from textos import CONTRATO_FALSO


def mostrar(nome_falso):
    ac = ecdsa.gerar_chaves()
    print("a Autoridade Certificadora (AC) tem um par de chaves; a pública dela já vem")
    print("instalada em todo computador (como as ACs do navegador).\n")

    techsecure = ecdsa.gerar_chaves()
    cert = certificado.emitir("TechSecure", techsecure.publica, "AC SecureDocs", ac)
    print("1) a TechSecure prova quem é para a AC, e a AC assina (nome + chave pública):")
    print("   dono: %s | emissor: %s | validade: %s" % (cert["dono"], cert["emissor"], cert["validade"]))
    print("   chave: %X..." % (techsecure.Q[0] >> 192))
    print("   assinatura da AC: (%X..., %X...)" % (cert["assinatura"][0] >> 224, cert["assinatura"][1] >> 224))
    print("   certificado confere com a chave da AC? %s\n" % certificado.verificar(cert, ac.publica))

    eva = ecdsa.gerar_chaves()
    print("2) Eva faz um certificado dizendo que a chave DELA é da '%s'" % nome_falso)
    falso = certificado.emitir(nome_falso, eva.publica, "AC SecureDocs", eva)
    print("   ela não tem a chave da AC, então assina com a dela")
    print("   certificado confere com a chave da AC? %s" % certificado.verificar(falso, ac.publica))

    print("\n3) Eva pega o certificado verdadeiro e troca só a chave pela dela")
    trocado = dict(cert)
    trocado["publica"] = eva.publica
    print("   certificado confere com a chave da AC? %s" % certificado.verificar(trocado, ac.publica))

    print("\n4) o cliente recebe o contrato: confere o certificado (AC) e depois a assinatura")
    dados = CONTRATO_FALSO.encode("utf-8")
    assinatura_eva = ecdsa.assinar(dados, eva)
    print("   contrato da Eva com a chave do certificado verdadeiro: %s"
          % ecdsa.verificar(dados, assinatura_eva, cert["publica"]))

    print("\nconclusão: a assinatura prova que foi o dono da chave; o certificado prova de")
    print("quem é a chave. Isso é a ICP (no Brasil, ICP-Brasil e o certificado e-CPF/e-CNPJ).")
    print("Mas e se a AC for invadida, ou a chave da TechSecure vazar? Revogação, cadeia")
    print("de certificados... próximo problema.")


def main():
    print("=== 9. NOVA DESCOBERTA: A CHAVE PÚBLICA É MESMO DA TECHSECURE? ===\n")
    print("(slide 'Protocolo de Distribuição de Chaves': X assina a chave pública de B)\n")
    mostrar("TechSecure")


def interativo():
    nome = ler_texto("Eva vai se passar por quem? ", "TechSecure")
    print()
    mostrar(nome)


if __name__ == "__main__":
    main()
