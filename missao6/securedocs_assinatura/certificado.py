# Nova descoberta: a assinatura prova que quem assinou tem a chave privada
# que corresponde àquela chave pública. Mas como saber que a chave pública é
# mesmo da TechSecure e não de um invasor que se passou por ela?
#
# Ideia do slide "Protocolo de Distribuição de Chaves": uma terceira parte
# confiável X (autoridade certificadora) ASSINA a chave pública de B junto com
# o nome dele. Esse pacote (nome + chave + assinatura de X) é o certificado.
# É uma versão bem simplificada do X.509 usado no HTTPS.

from . import ecdsa


def conteudo(dono, publica, emissor, validade):
    texto = "dono: %s\nchave: %s\nemissor: %s\nvalidade: %s\n" % (
        dono, ecdsa.ponto_para_bytes(publica.Q).hex().upper(), emissor, validade)
    return texto.encode("utf-8")


def emitir(dono, publica, emissor, privada_emissor, validade="2027-12-31"):
    assinatura = ecdsa.assinar(conteudo(dono, publica, emissor, validade), privada_emissor)
    return {"dono": dono, "publica": publica, "emissor": emissor,
            "validade": validade, "assinatura": assinatura}


def verificar(certificado, publica_emissor):
    dados = conteudo(certificado["dono"], certificado["publica"], certificado["emissor"],
                     certificado["validade"])
    return ecdsa.verificar(dados, certificado["assinatura"], publica_emissor)
