import os
import sys
MISSAO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, MISSAO)
sys.path.insert(0, os.path.dirname(MISSAO))

from securedocs_assinatura import comparacao, esquemas


def tabela():
    print("%-10s %-5s %-25s %-21s %-8s %s" % ("", "ano", "problema difícil", "chave", "hash", "assinatura"))
    for nome, ano, problema, chave, h, tamanho in comparacao.CARACTERISTICAS:
        print("%-10s %-5s %-25s %-21s %-8s %s" % (nome, ano, problema, chave, h, tamanho))


def medicoes():
    print("\nmedindo a NOSSA implementação (Python puro):")
    print("%-18s %10s %10s %10s %8s" % ("", "gerar", "assinar", "verificar", "tamanho"))
    for nome in esquemas.ESQUEMAS:
        t_chave, t_assinar, t_verificar, tamanho, ok = comparacao.medir(nome)
        print("%-18s %8.0f ms %8.1f ms %8.1f ms %6d B %s"
              % (nome, 1000 * t_chave, 1000 * t_assinar, 1000 * t_verificar, tamanho,
                 "" if ok else "ERRO"))
    print("(o DSA não precisa gerar p e q: usa os parâmetros já prontos)")


def main():
    print("=== 7. COMPARAÇÃO E A ESCOLHA PARA O SECUREDOCS ===\n")
    tabela()
    medicoes()

    print("\nESCOLHA: RSA com chave de 2048 bits e SHA-256")
    print("  - é o esquema do slide de assinatura (hash -> RSA com a chave privada);")
    print("  - a mesma chave RSA serve para o envelope digital da Missão 3 (assinatura secreta);")
    print("  - verificar é muito rápido (e = 65537) e o cliente verifica bem mais do que assina;")
    print("  - não depende de um k secreto por mensagem (o ataque 2 mostra o risco do DSA);")
    print("  - usa SHA-256: colisão em 2^128, contra 2^80 do SHA-1 que o DSA do slide usa.")
    print("  DSA: assinatura menor (40 bytes), mas k repetido entrega a chave e o hash é o SHA-1.")

    print("\nameaça futura: fatorar fica mais rápido com o tempo (computadores melhores).")
    print("  2048 bits = ~618 dígitos hoje; dá para subir para 4096 bits (~1234 dígitos)")
    print("  só mudando o tamanho na geração das chaves.")

    print("\nRELACIONANDO OS CONCEITOS")
    print("  hash ........................ resumo do documento -> integridade")
    print("  criptografia assimétrica .... só o dono tem a chave privada")
    print("  assinatura = hash + chave privada")
    print("    verificar com a pública OK -> o documento não mudou     (integridade)")
    print("                               -> foi o dono da chave       (autenticidade)")
    print("                               -> ele não pode negar depois (não repúdio)")


def interativo():
    medicoes()


if __name__ == "__main__":
    main()
