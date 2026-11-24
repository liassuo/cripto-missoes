import os
import sys
MISSAO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, MISSAO)
sys.path.insert(0, os.path.dirname(MISSAO))

from securedocs_assinatura import comparacao, esquemas


def tabela():
    print("%-20s %-5s %-24s %-17s %s" % ("", "ano", "problema difícil", "chave (128 bits)", "assinatura"))
    for nome, ano, problema, chave, tamanho in comparacao.CARACTERISTICAS:
        print("%-20s %-5d %-24s %-17s %s" % (nome, ano, problema, chave, tamanho))


def medicoes():
    print("\nmedindo a NOSSA implementação (Python puro, chaves de 2048 bits / P-256):")
    print("%-26s %10s %10s %10s %8s" % ("", "gerar", "assinar", "verificar", "tamanho"))
    for nome in esquemas.ESQUEMAS:
        if nome == "RSA-livro-SHA256":
            continue
        t_chave, t_assinar, t_verificar, tamanho, ok = comparacao.medir(nome)
        print("%-26s %8.0f ms %8.1f ms %8.1f ms %6d B %s"
              % (nome, 1000 * t_chave, 1000 * t_assinar, 1000 * t_verificar, tamanho,
                 "" if ok else "ERRO"))
    print("(o DSA não precisa gerar p e q: usa os parâmetros já prontos)")


def main():
    print("=== 8. COMPARAÇÃO E A ESCOLHA PARA O SECUREDOCS ===\n")
    tabela()
    medicoes()

    print("\nESCOLHA: ECDSA P-256 com SHA-256 e k pela RFC 6979")
    print("  - assinatura de 64 bytes e chave de 256 bits (RSA precisaria de 3072 bits);")
    print("  - assinar é rápido e já é usado nos certificados do HTTPS (TLS);")
    print("  - k determinístico: não depende do gerador aleatório (evita o ataque do PS3).")
    print("  RSA-PSS fica como alternativa (verificação mais rápida, mais compatível).")
    print("  DSA: retirado no FIPS 186-5 (2023) para assinaturas novas.")

    print("\nameaça futura: computador quântico (algoritmo de Shor) quebra RSA, DSA e ECDSA.")
    print("  o NIST já padronizou substitutos em 2024: ML-DSA (FIPS 204) e SLH-DSA (FIPS 205).")
    print("  o hash não cai (Grover só reduz SHA-256 para ~128 bits).")

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
