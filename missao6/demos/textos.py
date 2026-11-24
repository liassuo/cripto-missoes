CONTRATO = ("Pelo presente contrato a TechSecure se compromete a transferir todos os documentos "
            "confidenciais do cliente para o servidor central da empresa, mantendo sigilo absoluto "
            "sobre relatórios financeiros, contratos e informações estratégicas. O valor mensal "
            "do serviço é de R$ 12.000,00 e o prazo de vigência é de doze meses a contar da data "
            "de assinatura.")

# o que o invasor gostaria que o cliente assinasse
CONTRATO_FALSO = CONTRATO.replace("R$ 12.000,00", "R$ 120.000,00")
