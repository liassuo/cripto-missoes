import os


def area_de_trabalho():
    # pergunta ao Windows onde fica a Área de Trabalho (pode estar dentro do OneDrive)
    try:
        import ctypes
        caminho = ctypes.create_unicode_buffer(260)
        ctypes.windll.shell32.SHGetFolderPathW(None, 0x10, None, 0, caminho)   # 0x10 = Desktop
        if os.path.isdir(caminho.value):
            return caminho.value
    except (AttributeError, OSError):
        pass
    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    return desktop if os.path.isdir(desktop) else os.path.dirname(os.path.abspath(__file__))


# os arquivos do experimento ficam na Área de Trabalho para abrir na apresentação
PASTA = os.path.join(area_de_trabalho(), "SecureDocs_assinatura")


def limpar_caminho(caminho):
    # ao arrastar o arquivo para o terminal, o Windows pode colocar aspas ou "& '...'"
    if caminho.startswith("& "):
        caminho = caminho[2:]
    return caminho.strip().strip('"').strip("'")
