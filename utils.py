# utils.py
import sys
import os


def resource_path(relative_path):
    """
    Retorna o caminho absoluto para recursos (imagens, ícones, etc).
    Suporta Nuitka, PyInstaller e execução direta pelo Python.
    """
    if '__compiled__' in globals():
        # Estamos rodando compilados pelo Nuitka
        base_path = os.path.dirname(sys.executable)
    elif hasattr(sys, '_MEIPASS'):
        # PyInstaller cria uma pasta temporária e armazena o caminho em
        # _MEIPASS
        base_path = getattr(sys, '_MEIPASS')
    else:
        # Execução normal pelo script Python
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)
