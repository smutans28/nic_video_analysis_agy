#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# ====================================================================
# EXTRATOR DE HASHES E METADADOS FORENSES
# Copyright (c) 2026 Eduardo Silva. Todos os direitos reservados.
# ====================================================================
# AVISO DE LICENÇA E TERMOS DE USO
#
# Este software e seu código fonte são propriedade intelectual exclusiva
# do autor. O uso deste software é concedido "no estado em que se encontra"
# ("as is"), sem qualquer tipo de garantia, expressa ou implícita.
#
# 1. USO PERMITIDO:
# É concedido o direito de uso gratuito, não-exclusivo e intransferível
# deste software EXCLUSIVAMENTE para:
# a) Uso acadêmico, pesquisa e estudo;
# b) Uso institucional por órgãos de segurança pública, forças policiais,
#    órgãos do poder judiciário e instituições governamentais;
# c) Uso em investigações forenses e elaboração de laudos periciais
#    (incluindo o uso por peritos criminais e assistentes técnicos
#    particulares no exercício de suas funções processuais).
#
# 2. USO PROIBIDO (USO COMERCIAL):
# É terminantemente proibido, sem a autorização prévia e por escrito
# do autor:
# a) Integrar este código ou suas partes em softwares comerciais,
#    produtos pagos ou plataformas como serviço (SaaS);
# b) Vender, revender, alugar ou licenciar este software;
# c) Distribuir versões modificadas deste software ao público sem a
#    manutenção destes avisos de direitos autorais originais.
#
# 3. ISENÇÃO DE RESPONSABILIDADE:
# O autor não se responsabiliza por quaisquer danos diretos, indiretos,
# incidentais ou lucros cessantes resultantes do uso ou da incapacidade
# de uso deste software. A validação da integridade da evidência digital
# é de inteira responsabilidade do usuário final.
# ====================================================================

"""
Extrator de Hashes e Metadados (ERS-IC/SP-NIC)
Versão: 4.2.1
Desenvolvedor: Eduardo Rodrigues da Silva
Contato: rodrigues.ers@policiacientifica.sp.gov.br

Descrição:
    Ferramenta pericial para extração de hashes criptográficos (CRC32, MD5, SHA-1, SHA-256, SHA-384, SHA-512)
    e metadados avançados de uma vasta gama de arquivos (imagens, vídeos, áudios, documentos, executáveis,
    e-mails, atalhos, etc.). Inclui detecção de fluxos de dados ocultos (ADS NTFS), cálculo de entropia de Shannon,
    aquisição forense bit-a-bit de unidades (RAW) com geração de imagem .dd e log de auditoria.

    O programa é desenvolvido para auxiliar a perícia digital, garantindo a integridade das evidências por meio
    de técnicas de leitura somente-leitura, bloqueio de arquivos em uso e detecção de artefatos de nuvem.

    Código aberto para auditoria. Distribuição livre para fins forenses, conforme os termos de licença acima.
"""

import sys
import ctypes

# --- INFORMAÇÕES DO PROGRAMA ---
NOME_APP = "Extrator de Hashes e Metadados (ERS-IC/SP-NIC)"
VERSAO_APP = "4.2.1"
DESENVOLVEDOR = "Eduardo Rodrigues da Silva"
EMAIL_CONTATO = "rodrigues.ers@policiacientifica.sp.gov.br"
USUARIO = "eduardo-rsilva"
REPOSITORIO = "extrator_hashes_metadados"
LINK_GITHUB = f"https://github.com/{USUARIO}/{REPOSITORIO}"
# -------------------------------

DEBUG_MESSAGES = False # USADO APENAS NA FASE DE DESENVOLVIMENTO

INTERVALO_ATUALIZACAO_BARRA_PREVISAO_PROGRESSO_TOTAL = 2 # em segundos

# --- VALIDAÇÃO DE ARQUITETURA ---
if sys.maxsize <= 2**32:
    # Cria uma caixa de mensagem de erro nativa do Windows antes do PySide6 carregar
    import ctypes
    mensagem = (
        "ERRO FATAL: ARQUITETURA INCOMPATÍVEL\n\n"
        f"O {NOME_APP} requer um sistema e interpretador de 64 bits (x64).\n"
        "A execução atual foi detectada como 32 bits (x86).\n\n"
        "Por favor, execute o programa em um ambiente Windows 64-bits."
    )
    # 0x10 = MB_ICONHAND (Ícone de Erro / X Vermelho)
    ctypes.windll.user32.MessageBoxW(0, mensagem, "Erro de Arquitetura", 0x10)
    sys.exit(1)

# ==============================================================================
# IMPORTAÇÃO DAS DEMAIS BIBLIOTECAS (Só ocorre se passou pelo teste de 64-bits acima)
# ==============================================================================

import hashlib
import shutil
import math # Para o cálculo de logaritmo da Entropia
from collections import Counter
import datetime
import json
import msvcrt
from ctypes import wintypes
import os
import re
import subprocess
import traceback
from cryptography.fernet import Fernet
import zlib
import zipfile
import xml.etree.ElementTree as ET
from email import policy
from email.parser import BytesParser
import datetime as dt # Importado como dt para não conflitar com o datetime existente
from pathlib import Path
from PySide6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
                               QPushButton, QCheckBox, QTextEdit, QFileDialog,
                               QProgressBar, QLabel, QMessageBox, QToolTip, QDialog, QComboBox,
                               QTabWidget, QFrame, QGroupBox)
from PySide6.QtGui import QIcon
from PySide6.QtCore import QTimer, QEvent, Signal, Qt

# imports para hash bit a bit
import argparse
import tempfile
import uuid
import time

try:
    from hash_fonte import HASH_DO_CODIGO_FONTE
except ImportError:
    # Caso esteja rodando sem compilar (no PyCharm), o arquivo ainda pode não existir
    HASH_DO_CODIGO_FONTE = "Hash indisponível (Execução em modo IDE/Desenvolvimento)"

# Texto da licença (para ser carregado na GUI)
TEXTO_LICENCA = """AVISO DE LICENÇA E TERMOS DE USO

Este software e seu código fonte são propriedade intelectual exclusiva do autor. O uso deste software é concedido "no estado em que se encontra" ("as is"), sem qualquer tipo de garantia, expressa ou implícita.

1. USO PERMITIDO:
É concedido o direito de uso gratuito, não-exclusivo e intransferível deste software EXCLUSIVAMENTE para:
a) Uso acadêmico, pesquisa e estudo;
b) Uso institucional por órgãos de segurança pública, forças policiais, órgãos do poder judiciário e instituições governamentais;
c) Uso em investigações forenses e elaboração de laudos periciais (incluindo o uso por peritos criminais e assistentes técnicos particulares no exercício de suas funções processuais).

2. USO PROIBIDO (USO COMERCIAL):
É terminantemente proibido, sem a autorização prévia e por escrito do autor:
a) Integrar este código ou suas partes em softwares comerciais, produtos pagos ou plataformas como serviço (SaaS);
b) Vender, revender, alugar ou licenciar este software;
c) Distribuir versões modificadas deste software ao público sem a manutenção destes avisos de direitos autorais originais.

3. ISENÇÃO DE RESPONSABILIDADE:
O autor não se responsabiliza por quaisquer danos diretos, indiretos, incidentais ou lucros cessantes resultantes do uso ou da incapacidade de uso deste software em ambientes de produção ou perícia. A validação da integridade da evidência digital é de inteira responsabilidade do usuário final.

Ao utilizar este software, você concorda com estes termos.
"""

# --- TENTATIVA DE IMPORTAR BIBLIOTECAS DE METADADOS ---
try:
    from PIL import Image
    from PIL.ExifTags import GPSTAGS, TAGS

    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    import cv2

    HAS_CV2 = True
except ImportError:
    HAS_CV2 = False

try:
    from pypdf import PdfReader

    HAS_PYPDF = True
except ImportError:
    HAS_PYPDF = False

try:
    import olefile
    HAS_OLEFILE = True
except ImportError:
    HAS_OLEFILE = False

try:
    import LnkParse3
    HAS_LNKPARSE = True
except ImportError:
    HAS_LNKPARSE = False

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    import extract_msg
    HAS_EXTRACT_MSG = True
except ImportError:
    HAS_EXTRACT_MSG = False

try:
    from tinytag import TinyTag
    HAS_TINYTAG = True
except ImportError:
    HAS_TINYTAG = False

# ------------------------------------------------------

def get_base_dir() -> Path:
    nuitka_onefile_parent = os.environ.get("NUITKA_ONEFILE_PARENT")
    if nuitka_onefile_parent:
        return Path(nuitka_onefile_parent).resolve().parent

    if is_running_compiled():
        return Path(obter_caminho_exe()).resolve().parent

    return Path(__file__).resolve().parent


def obter_caminho_exe() -> str:
    """Obtém o caminho absoluto do .exe via API do Windows, imune a bugs do Nuitka."""
    if os.name == 'nt':
        buf = ctypes.create_unicode_buffer(32768)
        ctypes.windll.kernel32.GetModuleFileNameW(None, buf, 32768)
        return buf.value
    return os.path.abspath(sys.executable)


def is_running_compiled() -> bool:
    """Verifica com precisão se está compilado (PyInstaller ou Nuitka)."""
    if getattr(sys, "frozen", False):
        return True

    # Verifica nos globals ou nos built-ins se o Nuitka injetou a variável
    # (Assim o seu editor de código não apita variável não declarada)
    if "__compiled__" in globals() or hasattr(__builtins__, "__compiled__"):
        return True

    return False



BASE_DIR = get_base_dir()
ICON_PATH = str(BASE_DIR / "app.ico")
MENSAGEM_INICIAL = "Arraste e solte arquivos ou pastas em qualquer lugar desta janela."

CONFIG_FILE = BASE_DIR / "config.dat"
KEY = b'cN8vZ8jK8vJk9sLk2jHfGdSdFgJkLmQnRtYwXzPqLmN='
cipher = Fernet(KEY)

# --- LISTAS CENTRALIZADAS DE FORMATOS SUPORTADOS ---
FORMATOS_IMAGEM = [
    '3fr', 'aae', 'ai', 'ait', 'arq', 'arw', 'avif', 'bmp', 'dib', 'bpg', 'btf',
    'c2pa', 'jumbf', 'cos', 'cr2', 'cr3', 'crw', 'ciff', 'cs1', 'dcm', 'dc3',
    'dic', 'dicm', 'dcp', 'dcr', 'djvu', 'djv', 'dng', 'dpx', 'dr4', 'eip',
    'eps', 'epsf', 'ps', 'erf', 'exif', 'exr', 'exv', 'fff', 'fits', 'fla',
    'flif', 'fpf', 'fpx', 'gif', 'gpr', 'hdp', 'wdp', 'jxr', 'hdr', 'heic',
    'heif', 'hif', 'icc', 'icm', 'ico', 'cur', 'iiq', 'ind', 'indd', 'indt',
    'insp', 'j2k', 'jpc', 'j2c', 'jng', 'jp2', 'jpf', 'jpm', 'jpx', 'jpeg',
    'jpg', 'jpe', 'jxl', 'k25', 'kdc', 'key', 'la', 'lrv', 'mef', 'mie',
    'miff', 'mif', 'mng', 'mos', 'mrw', 'neq', 'nef', 'nrw', 'orf', 'ori',
    'pac', 'pcx', 'pef', 'pgm', 'pict', 'pct', 'pic', 'png', 'pnm', 'ppm',
    'psb', 'psd', 'qtk', 'raf', 'raw', 'riq', 'rw2', 'rwl', 'rwz', 'sr2',
    'srf', 'srw', 'svg', 'tiff', 'tif', 'vrd', 'webp', 'x3f', 'xcf', 'xmp'
]

FORMATOS_VIDEO = [
    '3g2', '3gp2', '3gp', '3gpp', 'asf', 'avi', 'crm', 'divx', 'dv', 'dvb',
    'dvr-ms', 'f4p', 'f4v', 'flv', 'glv', 'insv', 'm2t', 'm2ts', 'mts', 'm4v',
    'mkv', 'mov', 'qt', 'mp4', 'mp4v', 'mpeg', 'mpg', 'mpe', 'm2v', 'mxf',
    'ogv', 'rm', 'rv', 'rmvb', 'seq', 'swf', 'ts', 'vob', 'webm', 'wmv', 'xavc'
]

FORMATOS_AUDIO = [
    'aa', 'aax', 'aac', 'aiff', 'aif', 'aifc', 'ape', 'dsf', 'dss', 'ds2',
    'f4a', 'f4b', 'flac', 'm4a', 'm4b', 'm4p', 'mac', 'mid', 'midi', 'mka',
    'mp3', 'mpca', 'ogg', 'oga', 'opus', 'pac', 'ra', 'spx', 'tak', 'wav',
    'wma', 'wv', 'wvc'
]

# --- Subcategorias de Documentos e Outros ---
FORMATOS_PDF = ['pdf']
FORMATOS_OFFICE_XML = ['docx', 'xlsx', 'pptx']
FORMATOS_OFFICE_LEGADO = ['doc', 'xls', 'ppt']
FORMATOS_ATALHOS = ['lnk']
FORMATOS_EXECUTAVEIS = ['exe', 'dll', 'sys']
FORMATOS_EMAIL_EML = ['eml']
FORMATOS_EMAIL_MSG = ['msg']
FORMATOS_COMPACTADOS = ['zip', 'rar', '7z', 'tar', 'gz']
FORMATOS_TORRENT = ['torrent']
FORMATOS_RTF = ['rtf']

# Soma de todas as subcategorias para exibir na Interface do Usuário
FORMATOS_GERAIS = (FORMATOS_PDF + FORMATOS_OFFICE_XML + FORMATOS_OFFICE_LEGADO +
                   FORMATOS_ATALHOS + FORMATOS_EXECUTAVEIS + FORMATOS_EMAIL_EML +
                   FORMATOS_EMAIL_MSG + FORMATOS_COMPACTADOS + FORMATOS_TORRENT + FORMATOS_RTF)
# ---------------------------------------------------

###################### BLOCO PARA GERAÇÃO DE HASH BIT A BIT DE UNIDADES (INÍCIO) ##########################
kernel32 = ctypes.windll.kernel32
shell32 = ctypes.windll.shell32

INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080

DRIVE_UNKNOWN = 0
DRIVE_NO_ROOT_DIR = 1
DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3
DRIVE_REMOTE = 4
DRIVE_CDROM = 5
DRIVE_RAMDISK = 6

def _ctl_code(device_type, function, method, access):
    return (device_type << 16) | (access << 14) | (function << 2) | method

FILE_DEVICE_DISK = 0x00000007
FILE_DEVICE_VOLUME = 0x00000056
METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0

IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C
IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = _ctl_code(FILE_DEVICE_VOLUME, 0, METHOD_BUFFERED, FILE_ANY_ACCESS)

class GET_LENGTH_INFORMATION(ctypes.Structure):
    _fields_ = [("Length", ctypes.c_ulonglong)]  # c_ulonglong (64 bits) em vez de LARGE_INTEGER evita bugs de alinhamento no ctypes

class DISK_EXTENT(ctypes.Structure):
    _fields_ = [
        ("DiskNumber", wintypes.DWORD),
        ("StartingOffset", ctypes.c_ulonglong),
        ("ExtentLength", ctypes.c_ulonglong),
    ]

class VOLUME_DISK_EXTENTS(ctypes.Structure):
    _fields_ = [
        ("NumberOfDiskExtents", wintypes.DWORD),
        ("Extents", DISK_EXTENT * 1),  # placeholder; vamos ler buffer bruto
    ]

# Use ctypes.WinDLL com use_last_error=True para capturar falhas reais
kernel32_le = ctypes.WinDLL("kernel32", use_last_error=True)

CreateFileW = kernel32_le.CreateFileW
CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
    wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE
]
CreateFileW.restype = wintypes.HANDLE

ReadFile = kernel32_le.ReadFile
ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
ReadFile.restype = wintypes.BOOL

CloseHandle = kernel32_le.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

DeviceIoControl = kernel32_le.DeviceIoControl
DeviceIoControl.argtypes = [
    wintypes.HANDLE, wintypes.DWORD,
    wintypes.LPVOID, wintypes.DWORD,
    wintypes.LPVOID, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID
]
DeviceIoControl.restype = wintypes.BOOL

GetDriveTypeW = kernel32_le.GetDriveTypeW
GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
GetDriveTypeW.restype = wintypes.UINT

def is_elevated() -> bool:
    try:
        # Forma muito mais simples e confiável para .exe
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def traduzir_erro_windows(err_code: int, operacao: str) -> str:
    """Traduz códigos de erro obscuros do Windows para termos forenses claros."""
    erros = {
        1: "Função Inválida: O dispositivo ou sistema de arquivos não suporta esta operação de baixo nível (Pode ser uma unidade de rede ou RAM Disk).",
        2: "Arquivo/Caminho Não Encontrado: O dispositivo físico não foi localizado. Ele pode ter sido ejetado ou a numeração do PhysicalDrive mudou.",
        3: "Caminho Não Encontrado: O volume ou dispositivo não existe mais no sistema.",
        5: "Acesso Negado: O Windows bloqueou a leitura de baixo nível. Causas comuns: Falta de elevação (UAC), disco encriptado (BitLocker) ou bloqueio ativo do Antivírus/EDR.",
        21: "Dispositivo Não Pronto: A unidade não respondeu. Comum em leitores de cartão vazios, unidades virtuais (VHDs) não montadas ou falha lógica.",
        23: "Erro de Dados (CRC): [FALHA DE HARDWARE] Ocorreu um Erro de Verificação Cíclica de Redundância. O disco possui setores fisicamente danificados ou corrupção severa.",
        27: "Setor Não Encontrado: [FALHA DE HARDWARE] A agulha ou controladora não conseguiu localizar o setor físico no disco.",
        32: "Violação de Compartilhamento: Outro processo (ou o próprio Windows) está com acesso exclusivo bloqueando a unidade.",
        433: "Dispositivo Inexistente (NO_SUCH_DEVICE): O hardware foi removido ou desconectado abruptamente (cabo solto/ejetado) no meio da leitura de baixo nível.",
        1117: "Erro de Dispositivo de E/S (I/O): [FALHA CRÍTICA] O dispositivo de armazenamento falhou fisicamente ou a controladora travou durante a transferência de dados.",
        1167: "Dispositivo Não Conectado: O pendrive/disco foi fisicamente removido no meio da operação de leitura."
    }

    descricao = erros.get(err_code, f"Erro desconhecido documentado pela Microsoft.")
    return f"Falha na operação '{operacao}' (Código OS: {err_code}) -> {descricao}"

def open_device_readonly(device_path: str) -> int:
    h = CreateFileW(
        device_path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        0,
        None
    )
    if h == INVALID_HANDLE_VALUE:
        err = ctypes.get_last_error()
        msg = traduzir_erro_windows(err, "CreateFileW (Abrir Unidade)")
        raise RuntimeError(f"Erro ao tentar acessar: {device_path}\n{msg}")
    return h

def device_get_length_bytes(handle: int) -> int:
    out = GET_LENGTH_INFORMATION()
    br = wintypes.DWORD(0)
    ok = DeviceIoControl(handle, IOCTL_DISK_GET_LENGTH_INFO, None, 0, ctypes.byref(out), ctypes.sizeof(out), ctypes.byref(br), None)
    if not ok:
        err = ctypes.get_last_error()
        msg = traduzir_erro_windows(err, "DeviceIoControl (Medir Tamanho)")
        raise RuntimeError(msg)
    return int(out.Length)

def volume_to_physical_drives(volume_device: str) -> list[int]:
    h = open_device_readonly(volume_device)
    try:
        buf_size = 4096
        buf = ctypes.create_string_buffer(buf_size)
        br = wintypes.DWORD(0)
        ok = DeviceIoControl(h, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, None, 0, buf, buf_size, ctypes.byref(br), None)
        if not ok:
            err = ctypes.get_last_error()
            raise OSError(err, f"DeviceIoControl(IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS) falhou. Erro OS: {err}")

        num = int.from_bytes(buf.raw[0:4], "little", signed=False)
        drives = []
        offset = 8 # Pula o DWORD e o padding para chegar no array de extents (alinhamento de 64 bits)
        extent_size = ctypes.sizeof(DISK_EXTENT)
        for _ in range(num):
            ext = DISK_EXTENT.from_buffer_copy(buf.raw[offset:offset+extent_size])
            drives.append(int(ext.DiskNumber))
            offset += extent_size
        return sorted(set(drives))
    finally:
        CloseHandle(h)

def normalize_drive_root(drive_letter: str) -> str:
    d = drive_letter.strip().replace("/", "\\")
    if len(d) >= 2 and d[1] == ":":
        return d[0].upper() + ":\\"
    raise ValueError("Drive inválido (use tipo E: ou E:\\)")

def drive_root_to_volume_device(drive_root: str) -> str:
    # "E:\\" -> "\\\\.\\E:"
    return r"\\.\{}".format(drive_root[0].upper() + ":")

def get_drive_type(drive_root: str) -> int:
    return int(GetDriveTypeW(wintypes.LPCWSTR(drive_root)))

def parse_algos_csv(csv_text: str) -> list[str]:
    items = []
    for part in (csv_text or "").split(","):
        s = part.strip().upper()
        if s:
            items.append(s)
    return items

def init_hash_objects(algos: list[str]):
    h = {}
    if "CRC32" in algos:
        h["CRC32"] = 0
    if "MD5" in algos:
        h["MD5"] = hashlib.md5()
    if "SHA-1" in algos:
        h["SHA-1"] = hashlib.sha1()
    if "SHA-256" in algos:
        h["SHA-256"] = hashlib.sha256()
    if "SHA-384" in algos:
        h["SHA-384"] = hashlib.sha384()
    if "SHA-512" in algos:
        h["SHA-512"] = hashlib.sha512()
    return h

def finalize_hashes(hash_objs: dict):
    out = {}
    for k, v in hash_objs.items():
        if k == "CRC32":
            out["CRC32"] = f"{(v & 0xFFFFFFFF):08X}"
        else:
            out[k] = v.hexdigest().upper()
    return out

def raw_hash_device(
        device_path: str,
        algos: list[str],
        chunk_size: int,
        progress_json_path: str | None,
        cancel_flag_path: str | None,
        image_out_path: str | None = None
) -> dict:
    if not algos:
        raise ValueError("Nenhum algoritmo selecionado")

    h = open_device_readonly(device_path)

    # Prepara o arquivo de imagem de destino
    f_img = None
    if image_out_path:
        os.makedirs(os.path.dirname(os.path.abspath(image_out_path)), exist_ok=True)
        f_img = open(image_out_path, "wb")

    # Prepara variáveis de resultado fora do try
    total = 0
    bytes_read_total = 0
    hash_objs = {}

    # Prepara variáveis de resultado fora do try
    total = 0
    bytes_read_total = 0
    hash_objs = {}

    try:
        total = device_get_length_bytes(h)
        hash_objs = init_hash_objects(algos)
        buf = ctypes.create_string_buffer(chunk_size)

        last_progress_write = 0.0
        last_cancel_check = 0.0  # <--- variável para controle de tempo

        while bytes_read_total < total:
            now = time.time()

            # --- VERIFICAÇÃO DE CANCELAMENTO OTIMIZADA ---
            # Checa o disco no máximo 2 vezes por segundo (a cada 0.5s),
            # em vez de checar a cada chunk de 1MB lido
            if cancel_flag_path and (now - last_cancel_check) >= 0.5:
                last_cancel_check = now
                if os.path.exists(cancel_flag_path):
                    return {
                        "bytes_total": total,
                        "bytes_read": bytes_read_total,
                        "hashes": {},
                        "cancelado": True
                    }

            to_read = chunk_size

            remaining = total - bytes_read_total
            if remaining < to_read:
                to_read = int(remaining)

            br = wintypes.DWORD(0)
            ok = ReadFile(h, buf, to_read, ctypes.byref(br), None)

            if not ok:
                err = ctypes.get_last_error()
                msg = traduzir_erro_windows(err, f"ReadFile (Lendo byte {bytes_read_total})")
                raise RuntimeError(msg)

            n = int(br.value)
            if n <= 0:
                break

            data = buf.raw[:n]

            # --- SALVA O BLOCO NA IMAGEM FORENSE ---
            if f_img:
                f_img.write(data)
            # ---------------------------------------------

            for algo, obj in hash_objs.items():
                if algo == "CRC32":
                    hash_objs["CRC32"] = zlib.crc32(data, hash_objs["CRC32"])
                else:
                    obj.update(data)

            bytes_read_total += n

            now = time.time()
            if progress_json_path and (now - last_progress_write) >= INTERVALO_ATUALIZACAO_BARRA_PREVISAO_PROGRESSO_TOTAL:
                pct = int((bytes_read_total / total) * 100) if total else 0
                tmp = {
                    "device": device_path,
                    "bytes_total": total,
                    "bytes_read": bytes_read_total,
                    "percent": pct,
                    "ts": now,
                }
                try:
                    os.makedirs(os.path.dirname(progress_json_path), exist_ok=True)
                    with open(progress_json_path, "w", encoding="utf-8") as f:
                        json.dump(tmp, f, ensure_ascii=False)
                except Exception:
                    pass
                last_progress_write = now

        # Retorno normal (sucesso absoluto)
        return {
            "device": device_path,
            "bytes_total": total,
            "bytes_read": bytes_read_total,
            "hashes": finalize_hashes(hash_objs),
            "cancelado": False
        }

    finally:
        # O finally sempre rodará, fechando a alça do disco, não importa como saiu.
        CloseHandle(h)
        if f_img:
            f_img.close()  # Garante que o arquivo da imagem seja fechado.

def _raw_lock_key_from_device(device_path: str) -> str:
    """Descobre os discos físicos reais associados ao caminho selecionado."""
    s = (device_path or "").upper().strip()

    # 1. Se já for um disco físico (ex: \\.\PhysicalDrive0)
    if s.startswith("\\\\.\\PHYSICALDRIVE"):
        n = "".join(ch for ch in s.split("PHYSICALDRIVE", 1)[1] if ch.isdigit())
        if n:
            return [f"PD_{n}"]

    # 2. Se for um volume lógico (ex: \\.\C:)
    elif s.startswith("\\\\.\\") and len(s) >= 6 and s[5] == ":":
        try:
            # Usa sua função nativa para descobrir de qual disco físico esse volume faz parte
            drives = volume_to_physical_drives(device_path)
            if drives:
                # Se o volume for um RAID, pode estar em mais de um disco, retorna todos
                return [f"PD_{d}" for d in drives]
        except Exception:
            pass

    # 3. Fallback (unidades de rede mapeadas, pendrives não identificáveis, etc)
    safe = "".join(ch if ch.isalnum() else "_" for ch in s)
    return [f"DEV_{safe[:40]}"]


def try_acquire_raw_device_lock(device_path: str):
    """Tenta travar todos os discos físicos base associados à unidade requerida."""
    keys = _raw_lock_key_from_device(device_path)
    acquired_files = []

    for key in keys:
        lock_path = os.path.join(tempfile.gettempdir(), f"ERS_IC_NIC_RAW_LOCK_{key}.lock")
        try:
            f = open(lock_path, "a+b")
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)  # Falha imediato se ocupado
            acquired_files.append(f)
        except OSError:
            # Se falhou ao travar este disco, SOLTA todos os outros que já tinha conseguido antes de negar
            release_raw_device_lock(acquired_files)
            return None, lock_path

    return acquired_files, "locked"


def release_raw_device_lock(files_list):
    """Libera todos os locks adquiridos."""
    if not files_list:
        return

    # Garante que funciona caso passe um único arquivo ou uma lista
    if not isinstance(files_list, list):
        files_list = [files_list]

    for f in files_list:
        try:
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        except Exception:
            pass
        try:
            f.close()
        except Exception:
            pass


def _build_runas_command_args(params_list: list[str]) -> str:
    """
    Constrói a string de argumentos para o ShellExecuteW no Windows.
    Garante o quoting correto de caminhos com espaços e previne a quebra
    do comando por barras invertidas no final de diretórios.
    """
    args = []

    for item in params_list:
        # Garante a conversão caso a lista contenha objetos pathlib.Path
        param = str(item)

        # Parâmetros vazios devem ser passados explicitamente como strings vazias
        if not param:
            args.append('""')
            continue

        # Se houver espaços, tabulações ou aspas, precisamos de tratamento especial
        if ' ' in param or '\t' in param or '"' in param:
            # 1. Escapa aspas duplas internas já existentes
            param_escaped = param.replace('"', '\\"')

            # 2. CORREÇÃO CRUCIAL PARA O WINDOWS:
            # Se a string terminar com barra invertida, duplicamos a barra final.
            # Isso impede que a barra escape a aspa dupla de fechamento.
            if param_escaped.endswith('\\'):
                param_escaped += '\\'

            args.append(f'"{param_escaped}"')
        else:
            args.append(param)

    return " ".join(args)


def relancar_elevado(params_list: list[str]) -> int:
    # Retorna o código rc inteiro, em vez de um booleano (rc > 32)
    if is_running_compiled():
        exe = obter_caminho_exe()
        args = _build_runas_command_args(params_list)
    else:
        exe = os.path.abspath(sys.executable)
        script = os.path.abspath(__file__)
        args = _build_runas_command_args([script] + params_list)

    rc = shell32.ShellExecuteW(None, "runas", exe, args, None, 1)
    return rc  # Vai retornar >32 se sucesso, ou o código de erro



def run_raw_helper_elevated(
        device_path: str,
        algos: list[str],
        chunk_size: int,
        out_json_path: str,
        progress_json_path: str,
        cancel_flag_path: str,
        image_out_path: str = ""
) -> bool:
    params = [
        "--raw-hash",
        "--device", device_path,
        "--algos", ",".join(algos),
        "--chunk", str(int(chunk_size)),
        "--out-json", out_json_path,
        "--progress-json", progress_json_path,
        "--cancel-flag", cancel_flag_path,
    ]
    if image_out_path:
        params.extend(["--image-out", image_out_path])

    if is_elevated():
        if is_running_compiled():
            exe = obter_caminho_exe()
            cmd = [exe] + params
        else:
            exe = os.path.abspath(sys.executable)
            script = os.path.abspath(__file__)
            cmd = [exe, script] + params

        creationflags = 0
        if os.name == 'nt':
            creationflags = 0x08000000  # CREATE_NO_WINDOW

        subprocess.Popen(cmd, creationflags=creationflags)
        return 42 # Qualquer número > 32 significa sucesso

    return relancar_elevado(params)


def cli_raw_mode_main(argv=None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--raw-hash", action="store_true")
    parser.add_argument("--device", default="")
    parser.add_argument("--algos", default="SHA-256,SHA-512")
    parser.add_argument("--chunk", type=int, default=1024 * 1024)
    parser.add_argument("--out-json", default="")
    parser.add_argument("--progress-json", default="")
    parser.add_argument("--cancel-flag", default="")
    parser.add_argument("--image-out", default="")
    args, _ = parser.parse_known_args(argv)

    if not args.raw_hash:
        return 0

    # Este caminho precisa rodar elevado para abrir PhysicalDrive/volume raw
    if os.name != "nt":
        raise SystemExit("RAW só é suportado no Windows")

    algos = parse_algos_csv(args.algos)
    out_path = args.out_json.strip()
    prog_path = args.progress_json.strip() or None
    cancel_path = args.cancel_flag.strip() or None

    if not out_path:
        raise SystemExit("Parâmetro --out-json é obrigatório")

    img_out = args.image_out.strip() or None

    try:
        lock_f, lock_path = try_acquire_raw_device_lock(args.device)
        if lock_f is None:
            payload = {
                "ok": False,
                "error": f"JÁ EXISTE AQUISIÇÃO RAW EM ANDAMENTO PARA ESTE DRIVE: {args.device}"
            }
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            return 0

        res = raw_hash_device(
            device_path=args.device,
            algos=algos,
            chunk_size=max(4096, int(args.chunk)),
            progress_json_path=prog_path,
            cancel_flag_path=cancel_path,
            image_out_path=img_out
        )
        if res.get("cancelado"):
            payload = {"ok": False, "error": "OPERAÇÃO CANCELADA PELO USUÁRIO"}
        else:
            payload = {"ok": True, "result": res}
    except Exception as e:
        payload = {"ok": False, "error": repr(e)}

    finally:
        if lock_f:
            release_raw_device_lock(lock_f)

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    return 0

###################### BLOCO PARA GERAÇÃO DE HASH BIT A BIT DE UNIDADES (FIM) #############################

# --- FUNÇÃO PARA LOCALIZAR O EXIFTOOL ---
def obter_caminho_exiftool():
    """
    Retorna o caminho do ExifTool (exclusivo para 64 bits).
    Procura tanto no diretório base do script quanto um nível acima.
    """
    pasta_exiftool = "exiftool-13.51_64"
    nome_executavel = "exiftool.exe"

    # Define os possíveis locais de busca (dentro da pasta .dist ou na raiz do projeto)
    caminhos_tentativa = [
        BASE_DIR / pasta_exiftool / nome_executavel,
        BASE_DIR.parent / pasta_exiftool / nome_executavel
    ]

    for caminho in caminhos_tentativa:
        if caminho.exists():
            return str(caminho)

    return None


def salvar_config(config):
    """Serializa e salva config criptografada."""
    try:
        dados_json = json.dumps(config).encode('utf-8')
        dados_cripto = cipher.encrypt(dados_json)
        with open(CONFIG_FILE, 'wb') as f:
            f.write(dados_cripto)
    except Exception as e:
        print(f"Erro ao salvar config: {e}")

def carregar_config():
    """Carrega e descriptografa a configuração, retorna dict vazio se falhar."""
    if not CONFIG_FILE.exists():
        return {}
    try:
        with open(CONFIG_FILE, 'rb') as f:
            dados_cripto = f.read()
        dados_json = cipher.decrypt(dados_cripto)
        return json.loads(dados_json.decode('utf-8'))
    except Exception:
        return {}

def detectar_ads_windows(caminho_arquivo):
    """Detecta a presença de Alternate Data Streams (ADS) em arquivos NTFS."""
    if os.name != 'nt':
        return []

    streams_ocultos = []

    # Estrutura WIN32_FIND_STREAM_DATA da API do Windows
    class WIN32_FIND_STREAM_DATA(ctypes.Structure):
        _fields_ = [
            ("StreamSize", wintypes.LARGE_INTEGER),
            ("cStreamName", wintypes.WCHAR * 296)
        ]

    kernel32 = ctypes.windll.kernel32

    # --- Definindo explicitamente os tipos de argumentos e retorno ---
    # Isso evita o Access Violation por truncamento de ponteiros em sistemas 64 bits
    kernel32.FindFirstStreamW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.c_int,    # STREAM_INFO_LEVELS
        ctypes.c_void_p, # LPVOID lpFindStreamData
        wintypes.DWORD   # DWORD dwFlags
    ]
    kernel32.FindFirstStreamW.restype = ctypes.c_void_p # Retorna um HANDLE (ponteiro)

    kernel32.FindNextStreamW.argtypes = [
        ctypes.c_void_p, # HANDLE
        ctypes.c_void_p  # LPVOID lpFindStreamData
    ]
    kernel32.FindNextStreamW.restype = wintypes.BOOL

    kernel32.FindClose.argtypes = [ctypes.c_void_p]
    kernel32.FindClose.restype = wintypes.BOOL
    # ---------------------------------------------------------------------------

    FindExInfoStandard = 0
    find_data = WIN32_FIND_STREAM_DATA()

    # Inicia a busca por streams no arquivo
    handle = kernel32.FindFirstStreamW(
        wintypes.LPCWSTR(caminho_arquivo),
        FindExInfoStandard,
        ctypes.byref(find_data),
        0
    )

    # Captura o valor exato de INVALID_HANDLE_VALUE para a arquitetura atual
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    # Verifica se o handle é válido antes de prosseguir
    if handle and handle != INVALID_HANDLE_VALUE:
        try:
            teve_ads_suspeito = False
            textos_ads = []

            while True:
                nome_stream = find_data.cStreamName

                # Ignora o stream de dados padrão do Windows (::$DATA)
                if nome_stream != "::$DATA":
                    tamanho = find_data.StreamSize
                    explicacao = ""

                    # 1. Identifica os tipos mais comuns de ADS e gera uma explicação
                    if ":Zone.Identifier" in nome_stream:
                        explicacao = " (Mark of the Web: Indica que o arquivo foi baixado da internet/rede externa.)"
                    elif "SmartScreen" in nome_stream:
                        explicacao = " (Dados de verificação de segurança do Windows Defender SmartScreen.)"
                    elif "encryptable" in nome_stream:
                        explicacao = " (Relacionado a criptografia do Windows, como BitLocker ou EFS.)"
                    elif "favicon" in nome_stream.lower():
                        explicacao = " (Metadados de ícone salvos por navegadores de internet.)"
                    else:
                        explicacao = " (⚠️ ORIGEM DESCONHECIDA. Pode ser metadado de software ou payload malicioso oculto.)"
                        # Se não for nenhum dos conhecidos acima, ativa o gatilho de alerta!
                        teve_ads_suspeito = True

                    texto_atual = f"ADS Oculto: {nome_stream} ({tamanho} bytes){explicacao}"

                    # 2. Tenta ler o conteúdo interno do ADS se for pequeno (< 50 KB)
                    if 0 < tamanho < 51200:
                        try:
                            # O caminho do stream é a junção do arquivo base + o nome do stream
                            caminho_stream = f"{caminho_arquivo}{nome_stream}"

                            # Abre em modo texto, ignorando erros se for um arquivo binário
                            with open(caminho_stream, 'r', encoding='utf-8', errors='ignore') as f:
                                # Lê o limite definido (500)
                                texto_lido = f.read(500)

                                # Verifica se o corte REALMENTE ocorreu LOGO APÓS ler (antes de qualquer tradução ou strip)
                                foi_cortado = (len(texto_lido) == 500)

                                conteudo = texto_lido.strip()

                                if conteudo:
                                    # --- TRADUÇÃO DOS CÓDIGOS DE ZONA DO WINDOWS ---
                                    if "ZoneId=" in conteudo:
                                        dicionario_zonas = {
                                            "0": "[Origem: Computador Local]",
                                            "1": "[Origem: Intranet Local]",
                                            "2": "[Origem: Sites Confiáveis]",
                                            "3": "[Origem: Internet / Download Externo]",
                                            "4": "[Origem: Sites Restritos]"
                                        }
                                        for id_zona, descricao in dicionario_zonas.items():
                                            conteudo = conteudo.replace(f"ZoneId={id_zona}",
                                                                        f"ZoneId={id_zona} {descricao}")
                                    # -----------------------------------------------

                                    # Formata a saída para ficar indentada no relatório
                                    conteudo_formatado = conteudo.replace('\n', '\n       ')
                                    texto_atual += f"\n   ↳ Conteúdo extraído:\n       {conteudo_formatado}"

                                    # --- AVISO DE CORTE E COMANDO POWERSHELL ---
                                    if foi_cortado:
                                        # Divide a string ":Zone.Identifier:$DATA" pelos ":" e pega apenas o nome real
                                        partes_nome = nome_stream.split(":")
                                        nome_limpo_ps = partes_nome[1] if len(partes_nome) > 1 else nome_stream
                                        nome_arquivo_isolado = os.path.basename(caminho_arquivo)

                                        texto_atual += f"\n\n   ↳ [AVISO: O conteúdo excedeu o limite de leitura e foi truncado.]"
                                        texto_atual += f"\n   ↳ Para extrair e ver o conteúdo completo no PowerShell, navegue até a pasta do arquivo e use o comando:"
                                        texto_atual += f"\n       Get-Content -Path \"{nome_arquivo_isolado}\" -Stream \"{nome_limpo_ps}\""
                                    # -----------------------------------------------

                                else:
                                    texto_atual += "\n   ↳ [Conteúdo vazio ou formato binário não legível]"
                        except Exception as e:
                            texto_atual += f"\n   ↳ [Erro ao tentar ler conteúdo: {e}]"

                    elif tamanho >= 51200:
                        # Repete a lógica de limpeza do nome do fluxo para o PowerShell
                        partes_nome = nome_stream.split(":")
                        nome_limpo_ps = partes_nome[1] if len(partes_nome) > 1 else nome_stream
                        nome_arquivo_isolado = os.path.basename(caminho_arquivo)

                        texto_atual += "\n   ↳ [Conteúdo muito grande para exibição em texto. Recomenda-se extração manual.]"
                        texto_atual += f"\n   ↳ Para extrair e ver o conteúdo completo no PowerShell, navegue até a pasta do arquivo e use o comando:"
                        texto_atual += f"\n       Get-Content -Path \"{nome_arquivo_isolado}\" -Stream \"{nome_limpo_ps}\""
                        texto_atual += f"\n   ↳ (Dica: Adicione `> arquivo_extraido.bin` no final do comando para salvá-lo em disco)"

                    # Adiciona esse ADS na lista temporária
                    textos_ads.append(texto_atual)

                # Vai para o próximo stream
                if not kernel32.FindNextStreamW(handle, ctypes.byref(find_data)):
                    break
        finally:
            kernel32.FindClose(handle)

        # 3. Monta o bloco final adicionando o alerta geral apenas se necessário
        if textos_ads:
            streams_ocultos.append("⚠️ AVISO NTFS: Fluxos de Dados Ocultos (ADS) detectados!")

            if teve_ads_suspeito:
                streams_ocultos.append(
                    "   ↳ ALERTA PERICIAL: Foi detectado um fluxo anormal. Verifique possível ocultação de dados ou malware.")
            else:
                streams_ocultos.append(
                    "   ↳ Nota: Apenas marcações normais do sistema/navegador foram encontradas neste arquivo.")

            # Junta os textos lidos com o aviso principal
            streams_ocultos.extend(textos_ads)

    return streams_ocultos

def obter_info_volume(caminho):
    """Obtém o rótulo (Label), Serial e Sistema de Arquivos da unidade selecionada."""
    if os.name != 'nt':
        return None

    try:
        # Garante o formato "E:\" que a API do Windows exige
        drive = os.path.splitdrive(caminho)[0] + "\\"

        MAX_PATH = 260
        volume_name_buffer = ctypes.create_unicode_buffer(MAX_PATH + 1)
        file_system_name_buffer = ctypes.create_unicode_buffer(MAX_PATH + 1)
        serial_number = wintypes.DWORD()
        max_component_length = wintypes.DWORD()
        file_system_flags = wintypes.DWORD()

        kernel32 = ctypes.windll.kernel32
        sucesso = kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(drive),
            volume_name_buffer,
            ctypes.sizeof(volume_name_buffer),
            ctypes.byref(serial_number),
            ctypes.byref(max_component_length),
            ctypes.byref(file_system_flags),
            file_system_name_buffer,
            ctypes.sizeof(file_system_name_buffer)
        )

        if sucesso:
            # Formata o serial no padrão clássico hexadecimal do Windows (XXXX-XXXX)
            serial_hex = f"{serial_number.value:08X}"
            serial_formatado = f"{serial_hex[:4]}-{serial_hex[4:]}"

            return {
                'unidade': drive,
                'rotulo': volume_name_buffer.value or "[Sem Rótulo]",
                'serial': serial_formatado,
                'sistema_arquivos': file_system_name_buffer.value
            }
    except Exception:
        pass
    return None


def _reunir_hashes_quebrados_pdf(texto: str) -> str:
    import re
    # 1. Limpa caracteres invisíveis que o pypdf injeta secretamente
    texto = re.sub(r'[\u200b\u200e\u200f\x00]', '', texto)

    # 2. Padrão: Busca blocos de hexadecimais que tenham sido partidos por
    # espaços ou quebras de linha (\s, \n, \r).
    # Exige mínimo de 10 caracteres por pedaço para não grudar lixo aleatório.
    padrao = r'(?:[a-fA-F0-9]{10,}(?:[\s\n\r]+[a-fA-F0-9]{10,})+)'

    def substituir(match):
        trecho = match.group(0)
        # Arranca qualquer quebra de linha ou espaço entre os pedaços
        limpo = re.sub(r'\s+', '', trecho)
        # Só efetiva a união se a soma resultar exatamente no tamanho de um hash
        if len(limpo) in {32, 40, 64, 96, 128}:
            return limpo
        return trecho  # Se não for um tamanho válido, devolve intacto

    return re.sub(padrao, substituir, texto)


class TextEditCustodia(QTextEdit):
    """Caixa de texto customizada que aceita arquivos PDF/DOCX/XLSX/TXT via Drag & Drop."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)

        self.nome_arquivo_origem = None
        self.hash_arquivo_origem = None

        self._texto_fundo = (
            "Arraste e solte o relatório de hashes gerados pela delegacia aqui (PDF, DOCX, XLSX, TXT)\n"
            "ou cole o texto livremente para validar a Cadeia de Custódia... (Nota: Hashes CRC32 não são conferidos)"
        )

    def paintEvent(self, event):
        """Sobrescreve a pintura para forçar o texto de fundo a aceitar quebra de linha (\n)"""
        super().paintEvent(event)

        # 2. Se a caixa estiver vazia, nós mesmos "pintamos" o texto no fundo
        if not self.toPlainText():
            from PySide6.QtGui import QPainter, QColor
            from PySide6.QtCore import Qt

            painter = QPainter(self.viewport())
            painter.setPen(QColor("#888888"))  # Cor cinza padrão de placeholder

            # Cria uma margem de 5 pixels para o texto não ficar grudado na borda
            rect = self.viewport().rect().adjusted(5, 5, -5, -5)

            # Desenha o texto respeitando o \n e alinhando no topo
            painter.drawText(rect, Qt.AlignmentFlag.AlignTop | Qt.TextFlag.TextWordWrap, self._texto_fundo)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragMoveEvent(event)

    def dropEvent(self, event):
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            caminho_arquivo = urls[0].toLocalFile()
            event.acceptProposedAction()
            self.carregar_arquivo(caminho_arquivo)
        else:
            super().dropEvent(event)

    def carregar_arquivo(self, caminho):
        """Lê o arquivo arrastado e extrai o texto de forma nativa e segura."""
        self.nome_arquivo_origem = os.path.basename(caminho)

        # --- CÁLCULO DO HASH (SHA-256) DO ARQUIVO DE REFERÊNCIA ---
        try:
            import hashlib
            sha256_ref = hashlib.sha256()
            with open(caminho, 'rb') as f_hash:
                while chunk := f_hash.read(65536):
                    sha256_ref.update(chunk)
            self.hash_arquivo_origem = sha256_ref.hexdigest().upper()
        except Exception:
            self.hash_arquivo_origem = "[Erro ao calcular hash]"
        # ----------------------------------------------------------

        extensao = caminho.lower().split('.')[-1]
        texto_extraido = ""

        try:
            # 1. LEITURA DE PDF
            if extensao == 'pdf':
                reader = PdfReader(caminho)
                for page in reader.pages:
                    texto_pagina = page.extract_text()
                    if texto_pagina:
                        texto_extraido += texto_pagina + "\n"

                texto_extraido = _reunir_hashes_quebrados_pdf(texto_extraido)

                # Aviso de PDF Escaneado (Imagem)
                if not texto_extraido.strip():
                    texto_extraido = (
                        "⚠️ [AVISO FORENSE]\n"
                        "Nenhum texto digital detectado neste PDF.\n\n"
                        "O arquivo parece ser um documento escaneado (composto apenas por imagens). "
                        "Por favor, copie e cole os hashes do documento original manualmente aqui."
                    )

            # 2. LEITURA NATIVA DE WORD MODERNO (DOCX)
            elif extensao == 'docx':
                try:
                    with zipfile.ZipFile(caminho) as z:
                        xml_content = z.read('word/document.xml')
                        tree = ET.fromstring(xml_content)
                        textos = []
                        # Itera sobre os parágrafos para não quebrar palavras ao meio
                        for p_node in tree.iter():
                            if p_node.tag.endswith('}p'):
                                texto_paragrafo = ""
                                for t_node in p_node.iter():
                                    if t_node.tag.endswith('}t') and t_node.text:
                                        texto_paragrafo += t_node.text
                                if texto_paragrafo:
                                    textos.append(texto_paragrafo)
                        texto_extraido = "\n".join(textos)
                except zipfile.BadZipFile:
                    texto_extraido = "⚠️ Erro: O arquivo DOCX está corrompido."

            # 3. LEITURA NATIVA DE EXCEL MODERNO (XLSX)
            elif extensao == 'xlsx':
                try:
                    with zipfile.ZipFile(caminho) as z:
                        textos = []
                        # No Excel, os textos das células ficam salvos no sharedStrings.xml
                        if 'xl/sharedStrings.xml' in z.namelist():
                            xml_content = z.read('xl/sharedStrings.xml')
                            tree = ET.fromstring(xml_content)
                            for si_node in tree.iter():
                                if si_node.tag.endswith('}si'):
                                    texto_item = ""
                                    for t_node in si_node.iter():
                                        if t_node.tag.endswith('}t') and t_node.text:
                                            texto_item += t_node.text
                                    if texto_item:
                                        textos.append(texto_item)
                        texto_extraido = "\n".join(textos)
                except zipfile.BadZipFile:
                    texto_extraido = "⚠️ Erro: O arquivo XLSX está corrompido."

            # 4. AVISO PARA FORMATOS LEGADOS (DOC / XLS)
            elif extensao in ['doc', 'xls']:
                texto_extraido = (
                    f"⚠️ [FORMATO LEGADO NÃO SUPORTADO]\n"
                    f"O formato (.{extensao}) possui uma estrutura binária fechada.\n\n"
                    f"Para garantir a precisão da extração sem corromper os hashes, abra o arquivo no Office e "
                    f"copie/cole o texto aqui, ou salve-o como PDF e arraste novamente."
                )

            # 5. ARQUIVOS DE TEXTO COMUNS (TXT, CSV)
            else:
                with open(caminho, 'r', encoding='utf-8', errors='replace') as f:
                    texto_extraido = f.read()

            self.setPlainText(texto_extraido)
            # Imprime no console (se aberto) que o carregamento foi bem sucedido
            print(f"Relatório carregado: {os.path.basename(caminho)}")
        except Exception as e:
            self.setPlainText(f"Erro inesperado ao ler o arquivo de referência: {str(e)}")

    def clear(self):
        """Sobrescreve a limpeza para esquecer o nome e o hash do arquivo quando o botão Limpar for clicado."""
        self.nome_arquivo_origem = None
        self.hash_arquivo_origem = None
        super().clear()

class ValidadorCustodia:
    """Implementa a busca reversa com barreira de algoritmo para Cadeia de Custódia."""

    def __init__(self, texto_referencia: str, is_pdf: bool = False):
        self.linhas = [linha.strip() for linha in texto_referencia.splitlines()]
        self.is_pdf = is_pdf

        # Padrões com 'word boundaries' para identificar tamanhos exatos
        self.padroes = {
            "MD5": r'\b[a-fA-F0-9]{32}\b',
            "SHA-1": r'\b[a-fA-F0-9]{40}\b',
            "SHA-256": r'\b[a-fA-F0-9]{64}\b',
            "SHA-384": r'\b[a-fA-F0-9]{96}\b',
            "SHA-512": r'\b[a-fA-F0-9]{128}\b'
        }

        self.mapa_hashes = {}
        self.barreiras_algo = {algo: set() for algo in self.padroes}

        self.arquivos_validados = []

        self._mapear_texto()

    def _mapear_texto(self):
        """Varre o texto uma única vez mapeando a posição de cada hash."""
        for idx, linha in enumerate(self.linhas):
            if not linha: continue

            for algo, padrao in self.padroes.items():
                for match in re.finditer(padrao, linha):
                    val_hash = match.group().upper()

                    if val_hash not in self.mapa_hashes:
                        self.mapa_hashes[val_hash] = []

                    self.mapa_hashes[val_hash].append({'algo': algo, 'linha_idx': idx})
                    self.barreiras_algo[algo].add(idx)

    def _linha_contem_nome(self, linha: str, nome_arquivo_atual: str) -> bool:
        """Checa se o nome base do arquivo está na linha, blindado contra espaços injetados por PDFs."""
        linha_lower = linha.lower()

        # 1. Limpeza pesada de caracteres invisíveis
        linha_lower = linha_lower.replace('\xad', '').replace('\u200b', '').replace('\u200e', '').replace('\u200f', '')

        # 2. Corrige a falha clássica do pypdf: injetar espaços ao redor do ponto (ex: "RawTAP .pm" ou "RawTAP. pm")
        linha_lower = linha_lower.replace(' .', '.').replace('. ', '.')

        # --- TENTATIVA A: Busca Padronizada ---
        idx = linha_lower.find(nome_arquivo_atual)
        while idx != -1:
            valido_antes = True
            if idx > 0:
                char_anterior = linha_lower[idx - 1]
                if char_anterior.isalnum() or char_anterior == '_':
                    valido_antes = False

            valido_depois = True
            fim_idx = idx + len(nome_arquivo_atual)
            if fim_idx < len(linha_lower):
                char_posterior = linha_lower[fim_idx]
                if char_posterior.isalnum() or char_posterior == '_':
                    valido_depois = False

            if valido_antes and valido_depois:
                return True

            idx = linha_lower.find(nome_arquivo_atual, idx + 1)

        # --- TENTATIVA B: Fallback Agressivo (Para PDF "esmigalhado" tipo P S P . p m) ---
        # Removemos TODOS os espaços da linha e do nome do arquivo
        linha_sem_espaco = linha_lower.replace(' ', '')
        nome_sem_espaco = nome_arquivo_atual.replace(' ', '')

        # Só ativamos esse modo se o arquivo tiver um nome razoável para evitar falsos positivos
        if len(nome_sem_espaco) >= 4 and nome_sem_espaco in linha_sem_espaco:
            idx_fuzzy = linha_sem_espaco.find(nome_sem_espaco)

            # Como arrancamos os espaços, precisamos garantir que é o arquivo mesmo.
            # Verifica se há uma barra (\ ou /) logo antes do nome, o que confirma ser o final de um caminho.
            if idx_fuzzy > 0:
                char_anterior = linha_sem_espaco[idx_fuzzy - 1]
                if char_anterior in '\\/':
                    return True
            else:
                return True

        return False

    def validar(self, caminho_arquivo: str, hashes_calculados: dict) -> tuple[int, str]:
        """Executa a busca reversa, testando múltiplos hashes, e retorna (status, mensagem_formatada)."""
        nome_arquivo_atual = os.path.basename(caminho_arquivo).lower()

        algos_conferem = []
        algos_alerta = []

        for algo_calc, val_calc in hashes_calculados.items():
            if val_calc in self.mapa_hashes:
                ocorrencias = self.mapa_hashes[val_calc]
                nome_encontrado_para_este_hash = False

                for ocorrencia in ocorrencias:
                    algo_ref = ocorrencia['algo']
                    idx_ref = ocorrencia['linha_idx']

                    # 1. Verifica na mesma linha
                    if self._linha_contem_nome(self.linhas[idx_ref], nome_arquivo_atual):
                        algos_conferem.append(algo_calc)
                        nome_encontrado_para_este_hash = True
                        break  # Achou o nome para este hash, vai pro próximo hash calculado

                    # 2. Busca Reversa: Sobe as linhas do texto acumulando o contexto
                    idx_busca = idx_ref - 1
                    achou_na_reversa = False
                    bloco_acumulado = self.linhas[idx_ref]

                    while idx_busca >= 0:
                        linha_atual = self.linhas[idx_busca]

                        # Barreira de Algoritmo
                        if idx_busca in self.barreiras_algo[algo_ref]:
                            break

                        # Acumula a linha de cima com o bloco atual
                        bloco_acumulado = linha_atual + " " + bloco_acumulado

                        if self._linha_contem_nome(bloco_acumulado, nome_arquivo_atual):
                            algos_conferem.append(algo_calc)
                            nome_encontrado_para_este_hash = True
                            achou_na_reversa = True
                            break

                        idx_busca -= 1

                    if achou_na_reversa:
                        break  # Se achou na reversa, sai do loop

                    # 3. Busca Progressiva Condicional (SÓ RODA SE FOR PDF)
                    if self.is_pdf and not nome_encontrado_para_este_hash:
                        idx_busca = idx_ref + 1
                        achou_na_progressiva = False
                        bloco_acumulado_descendo = self.linhas[idx_ref]

                        while idx_busca < len(self.linhas):
                            linha_atual = self.linhas[idx_busca]

                            # Barreira de Algoritmo
                            if idx_busca in self.barreiras_algo[algo_ref]:
                                break

                            # Acumula a linha de baixo com o bloco atual
                            bloco_acumulado_descendo = bloco_acumulado_descendo + " " + linha_atual

                            if self._linha_contem_nome(bloco_acumulado_descendo, nome_arquivo_atual):
                                algos_conferem.append(algo_calc)
                                nome_encontrado_para_este_hash = True
                                achou_na_progressiva = True
                                break

                            idx_busca += 1

                        if achou_na_progressiva:
                            break  # Se achou descendo, sai do loop

                # Se passou por todas as ocorrências desse hash no texto e não achou o nome perto de nenhuma
                if not nome_encontrado_para_este_hash:
                    algos_alerta.append(algo_calc)

        # Montagem da mensagem final
        if algos_conferem:
            texto_algos = ' e '.join(algos_conferem) if len(algos_conferem) < 3 else ', '.join(
                algos_conferem[:-1]) + ' e ' + algos_conferem[-1]
            sufixo = 's' if len(algos_conferem) > 1 else ''

            for a in algos_conferem:
                if not hasattr(self, 'arquivos_validados_dict'): self.arquivos_validados_dict = {}
                if nome_arquivo_atual not in self.arquivos_validados_dict:
                    self.arquivos_validados_dict[nome_arquivo_atual] = {}
                self.arquivos_validados_dict[nome_arquivo_atual][a] = hashes_calculados[a]

            # --- VERIFICAÇÃO DE DIVERGÊNCIA PARCIAL ---
            algos_calculados_lista = list(hashes_calculados.keys())
            if "CRC32" in algos_calculados_lista:
                algos_calculados_lista.remove("CRC32")

            algos_falharam = [a for a in algos_calculados_lista if a not in algos_conferem]

            if algos_falharam:
                texto_falhos = ' e '.join(algos_falharam) if len(algos_falharam) < 3 else ', '.join(
                    algos_falharam[:-1]) + ' e ' + algos_falharam[-1]
                return 4, f"⚠️ ALERTA PARCIAL - {texto_algos} validado{sufixo}, mas houve DIVERGÊNCIA no {texto_falhos}."
            # -------------------------------------------

            return 1, f"✅ CONFERE - {texto_algos} validado{sufixo}."

        elif algos_alerta:
            texto_algos = ' e '.join(algos_alerta) if len(algos_alerta) < 3 else ', '.join(algos_alerta[:-1]) + ' e ' + \
                                                                                 algos_alerta[-1]

            hash_principal = hashes_calculados.get(algos_alerta[0], "N/A")
            nome_limpo = os.path.basename(caminho_arquivo)

            if not hasattr(self, 'arquivos_validados_dict'): self.arquivos_validados_dict = {}
            if nome_limpo not in self.arquivos_validados_dict:
                self.arquivos_validados_dict[nome_limpo] = {}
            self.arquivos_validados_dict[nome_limpo][algos_alerta[0]] = f"{hash_principal} (NOME DIVERGENTE)"

            return 2, f"⚠️ ALERTA - Hash confere ({texto_algos}), mas o nome diverge."

        return 3, "❌ DIVERGÊNCIA - Nenhum hash calculado para este arquivo consta na relação original da Cadeia de Custódia."

    def validar_hash_simples(self, hashes_calculados: dict) -> tuple[int, str]:
        """Valida apenas a existência do hash no texto, ideal para aquisições RAW onde o nome da mídia varia no laudo."""
        algos_conferem = []

        for algo_calc, val_calc in hashes_calculados.items():
            if val_calc in self.mapa_hashes:
                algos_conferem.append(algo_calc)

        if algos_conferem:
            texto_algos = " e ".join(algos_conferem) if len(algos_conferem) < 3 else ", ".join(
                algos_conferem[:-1]) + " e " + algos_conferem[-1]
            sufixo = "s" if len(algos_conferem) > 1 else ""

            # --- VERIFICAÇÃO DE DIVERGÊNCIA PARCIAL ---
            algos_calculados_lista = list(hashes_calculados.keys())
            if "CRC32" in algos_calculados_lista:
                algos_calculados_lista.remove("CRC32")  # CRC32 não entra em custódia

            algos_falharam = [a for a in algos_calculados_lista if a not in algos_conferem]

            if algos_falharam:
                texto_falhos = " e ".join(algos_falharam) if len(algos_falharam) < 3 else ", ".join(
                    algos_falharam[:-1]) + " e " + algos_falharam[-1]
                return 2, f"⚠️ ALERTA PARCIAL - Hash{sufixo} confere ({texto_algos}), mas houve DIVERGÊNCIA no {texto_falhos}."
            # -------------------------------------------

            return 1, f"✅ CONFERE - Hash{sufixo} ({texto_algos}) localizado{sufixo} no documento de custódia."

        return 3, "❌ NÃO CONFERE / NENHUM HASH DA UNIDADE LOCALIZADO NO TEXTO"

    def obter_lista_limpa(self) -> list:
        """Tenta extrair os pares (Nome do Arquivo, Hash) do texto de referência usando heurística forense."""
        lista_limpa = []
        arquivos_encontrados = {}  # Para agrupar hashes do mesmo arquivo

        for idx_linha, linha in enumerate(self.linhas):
            for algo, padrao in self.padroes.items():
                for match in re.finditer(padrao, linha):
                    hash_val = match.group().upper()
                    nome_encontrado = "[Nome não identificado]"

                    # Busca reversa DIRETA (Sobe as linhas acumulando o texto do nome)
                    idx_busca = idx_linha - 1
                    bloco_nome = ""

                    while idx_busca >= 0:
                        if idx_busca in self.barreiras_algo[algo]:
                            break

                        linha_original = self.linhas[idx_busca]
                        linha_cima = linha_original.strip()
                        linha_cima_lower = linha_cima.lower()

                        if not linha_cima:
                            idx_busca -= 1
                            continue

                        # Pula linhas de metadados comuns ou prefixos de outros hashes
                        prefixos_pular = ('tamanho', 'size', 'modificado', 'criado', 'data', 'entropia', 'crc32',
                                          'md5', 'sha-1', 'sha-256', 'sha-384', 'sha-512')
                        if linha_cima_lower.startswith(prefixos_pular):
                            idx_busca -= 1
                            continue

                        # Pula se a linha for apenas um hash puro solto (sem prefixo)
                        if re.match(r'^[a-fA-F0-9]{32,128}\s*$', linha_cima):
                            idx_busca -= 1
                            continue

                        # Limpa prefixos como "Arquivo:"
                        linha_cima = re.sub(r'^(Arquivo|Nome|File|Target)\s*:\s*', '', linha_cima,
                                            flags=re.IGNORECASE)

                        # Acumula na frente (já que estamos subindo)
                        if bloco_nome:
                            bloco_nome = linha_cima + " " + bloco_nome
                        else:
                            bloco_nome = linha_cima

                        # Condição de parada de sucesso: Achou o prefixo "Arquivo:" ou letra de Drive C:/
                        if re.match(r'^(Arquivo|Nome|File|Target)\s*:', linha_original, flags=re.IGNORECASE) or \
                                re.match(r'^([A-Za-z]:[\\/]|\\\\|/)', linha_cima):
                            break

                        # Se não for PDF, a quebra de linha em laudos txt não deveria existir no meio do nome.
                        if not getattr(self, 'is_pdf', False):
                            break

                        idx_busca -= 1

                    if bloco_nome:
                        # Pega sempre a ponta final (o nome do arquivo em si) do bloco acumulado
                        nome_encontrado = bloco_nome.replace('\\', '/').split('/')[-1].strip()

                    # Agrupa os hashes completos pelo nome do arquivo encontrado
                    if nome_encontrado not in arquivos_encontrados:
                        arquivos_encontrados[nome_encontrado] = []

                    # Salva o hash original em seu tamanho completo
                    arquivos_encontrados[nome_encontrado].append(f"{algo}: {hash_val}")

        # Formata de um jeito profissional para o relatório final
        for nome, hashes in arquivos_encontrados.items():
            hashes_str = " | ".join(hashes)
            lista_limpa.append(f"📄 {nome}   |   {hashes_str}")

        return lista_limpa


class JanelaHashes(QWidget):
    sinal_atualizacao = Signal(str, str, str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{NOME_APP} - v.{VERSAO_APP}")
        self.resize(900, 680)

        if os.path.exists(ICON_PATH):
            self.setWindowIcon(QIcon(ICON_PATH))

        self.setAcceptDrops(True)
        self.cancelar_operacao = False
        self.processando = False

        self.setup_ui()

        # --- LIMPEZA PREVENTIVA DE RASTROS DE EXECUÇÕES ANTERIORES ---
        self.limpar_arquivos_temporarios()

        # --- CONTROLE DE TEMPO DECORRIDO E DE TEMPO RESTANTE ---
        self.timer_tempo = QTimer(self)
        self.timer_tempo.timeout.connect(self.atualizar_tempo_total)
        self.bytes_processados_total = 0
        self.total_bytes_processar = 0
        self.tempo_inicio_total = 0

        # Conecta o sinal emitido pela thread à função que altera a interface
        self.sinal_atualizacao.connect(self._exibir_alerta_atualizacao)
        # --- CHAMA A ROTINA DE CHECAGEM DE NOVA ATUALIZAÇÃO DE VERSÃO ---
        self.checar_atualizacoes()

    def setup_ui(self):
        layout_principal = QVBoxLayout()

        # --- LINHA 1: Controles Principais ---
        layout_controles = QHBoxLayout()

        self.btn_arquivo = QPushButton("Selecionar Arquivo(s)")
        self.btn_arquivo.clicked.connect(self.selecionar_arquivo)
        layout_controles.addWidget(self.btn_arquivo)

        self.btn_diretorio = QPushButton("Selecionar Diretório")
        self.btn_diretorio.clicked.connect(self.selecionar_diretorio)
        layout_controles.addWidget(self.btn_diretorio)

        self.chk_subdiretorios = QCheckBox("Incluir Subdiretórios")
        self.chk_subdiretorios.setChecked(True)
        layout_controles.addWidget(self.chk_subdiretorios)

        layout_controles.addSpacing(25)

        # Botão RAW
        self.btn_unidade_raw = QPushButton("Selecionar Unidade (RAW)")
        self.btn_unidade_raw.clicked.connect(self.selecionar_unidade_raw)
        # Estilo distinto para diferenciar o RAW dos arquivos comuns
        self.btn_unidade_raw.setStyleSheet("""
                    QPushButton {
                        font-weight: bold; 
                        color: #800000; 
                        background-color: #e6e6e6;
                    }
                    QPushButton:disabled {
                        color: #999999; 
                        background-color: #f0f0f0;
                        border: 1px solid #cccccc;
                    }
                """)
        layout_controles.addWidget(self.btn_unidade_raw)

        # --- Checkbox de Metadados Extras à direita de Subdiretórios ---
        self.chk_metadados = QCheckBox("Incluir Metadados Básicos")
        self.chk_metadados.setChecked(True)
        self.chk_metadados.setToolTip(
            "<p><b>Suporte a extração de metadados avançados:</b></p>"
            "<ul>"
            "<li><b>Imagens (JPG, PNG, TIFF, WEBP...):</b> Resolução, Formato, DPI, Dispositivo (Marca/Modelo), Data de Captura, Software/Editor e Coordenadas GPS (com link para o Google Maps).</li>"
            "<li><b>Vídeos (MP4, AVI, MKV...):</b> Resolução, FPS, Duração, Data de Criação, Dispositivo de Gravação, Software e Coordenadas GPS (com link para o Google Maps).</li>"
            "<li><b>Documentos (PDF e Office):</b> Total de Páginas, Título Interno, Autor, Último a Modificar e Software Criador.</li>"
            "<li><b>Áudio (MP3, WAV, FLAC...):</b> Duração Exata, Taxa de Bits (Bitrate), Artista/Software e Comentários Ocultos.</li>"
            "<li><b>Executáveis (EXE, DLL, SYS):</b> Data de Compilação Exata (UTC), Verificação de Assinatura Digital (Authenticode), Nome Original do Arquivo e Empresa.</li>"
            "<li><b>E-mails (EML, MSG):</b> Remetente Real, Destinatário, Assunto, Data de Envio e 1º Servidor de Trânsito (rastreio de IP).</li>"
            "<li><b>Atalhos do Windows (LNK):</b> Caminho Alvo (Local e Relativo), Argumentos de Execução (Payloads), Diretório de Trabalho, Rótulo/Serial do Pendrive/HD (em Hex) e MAC Address de origem.</li>"
            "</ul>"
            "<p><b>Análises Forenses Integradas e Proteções:</b></p>"
            "<ul>"
            "<li><b>Segurança NTFS (ADS):</b> Detecção e leitura parcial de fluxos de dados ocultos, como 'Mark of the Web' ou payloads binários.</li>"
            "<li><b>Preservação de Evidência (Nuvem):</b> Bloqueio automático de leitura de arquivos 'Apenas Online' (OneDrive/Google Drive) para evitar downloads indesejados e alteração do disco.</li>"
            "<li><b>Seleção Literal:</b> Ignora ativamente resoluções nativas do Windows para links simbólicos e junções de diretório.</li>"
            "<li><b>File Lock / Controle de Acesso:</b> Identificação segura de arquivos trancados com acesso exclusivo pelo sistema operacional ou em uso por outros aplicativos (ex: pacote Office).</li>"
            "</ul>"
        )
        self.chk_metadados.installEventFilter(self)

        layout_controles.addStretch()

        self.btn_formatos = QPushButton("Formatos Suportados")
        self.btn_formatos.clicked.connect(self.mostrar_formatos)
        layout_controles.addWidget(self.btn_formatos)

        self.btn_sobre = QPushButton("Sobre")
        self.btn_sobre.clicked.connect(self.mostrar_sobre)
        layout_controles.addWidget(self.btn_sobre)

        layout_principal.addLayout(layout_controles)

        # --- LINHA 2: Seleção de Algoritmos ---
        layout_hashes = QHBoxLayout()
        layout_hashes.addWidget(QLabel("Algoritmos:"))

        self.chk_hashes = {}
        lista_algoritmos = ["CRC32", "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"]

        # Dicionário com as descrições forenses de cada algoritmo
        tooltips_hashes = {
            "CRC32": "<p><b>CRC32:</b> Verificação de redundância (Não Criptográfico).</p>"
                     "<ul><li><b>Segurança:</b> Nula.</li>"
                     "<li><b>Colisão:</b> Altíssima.</li>"
                     "<li><b>Uso:</b> Inseguro para evidências. Útil apenas para detecção rápida de corrupção. <br><br>"
                     "<span style='color: #990000;'><b>⚠️ Nota Pericial:</b> Para evitar falsos positivos, o CRC32 é "
                     "intencionalmente ignorado na conferência automática da Cadeia de Custódia.</span></li></ul>",

            "MD5": "<p><b>MD5:</b> Hash criptográfico legado.</p>"
                   "<ul><li><b>Segurança:</b> Quebrada.</li>"
                   "<li><b>Colisão:</b> Muito Alta (facilmente forjada).</li>"
                   "<li><b>Uso:</b> Utilizado historicamente, mas hoje serve apenas para conferência de integridade simples, não para validação de evidência contra adulteração intencional.</li></ul>",

            "SHA-1": "<p><b>SHA-1:</b> Hash criptográfico obsoleto.</p>"
                     "<ul><li><b>Segurança:</b> Comprometida (Ataque SHAttered).</li>"
                     "<li><b>Colisão:</b> Comprovada na prática, mas exige vastos recursos computacionais e financeiros (ex: ataques de nível estatal).</li>"
                     "<li><b>Uso:</b> Ainda comum em sistemas antigos ou de versionamento (ex: Git), mas substituído pelo SHA-256 no meio pericial.</li></ul>",

            "SHA-256": "<p><b>SHA-256:</b> Padrão atual da indústria forense (Família SHA-2).</p>"
                       "<ul><li><b>Segurança:</b> Criptograficamente Seguro.</li>"
                       "<li><b>Colisão:</b> Praticamente Nula.</li>"
                       "<li><b>Uso:</b> Padrão-ouro aceito em tribunais internacionalmente para garantir a inalterabilidade da evidência.</li></ul>",

            "SHA-384": "<p><b>SHA-384:</b> Variação truncada do SHA-512 (Família SHA-2).</p>"
                       "<ul><li><b>Segurança:</b> Altamente Seguro (Imune a ataques de extensão de comprimento).</li>"
                       "<li><b>Colisão:</b> Nula.</li>"
                       "<li><b>Uso:</b> Exigido em níveis de segurança governamentais muito específicos.</li></ul>",

            "SHA-512": "<p><b>SHA-512:</b> Nível máximo da família SHA-2.</p>"
                       "<ul><li><b>Segurança:</b> Máxima (Nível Militar).</li>"
                       "<li><b>Colisão:</b> Nula.</li>"
                       "<li><b>Uso:</b> Perfeição criptográfica atual. <i>Dica: Geralmente calcula mais rápido que o SHA-256 em processadores modernos de 64-bits.</i></li></ul>"
        }

        for algo in lista_algoritmos:
            chk = QCheckBox(algo)
            if algo in ["SHA-256", "SHA-512"]:
                chk.setChecked(True)

            # Aplica o texto da tooltip correspondente
            chk.setToolTip(tooltips_hashes[algo])
            # Instala o filtro de eventos para aparecer instantaneamente
            chk.installEventFilter(self)

            layout_hashes.addWidget(chk)
            self.chk_hashes[algo] = chk

        layout_hashes.addStretch()

        layout_hashes.addWidget(QLabel("Análise:"))
        layout_hashes.addWidget(self.chk_metadados)


        layout_principal.addLayout(layout_hashes)

        # --- ALERTA DE ATUALIZAÇÃO (Invisível por padrão) ---
        self.lbl_alerta_versao = QLabel()
        self.lbl_alerta_versao.setOpenExternalLinks(True)  # Para o link funcionar
        self.lbl_alerta_versao.hide()  # Esconde ao iniciar
        layout_principal.addWidget(self.lbl_alerta_versao)

        # --- DIVISOR AJUSTÁVEL (QSplitter) ---
        # É ele que permite arrastar a linha entre as caixas para redimensioná-las com o mouse
        splitter = QSplitter(Qt.Orientation.Vertical)

        # --- CADEIA DE CUSTÓDIA ---
        grupo_validacao = QGroupBox("Validar Cadeia de Custódia (Opcional)")
        layout_validacao = QHBoxLayout()  # O seu layout horizontal perfeito

        self.texto_referencia = TextEditCustodia(self)
        self.texto_referencia.setMinimumHeight(65)

        self.btn_limpar_custodia = QPushButton("Limpar\nConteúdo")
        self.btn_limpar_custodia.setFixedWidth(80)
        # Faz o botão acompanhar a altura da caixa de texto
        self.btn_limpar_custodia.setSizePolicy(self.btn_limpar_custodia.sizePolicy().Policy.Fixed,
                                               self.btn_limpar_custodia.sizePolicy().Policy.Expanding)
        self.btn_limpar_custodia.clicked.connect(self.texto_referencia.clear)

        layout_validacao.addWidget(self.texto_referencia)
        layout_validacao.addWidget(self.btn_limpar_custodia)
        grupo_validacao.setLayout(layout_validacao)

        # A MÁGICA ACONTECE AQUI: Em vez de adicionar ao layout principal, adicionamos ao splitter!
        splitter.addWidget(grupo_validacao)

        # --- Área de Texto Principal ---
        self.texto_saida = QTextEdit()
        self.texto_saida.setReadOnly(True)
        self.texto_saida.setStyleSheet(
            "background-color: #f4f4f4; color: #111111; font-family: Consolas; font-size: 10pt;")
        self.texto_saida.append(MENSAGEM_INICIAL + "\n")

        # Adiciona a saída também no splitter, para ficar embaixo da validação
        splitter.addWidget(self.texto_saida)

        # Define as proporções iniciais de altura (Ex: 80 pixels para validação e 500 para o log)
        splitter.setSizes([190, 390])

        # Finalmente, coloca o splitter inteiro na tela principal
        layout_principal.addWidget(splitter)

        # --- Barras de Progresso ---
        layout_progresso = QVBoxLayout()

        # Estilo padrão para as barras (Fundo escuro/Grafite e Letra Branca)
        self.estilo_barra_padrao = """
                    QProgressBar {
                        border: 1px solid #999999;
                        border-radius: 4px;
                        text-align: center;
                        background-color: #333333;
                        color: #ffffff;
                        font-weight: bold;
                    }
                    QProgressBar::chunk {
                        background-color: #0078d7;
                        border-radius: 2px;
                    }
                """

        # 1. Progresso do Arquivo Atual
        self.lbl_progresso_arquivo = QLabel("Progresso do Arquivo Atual:")
        layout_progresso.addWidget(self.lbl_progresso_arquivo)

        self.barra_arquivo = QProgressBar()
        self.barra_arquivo.setValue(0)
        self.barra_arquivo.setStyleSheet(self.estilo_barra_padrao)
        layout_progresso.addWidget(self.barra_arquivo)

        layout_progresso.addSpacing(5)  # Pequeno respiro entre as barras

        # 2. Progresso Total (Arquivos)
        self.lbl_progresso_total = QLabel("Progresso Total (Arquivos):")
        layout_progresso.addWidget(self.lbl_progresso_total)

        self.barra_total = QProgressBar()
        self.barra_total.setValue(0)
        self.barra_total.setStyleSheet(self.estilo_barra_padrao)

        layout_progresso.addWidget(self.barra_total)

        layout_progresso.addSpacing(10)  # Espaço maior antes do botão

        # 3. Botão Cancelar em linha dedicada e centralizado
        self.btn_cancelar = QPushButton("CANCELAR PROCESSAMENTO")
        self.btn_cancelar.setMinimumWidth(280)
        self.btn_cancelar.setMinimumHeight(40)
        self.btn_cancelar.setStyleSheet("""
                            QPushButton {
                                background-color: #ffcccc; 
                                color: #990000; 
                                font-weight: bold;
                                border: 1px solid #cc9999;
                                border-radius: 5px;
                            }
                            QPushButton:hover {
                                background-color: #ffb3b3; /* Vermelho um pouco mais forte ao passar o mouse */
                                border: 1px solid #b30000;
                            }
                            QPushButton:pressed {
                                background-color: #ff9999; /* Vermelho ainda mais escuro ao clicar */
                            }
                            QPushButton:disabled {
                                background-color: #e0e0e0; 
                                color: #888888;
                                border: 1px solid #cccccc;
                            }
                        """)
        self.btn_cancelar.setEnabled(False)
        self.btn_cancelar.clicked.connect(self.acao_cancelar)

        # Adicionado diretamente ao layout vertical para expandir totalmente
        layout_progresso.addWidget(self.btn_cancelar)

        layout_principal.addLayout(layout_progresso)

        # --- Barra Inferior ---
        layout_inferior = QHBoxLayout()

        self.btn_copiar = QPushButton("Copiar Relatório (Ctrl+C)")
        self.btn_copiar.clicked.connect(self.copiar_para_area_transferencia)
        layout_inferior.addWidget(self.btn_copiar)

        self.btn_salvar = QPushButton("Salvar Relatório em TXT")
        self.btn_salvar.clicked.connect(self.salvar_relatorio)
        layout_inferior.addWidget(self.btn_salvar)

        self.btn_limpar = QPushButton("Limpar Tela")
        self.btn_limpar.clicked.connect(self.limpar_tela)
        layout_inferior.addWidget(self.btn_limpar)

        layout_principal.addLayout(layout_inferior)

        self.setLayout(layout_principal)

        # Carregar configurações salvas
        config = carregar_config()
        if config:
            # Restaura estado do checkbox de metadados
            self.chk_metadados.setChecked(config.get('chk_metadados', True))
            # Restaura estado do checkbox de subdiretórios
            self.chk_subdiretorios.setChecked(config.get('chk_subdiretorios', True))
            # Restaura estados dos algoritmos
            hash_states = config.get('hashes', {})
            for algo, chk in self.chk_hashes.items():
                chk.setChecked(hash_states.get(algo, algo in ["SHA-256", "SHA-512"]))

    def checar_atualizacoes(self):
        """Checa na API do GitHub se há uma nova Release publicada"""
        url = f"https://api.github.com/repos/{USUARIO}/{REPOSITORIO}/releases/latest"

        def _worker():
            try:
                import urllib.request
                import json
                import re

                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
                with urllib.request.urlopen(req, timeout=5) as response:
                    dados = json.loads(response.read().decode('utf-8'))

                versao_github_bruta = dados.get('tag_name', '')
                url_download = dados.get('html_url', LINK_GITHUB)
                notas_lancamento = dados.get('body', 'Sem notas de lançamento disponíveis.')

                match_gh = re.search(r'(\d+\.\d+\.\d+)', versao_github_bruta)
                match_local = re.search(r'(\d+\.\d+\.\d+)', VERSAO_APP)

                if match_gh and match_local:
                    str_gh = match_gh.group(1)
                    str_local = match_local.group(1)
                    tup_gh = tuple(map(int, str_gh.split('.')))
                    tup_local = tuple(map(int, str_local.split('.')))

                    if tup_gh > tup_local:
                        # Emite as três informações para a interface
                        self.sinal_atualizacao.emit(versao_github_bruta, url_download, notas_lancamento)

            except Exception as e:
                pass  # Erros de rede são ignorados silenciosamente para não travar o app

        import threading
        t = threading.Thread(target=_worker, daemon=True)
        t.start()

    def _exibir_alerta_atualizacao(self, nova_versao, link, notas_lancamento):
        import re

        alerta_html = (
            f"<div style='background-color: #fff3cd; border: 1px solid #ffeeba; padding: 12px; border-radius: 5px; margin-bottom: 5px;'>"
            f"<span style='color: #856404; font-size: 11pt;'>"
            f"<b>⚠️ Nova atualização disponível!</b> A versão <b>{nova_versao}</b> foi lançada! "
            f"(Você está usando a v.{VERSAO_APP}). "
            f"<a href='{link}' style='color: #0056b3; text-decoration: none; font-weight: bold;'>BAIXAR NOVA VERSÃO</a>"
            f"</span>"
            f"</div>"
        )

        notas = notas_lancamento.replace('\r\n', '\n')
        while '\n\n\n' in notas:
            notas = notas.replace('\n\n\n', '\n\n')

        notas = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', notas)
        notas = re.sub(r'^- (.*)', r'• \1', notas, flags=re.MULTILINE)
        notas = re.sub(r'^#+ (.*)', r'<b>\1</b>', notas, flags=re.MULTILINE)

        if len(notas) > 1200:
            notas = notas[:1200] + "\n\n... (clique para ver as notas completas)"

        notas_formatadas = notas.replace('\n', '<br>')

        # Dica: adicionei um background na div interna para garantir que ela
        # não fique transparente em alguns temas do Windows
        tooltip_html = (
            f"<div style='width: 650px; font-size: 10pt; line-height: 1.2; font-family: Consolas, monospace; background-color: #ffffff; color: #000000; padding: 5px;'>"
            f"<span style='font-size: 11pt;'><b>O que há de novo na versão {nova_versao}:</b></span><hr>"
            f"{notas_formatadas}"
            f"</div>"
        )

        self.lbl_alerta_versao.setText(alerta_html)
        self.lbl_alerta_versao.show()

        # Guarda o texto da tooltip na própria label para podermos acessar depois
        self.lbl_alerta_versao.custom_tooltip_text = tooltip_html

        # Instala um filtro para ouvir quando o mouse entra na label
        self.lbl_alerta_versao.installEventFilter(self)

    def atualizar_tempo_total(self):
        if not self.processando or self.total_bytes_processar == 0:
            return

        decorrido = time.time() - self.tempo_inicio_total

        # Formatação do tempo decorrido
        horas_d, rem_d = divmod(decorrido, 3600)
        mins_d, segs_d = divmod(rem_d, 60)
        str_decorrido = f"{int(horas_d):02d}:{int(mins_d):02d}:{int(segs_d):02d}"

        # Cálculo do tempo restante baseado nos BYTES processados (alta precisão)
        if self.bytes_processados_total > 0:
            bytes_por_segundo = self.bytes_processados_total / decorrido
            bytes_restantes = self.total_bytes_processar - self.bytes_processados_total

            # Evita divisão por zero caso a leitura trave
            restante = bytes_restantes / bytes_por_segundo if bytes_por_segundo > 0 else 0

            horas_r, rem_r = divmod(restante, 3600)
            mins_r, segs_r = divmod(rem_r, 60)
            str_restante = f"{int(horas_r):02d}:{int(mins_r):02d}:{int(segs_r):02d}"
        else:
            str_restante = "Calculando..."

        self.lbl_progresso_total.setText(
            f"Progresso Total (Arquivos) - Decorrido: {str_decorrido} | Restante: {str_restante}"
        )

    def exportar_codigo_fonte(self):
        """Permite que o usuário salve uma cópia do script para auditoria forense"""
        try:
            # Se estiver rodando como .py, usa o __file__
            if sys.argv[0].endswith('.py'):
                caminho_origem = os.path.abspath(__file__)
            else:
                # No Nuitka Standalone, o arquivo .py estará na raiz da pasta do .exe
                diretorio_exe = os.path.dirname(os.path.abspath(sys.executable))
                caminho_origem = os.path.join(diretorio_exe, "extrator_hashes_metadados.py")

            if not os.path.exists(caminho_origem):
                QMessageBox.warning(self, "Aviso de Auditoria",
                    "O arquivo de código-fonte não foi localizado no pacote.\n"
                    "Certifique-se de que o arquivo 'extrator_hashes_metadados.py' está na pasta do programa.")
                return

            caminho_destino, _ = QFileDialog.getSaveFileName(
                self, "Exportar Código Fonte para Auditoria",
                "extrator_hashes_metadados_auditoria.py", "Python Script (*.py)"
            )

            if caminho_destino:
                import shutil
                shutil.copy(caminho_origem, caminho_destino)
                QMessageBox.information(self, "Sucesso", "Código-fonte exportado com sucesso para auditoria.")
        except Exception as e:
            QMessageBox.critical(self, "Erro", f"Falha ao exportar código: {e}")

    def _ativar_modo_admin_visual(self):
        self._titulo_original = self.windowTitle()
        self.setWindowTitle(self._titulo_original + "  |  MODO ADMINISTRADOR ATIVADO")

        # Define um ObjectName para a janela principal se ela ainda não tiver
        self.setObjectName("MainWindow")

        # Estilo geral da janela (Fundo vermelho e letras brancas para os botões/textos soltos)
        estilo_admin = """
                            #MainWindow { background-color: #4a0000; }
                            #MainWindow QLabel, #MainWindow QCheckBox, #MainWindow QPushButton, #MainWindow QGroupBox { color: #f0f0f0; }

                            QProgressBar {
                                border: 1px solid #7a0000;
                                background-color: #2a0000;
                                text-align: center;
                                color: #ffffff;
                                font-weight: bold;
                                border-radius: 4px;
                            }
                            QProgressBar::chunk {
                                background-color: #cc0000;
                            }
                        """
        self.setStyleSheet(estilo_admin)

        # Trata a caixa de texto grande (QTextEdit) individualmente para evitar conflito de prioridade de CSS
        self._estilo_texto_original = self.texto_saida.styleSheet()
        self.texto_saida.setStyleSheet(
            "background-color: #330000; color: #ffffff; font-family: Consolas; font-size: 10pt; border: 1px solid #7a0000;")

    def _desativar_modo_admin_visual(self):
        if hasattr(self, "_titulo_original"):
            self.setWindowTitle(self._titulo_original)

        # Remove o estilo global vermelho (volta para o padrão do Windows)
        self.setStyleSheet("")

        # Re-aplica o estilo padronizado com texto centralizado nas barras
        if hasattr(self, "estilo_barra_padrao"):
            self.barra_arquivo.setStyleSheet(self.estilo_barra_padrao)
            self.barra_total.setStyleSheet(self.estilo_barra_padrao)

        if hasattr(self, "_estilo_texto_original"):
            self.texto_saida.setStyleSheet(self._estilo_texto_original)

    def _temp_paths_raw(self):
        base = os.path.join(tempfile.gettempdir(), "ERS_IC_NIC_RAW_" + uuid.uuid4().hex)
        os.makedirs(base, exist_ok=True)
        out_json = os.path.join(base, "resultado.json")
        progress_json = os.path.join(base, "progresso.json")
        cancel_flag = os.path.join(base, "CANCELAR.flag")
        return out_json, progress_json, cancel_flag

    def _listar_unidades_windows(self):
        # Lista A:\ a Z:\ presentes (GetLogicalDrives)
        drives_mask = kernel32.GetLogicalDrives()
        out = []
        for i in range(26):
            if drives_mask & (1 << i):
                letter = chr(ord("A") + i)
                root = f"{letter}:\\"
                dtype = get_drive_type(root)
                out.append((letter, root, dtype))
        return out

    def _tipo_unidade_texto(self, dtype: int) -> str:
        return {
            DRIVE_REMOVABLE: "Removível (Pendrive/SD)",
            DRIVE_FIXED: "Fixo (HD/SSD)",
            DRIVE_CDROM: "CD/DVD",
            DRIVE_REMOTE: "Rede",
        }.get(dtype, "Desconhecido")

    def selecionar_unidade_raw(self):
        if self.processando:
            return

        if os.name != "nt":
            QMessageBox.warning(self, "Indisponível", "Hash RAW só está disponível no Windows.")
            return

        unidades = self._listar_unidades_windows()
        # filtra coisas inúteis
        unidades = [u for u in unidades if u[2] in (DRIVE_REMOVABLE, DRIVE_FIXED, DRIVE_CDROM)]

        if not unidades:
            QMessageBox.information(self, "Unidades", "Nenhuma unidade removível/fixa/CD detectada.")
            return

        # Dialog simples com combo
        dialog = QDialog(self)
        dialog.setWindowTitle("Selecionar unidade para HASH RAW")
        dialog.setMinimumWidth(500)

        layout = QVBoxLayout()
        combo = QComboBox()

        for letter, root, dtype in unidades:
            combo.addItem(f"{root}  -  {self._tipo_unidade_texto(dtype)}", (letter, root, dtype))

        layout.addWidget(QLabel("Escolha a unidade:"))
        layout.addWidget(combo)

        btns = QHBoxLayout()
        btn_ok = QPushButton("OK")
        btn_cancel = QPushButton("Cancelar")
        btn_ok.clicked.connect(dialog.accept)
        btn_cancel.clicked.connect(dialog.reject)
        btns.addWidget(btn_ok)
        btns.addWidget(btn_cancel)
        layout.addLayout(btns)

        dialog.setLayout(layout)
        if dialog.exec() != QDialog.Accepted:
            return

        letter, root, dtype = combo.currentData()
        info = obter_info_volume(root)

        # --- LIMPA A MENSAGEM INICIAL SE ELA FOR A ÚNICA COISA NA TELA ---
        if self.texto_saida.toPlainText().strip() == MENSAGEM_INICIAL:
            self.texto_saida.clear()
        # -----------------------------------------------------------------

        if info:
            self.texto_saida.append("=== UNIDADE SELECIONADA (RAW) ===")
            self.texto_saida.append(f"Letra: {info['unidade']}")
            self.texto_saida.append(f"Rótulo: {info['rotulo']}")
            self.texto_saida.append(f"Serial: {info['serial']}")
            self.texto_saida.append(f"FS: {info['sistema_arquivos']}")
            self.texto_saida.append("")

        # --- Diálogo customizado de UAC (Botões Centralizados) ---
        dialog_uac = QDialog(self)
        dialog_uac.setWindowTitle("Elevação de Privilégios")
        dialog_uac.setMinimumWidth(450)

        layout_uac = QVBoxLayout()

        # Texto de aviso
        lbl_aviso = QLabel(
            "A extração RAW requer acesso de baixo nível ao hardware da unidade.<br><br>"
            "<b>ATENÇÃO: será necessário solicitar elevação (UAC).</b><br><br>"
            "O modo administrador será desativado automaticamente ao final do processo."
        )
        lbl_aviso.setWordWrap(True)
        lbl_aviso.setStyleSheet("font-size: 10pt;")
        layout_uac.addWidget(lbl_aviso)

        layout_uac.addSpacing(15)

        # Layout dos botões com stretches nas laterais para centralizar
        layout_botoes = QHBoxLayout()
        btn_autorizar = QPushButton("Autorizar")
        btn_nao_autorizar = QPushButton("Não Autorizar")

        # Deixa os botões com um tamanho padrão mais bonito
        btn_autorizar.setMinimumWidth(120)
        btn_nao_autorizar.setMinimumWidth(120)

        # Adiciona uma cor leve ao botão de autorizar para destacá-lo
        btn_autorizar.setStyleSheet("font-weight: bold; background-color: #e0e0e0;")

        # Conecta os botões às ações de aceitar/rejeitar o diálogo
        btn_autorizar.clicked.connect(dialog_uac.accept)
        btn_nao_autorizar.clicked.connect(dialog_uac.reject)

        layout_botoes.addStretch()
        layout_botoes.addWidget(btn_autorizar)
        layout_botoes.addWidget(btn_nao_autorizar)
        layout_botoes.addStretch()

        layout_uac.addLayout(layout_botoes)
        dialog_uac.setLayout(layout_uac)

        # Se o usuário clicar em "Não Autorizar" ou fechar no "X" da janela
        if dialog_uac.exec() != QDialog.Accepted:
            return
        # ---------------------------------------------------------

        # Decide alvo (volume vs physical drive)
        volume_dev = drive_root_to_volume_device(root)  # Ex: \\.\I:
        device_path = volume_dev

        if dtype in (DRIVE_REMOVABLE, DRIVE_FIXED):
            # Cria um diálogo customizado para escolha clara do escopo
            dialog_escopo = QDialog(self)
            dialog_escopo.setWindowTitle("Escopo do Hash RAW (Perícia Forense)")
            dialog_escopo.resize(650, 350)
            layout_escopo = QVBoxLayout()

            lbl_info = QLabel("Escolha a metodologia de extração bit-a-bit:")
            lbl_info.setStyleSheet("font-weight: bold; font-size: 12pt; margin-bottom: 10px;")
            layout_escopo.addWidget(lbl_info)

            # TEXTO OPÇÃO 1
            lbl_titulo_disco = QLabel(
                "<b><span style='font-size: 12pt;'>OPÇÃO 1: Disco Físico Inteiro (\\\\.\\PhysicalDriveN)</span></b>")
            lbl_desc_disco = QLabel(
                "<b>O que faz:</b> Acesso irrestrito em nível de hardware. Lê a mídia de ponta a ponta, do primeiro ao último setor físico disponível.<br>"
                "<b>O que captura:</b> Tabelas de inicialização (MBR/GPT), todas as partições (visíveis, ocultas ou com sistemas desconhecidos), espaço não alocado e resíduos entre partições.<br>"
                "<b>Uso Forense:</b> Padrão-ouro para espelhamento pericial completo. Essencial para <i>Data Carving</i> e garantia de que nenhum byte foi deixado para trás."
            )
            lbl_desc_disco.setWordWrap(True)
            # Adicionado font-size: 11pt e margem inferior
            lbl_desc_disco.setStyleSheet("color: #333; font-size: 11pt; margin-bottom: 10px;")

            btn_disco = QPushButton("Selecionar Opção 1 (Hardware Completo)")
            btn_disco.setStyleSheet("padding: 8px; font-weight: bold; font-size: 11pt; background-color: #e0e0e0;")

            # TEXTO OPÇÃO 2
            lbl_titulo_volume = QLabel(
                f"<br><b><span style='font-size: 12pt;'>OPÇÃO 2: Apenas o Volume Lógico ({volume_dev})</span></b>")
            lbl_desc_volume = QLabel(
                "<b>O que faz:</b> Acesso lógico delimitado. Lê bit a bit exclusivamente dentro dos limites da partição selecionada pelo Windows.<br>"
                "<b>O que captura:</b> O sistema de arquivos (MFT/FAT), arquivos ativos, deletados recuperáveis, <i>File Slack</i> e espaço livre. <b>Ignora</b> o resto do disco.<br>"
                "<b>Uso Forense:</b> Ideal para triagem rápida. Metodologia recomendada para extrair o conteúdo 'em claro' de partições BitLocker após desbloqueio."
            )
            lbl_desc_volume.setWordWrap(True)
            # Adicionado font-size: 11pt
            lbl_desc_volume.setStyleSheet("color: #333; font-size: 11pt; margin-bottom: 10px;")

            btn_volume = QPushButton("Selecionar Opção 2 (Apenas Partição)")
            btn_volume.setStyleSheet("padding: 8px; font-weight: bold; font-size: 11pt; background-color: #e0e0e0;")

            # Lógica de seleção
            escolha = {"tipo": "volume"}

            def set_disco():
                escolha["tipo"] = "disco"
                dialog_escopo.accept()

            def set_volume():
                escolha["tipo"] = "volume"
                dialog_escopo.accept()

            btn_disco.clicked.connect(set_disco)
            btn_volume.clicked.connect(set_volume)

            # Montagem do Layout
            layout_escopo.addWidget(lbl_titulo_disco)
            layout_escopo.addWidget(lbl_desc_disco)
            layout_escopo.addWidget(btn_disco)

            layout_escopo.addWidget(lbl_titulo_volume)
            layout_escopo.addWidget(lbl_desc_volume)
            layout_escopo.addWidget(btn_volume)

            layout_escopo.addStretch()

            btn_cancelar_escopo = QPushButton("Cancelar Operação")
            btn_cancelar_escopo.clicked.connect(dialog_escopo.reject)
            layout_escopo.addWidget(btn_cancelar_escopo)

            dialog_escopo.setLayout(layout_escopo)

            if dialog_escopo.exec() != QDialog.Accepted:
                return

            if escolha["tipo"] == "disco":
                try:
                    disks = volume_to_physical_drives(volume_dev)
                    if not disks:
                        raise RuntimeError("Não foi possível mapear volume -> PhysicalDrive")
                    if len(disks) > 1:
                        QMessageBox.warning(self, "Aviso",
                                            f"Volume mapeado para múltiplos discos físicos: {disks}. Usando o primeiro.")
                    # noinspection PyUnusedLocal
                    device_path = r"\\.\PhysicalDrive{}".format(disks[0])
                    self._raw_metodo_escolhido = "Disco Físico Inteiro (Acesso direto ao Hardware)"

                except Exception as e:
                    QMessageBox.critical(self, "Erro Mapeamento",
                                         f"Falha ao obter PhysicalDrive (Erro: {e}).\n\nUsando o volume ({volume_dev}) como alternativa.")
                    device_path = volume_dev
                    # SALVA A ESCOLHA (FALLBACK)
                    self._raw_metodo_escolhido = "Volume Lógico (Fallback por falha no mapeamento físico)"
            else:
                device_path = volume_dev
                # SALVA A ESCOLHA (OPÇÃO 2)
                self._raw_metodo_escolhido = "Apenas Volume Lógico (Delimitado pelo S.O.)"

        else:
            # Se for CD-ROM, só tem uma opção
            self._raw_metodo_escolhido = "Leitura Direta da Mídia (CD/DVD)"

        # --- DIÁLOGO CUSTOMIZADO: AQUISIÇÃO DE IMAGEM FORENSE ---
        caminho_imagem = ""
        dialog_imagem = QDialog(self)
        dialog_imagem.setWindowTitle("Aquisição de Imagem Forense")
        dialog_imagem.setMinimumWidth(550)  # Aumentado levemente para acomodar a explicação

        layout_img = QVBoxLayout()

        # Texto de aviso principal
        lbl_aviso_img = QLabel(
            "Deseja também salvar uma cópia bit-a-bit (imagem .dd) desta unidade durante a extração do Hash?\n\n"
            "⚠️ ATENÇÃO: Você precisará de espaço livre no destino igual ou superior ao tamanho total da unidade de origem. "
            "NUNCA salve a imagem dentro da própria unidade que está sendo periciada."
        )
        lbl_aviso_img.setWordWrap(True)
        lbl_aviso_img.setStyleSheet("font-size: 10pt; font-weight: bold;")
        layout_img.addWidget(lbl_aviso_img)

        layout_img.addSpacing(15)

        # Layout dos botões centralizados
        layout_botoes_img = QHBoxLayout()
        btn_sim = QPushButton("SIM. Gere o HASH e a cópia bit-a-bit.")
        btn_nao = QPushButton("NÃO. Gere apenas o HASH.")

        btn_sim.setMinimumWidth(250)
        btn_nao.setMinimumWidth(200)

        # Conexões explícitas com inteiros
        btn_sim.clicked.connect(lambda: dialog_imagem.done(1))  # 1 = SIM
        btn_nao.clicked.connect(lambda: dialog_imagem.done(2))  # 2 = NÃO

        layout_botoes_img.addStretch()
        layout_botoes_img.addWidget(btn_sim)
        layout_botoes_img.addWidget(btn_nao)
        layout_botoes_img.addStretch()

        layout_img.addLayout(layout_botoes_img)

        # --- NOTA TÉCNICA SOBRE ABERTURA DE ARQUIVOS .DD ---
        layout_img.addSpacing(20)
        lbl_nota_tecnica = QLabel(
            "<div style='background-color: #f9f9f9; border: 1px solid #ddd; padding: 12px; border-radius: 5px; color: #333;'>"
            "<b>ℹ️ Nota Técnica sobre Montagem de Imagens RAW (.dd):</b><br><br>"
            "O uso de softwares como <b>Daemon Tools não é recomendado</b> para perícia. Ele foi projetado para "
            "emular mídias ópticas (ISO, MDS) e não interpreta corretamente tabelas de partição (MBR/GPT) ou sistemas "
            "de arquivos (NTFS, exFAT) embutidos em imagens de discos rígidos e pendrives.<br><br>"
            "Para preservar a integridade da evidência, utilize ferramentas que forcem o modo <b>Somente-Leitura (Read-Only)</b> "
            "e emulem o disco físico real. Sugestões:<br><br>"
            "• <b>Arsenal Image Mounter (AIM):</b> O padrão-ouro atual. A versão gratuita suporta emulação SCSI, ideal para volumes complexos e BitLocker.<br>"
            "• <b>FTK Imager:</b> Ferramenta totalmente gratuita e consolidada na comunidade forense que possui a opção 'Mount Image' nativa.<br>"
            "• <b>OSFMount:</b> Leve e versátil, permite montar a imagem RAW rapidamente, inclusive alocando-a em RAM "
            "se necessário para maior performance. É totalmente gratuita e consolidada na comunidade forense.<br>"
            "</div>"
        )
        lbl_nota_tecnica.setWordWrap(True)
        lbl_nota_tecnica.setStyleSheet("font-size: 9pt; color: #444;")
        layout_img.addWidget(lbl_nota_tecnica)

        dialog_imagem.setLayout(layout_img)

        # --- AVALIAÇÃO DA RESPOSTA DO USUÁRIO ---
        resultado_imagem = dialog_imagem.exec()

        # Se o usuário fechou a janela no 'X' (ausência de escolha)
        if resultado_imagem == 0:
            # 0 é o retorno padrão do PySide6 quando o usuário fecha a janela no "X"
            self.texto_saida.append("\n[!] Operação cancelada pelo usuário (Janela fechada).")
            return  # Aborta tudo e mantém no modo não-admin

        # Se o usuário clicar em "Sim"
        if resultado_imagem == 1:
            # Usuário clicou em SIM (Gere o HASH e a cópia)
            nome_da_imagem = f"imagem_forense_{info['serial'] if info else 'raw'}"

            # Laço para permitir que o usuário tente selecionar o destino novamente
            while True:
                # Pede para o usuário escolher APENAS UM DIRETÓRIO onde a nova pasta será criada
                diretorio_escolhido = QFileDialog.getExistingDirectory(
                    self,
                    f"Selecione o local para criar a pasta da evidência '{nome_da_imagem}'"
                )

                if diretorio_escolhido:
                    # LÓGICA DE DIRETÓRIO: Cria a pasta de evidência para agrupar o DD e o Log
                    pasta_evidencia = os.path.join(diretorio_escolhido, f"{nome_da_imagem}_evidencia")

                    os.makedirs(pasta_evidencia, exist_ok=True)

                    caminho_imagem = os.path.join(pasta_evidencia, f"{nome_da_imagem}.dd")
                    self.caminho_audit_log = os.path.join(pasta_evidencia, f"{nome_da_imagem}_auditoria.txt")

                    self._raw_metodo_escolhido += " + Geração de Imagem (.dd)"
                    break  # Saída do laço: caminho selecionado com sucesso
                else:
                    # O usuário cancelou a janela de escolher pasta, abre a segunda confirmação
                    dialog_cancela = QDialog(self)
                    dialog_cancela.setWindowTitle("Aviso - Destino não selecionado")
                    dialog_cancela.setMinimumWidth(450)

                    layout_cancela = QVBoxLayout()

                    lbl_aviso_cancela = QLabel(
                        "Nenhum destino selecionado para a imagem.\n\n"
                        "Deseja tentar selecionar um destino novamente ou continuar APENAS com a geração do Hash RAW?"
                    )
                    lbl_aviso_cancela.setWordWrap(True)
                    lbl_aviso_cancela.setStyleSheet("font-size: 10pt;")
                    layout_cancela.addWidget(lbl_aviso_cancela)
                    layout_cancela.addSpacing(15)

                    layout_botoes_cancela = QHBoxLayout()
                    btn_sim_cancela = QPushButton("Selecionar um destino\npara a cópia bit-a-bit.")
                    btn_nao_cancela = QPushButton("Gere apenas o HASH.")

                    btn_sim_cancela.clicked.connect(lambda: dialog_cancela.done(1))
                    btn_nao_cancela.clicked.connect(lambda: dialog_cancela.done(2))

                    layout_botoes_cancela.addStretch()
                    layout_botoes_cancela.addWidget(btn_sim_cancela)
                    layout_botoes_cancela.addWidget(btn_nao_cancela)
                    layout_botoes_cancela.addStretch()

                    layout_cancela.addLayout(layout_botoes_cancela)
                    dialog_cancela.setLayout(layout_cancela)

                    # --- CORREÇÃO AQUI: Tratamento do resultado da segunda janela ---
                    resultado_cancela = dialog_cancela.exec()

                    if resultado_cancela == 0:
                        # Fechou a segunda janela no 'X'
                        self.texto_saida.append("\n[!] Operação cancelada pelo usuário (Destino não selecionado).")
                        return
                    elif resultado_cancela == 1:
                        # Quer tentar escolher a pasta de novo
                        continue
                    elif resultado_cancela == 2:
                        # Desistiu de salvar a imagem, quer só o hash (sai do While)
                        break

        # Se resultado_imagem == 2 (clicou em NÃO na primeira tela), os IFs acima são ignorados
        # e o código flui direto para cá, executando apenas o Hash RAW.
        self._iniciar_raw_hash_elevado(device_path, caminho_imagem)

    def _iniciar_raw_hash_elevado(self, device_path: str, caminho_imagem: str = ""):
        lf, _ = try_acquire_raw_device_lock(device_path)
        if lf is None:
            QMessageBox.warning(self, "RAW em andamento",
                                f"Já existe uma aquisição RAW em andamento para: {device_path}")
            return
        # Se conseguiu, libera imediatamente (a trava real será no helper)
        release_raw_device_lock(lf)

        algos = [algo for algo, chk in self.chk_hashes.items() if chk.isChecked()]
        if not algos:
            QMessageBox.warning(self, "Algoritmos", "Selecione ao menos um algoritmo de hash.")
            return

        out_json, progress_json, cancel_flag = self._temp_paths_raw()

        self._raw_out_json = out_json
        self._raw_progress_json = progress_json
        self._raw_cancel_flag = cancel_flag
        self._raw_device = device_path

        # trava UI e ativa modo admin VISUAL enquanto o helper roda
        self.travar_interface()
        self.barra_total.setMaximum(100)
        self.barra_total.setValue(0)
        self.lbl_progresso_total.setText("Progresso RAW - Iniciando...")
        self._ativar_modo_admin_visual()
        self.cancelar_operacao = False
        self.btn_cancelar.setText("CANCELAR PROCESSAMENTO")
        self.btn_cancelar.setEnabled(True)

        rc = run_raw_helper_elevated(
            device_path=device_path,
            algos=algos,
            chunk_size=1024 * 1024,  # 1MB
            out_json_path=out_json,
            progress_json_path=progress_json,
            cancel_flag_path=cancel_flag,
            image_out_path=caminho_imagem
        )

        if rc <= 32:
            self._desativar_modo_admin_visual()
            self.destravar_interface()

            if rc == 5:
                QMessageBox.critical(self, "Acesso Negado",
                                     "Você não tem privilégios de administrador neste computador ou as credenciais falharam.")
            elif rc == 1223 or rc == 0:
                QMessageBox.warning(self, "Cancelado",
                                    "A operação foi cancelada pelo usuário no prompt do Windows (UAC).")
            else:
                QMessageBox.warning(self, "Erro", f"Falha ao iniciar o modo administrador. Código de erro: {rc}")
            return

        # Timer para acompanhar progresso/resultado
        self._raw_tempo_inicio = time.time()

        # Timer para acompanhar progresso/resultado
        self._raw_timer = QTimer(self)
        self._raw_timer.timeout.connect(self._poll_raw_hash_status)
        self._raw_timer.start(INTERVALO_ATUALIZACAO_BARRA_PREVISAO_PROGRESSO_TOTAL*1000)


    def _poll_raw_hash_status(self):
        QApplication.processEvents() # Permite que o programa registre o clique no botão "Cancelar"
        # 1) Progresso
        try:
            if hasattr(self, "_raw_progress_json") and os.path.exists(self._raw_progress_json):
                with open(self._raw_progress_json, "r", encoding="utf-8") as f:
                    p = json.load(f)
                pct = int(p.get("percent", 0))
                self.barra_arquivo.setValue(max(0, min(100, pct)))
                self.barra_total.setValue(max(0, min(100, pct)))
                self.lbl_progresso_arquivo.setText(f"RAW {pct}% - {self._raw_device}")

                bytes_read = p.get("bytes_read", 0)
                bytes_total = p.get("bytes_total", 0)

                if hasattr(self, "_raw_tempo_inicio"):
                    import time  # Certifique-se de que time está importado no topo do arquivo
                    decorrido = time.time() - self._raw_tempo_inicio

                    # Formata o tempo decorrido
                    horas_d, rem_d = divmod(decorrido, 3600)
                    mins_d, segs_d = divmod(rem_d, 60)
                    str_decorrido = f"{int(horas_d):02d}:{int(mins_d):02d}:{int(segs_d):02d}"

                    # Calcula o tempo restante
                    if bytes_read > 0 and decorrido > 0:
                        bytes_por_segundo = bytes_read / decorrido
                        bytes_restantes = bytes_total - bytes_read

                        restante = bytes_restantes / bytes_por_segundo if bytes_por_segundo > 0 else 0

                        horas_r, rem_r = divmod(restante, 3600)
                        mins_r, segs_r = divmod(rem_r, 60)
                        str_restante = f"{int(horas_r):02d}:{int(mins_r):02d}:{int(segs_r):02d}"
                    else:
                        str_restante = "Calculando..."

                    self.lbl_progresso_total.setText(
                        f"Progresso RAW - Decorrido: {str_decorrido} | Restante: {str_restante}"
                    )
        except Exception:
            pass

        # 2) Final
        if os.path.exists(self._raw_out_json):
            try:
                with open(self._raw_out_json, "r", encoding="utf-8") as f:
                    payload = json.load(f)
            except Exception as e:
                payload = {"ok": False, "error": f"Falha ao ler JSON final: {e}"}

            self._raw_timer.stop()

            self.btn_cancelar.setEnabled(False)
            self.btn_cancelar.setText("CANCELAR PROCESSAMENTO")

            self.texto_saida.append("=== HASH RAW (BIT-A-BIT) ===")
            if hasattr(self, '_raw_metodo_escolhido'):
                self.texto_saida.append(f"Metodologia: {self._raw_metodo_escolhido}")
            self.texto_saida.append(f"Dispositivo: {self._raw_device}")

            if payload.get("ok"):
                res = payload.get("result", {})
                str_bytes = f"Bytes lidos: {res.get('bytes_read')} / {res.get('bytes_total')}"
                self.texto_saida.append(str_bytes)

                hashes = res.get("hashes", {})
                texto_hashes = []
                for k, v in hashes.items():
                    texto_hashes.append(f"{k}: {v}")
                    self.texto_saida.append(f"{k}: {v}")

                # --- INTEGRAÇÃO: VALIDAÇÃO DA CADEIA DE CUSTÓDIA PARA RAW ---
                texto_custodia = self.texto_referencia.toPlainText().strip()
                if texto_custodia:
                    validador_raw = ValidadorCustodia(texto_custodia)
                    status, msg_custodia = validador_raw.validar_hash_simples(hashes)
                    self.texto_saida.append("")
                    self.texto_saida.append("=== VALIDAÇÃO DA CADEIA DE CUSTÓDIA ===")
                    self.texto_saida.append(msg_custodia)
                    self.texto_saida.append("")

                    # Adiciona a validação à lista de textos que vão para o Log físico (txt)
                    texto_hashes.append("")
                    texto_hashes.append("=== RESULTADO DA VALIDAÇÃO ===")
                    texto_hashes.append(msg_custodia)
                # ------------------------------------------------------------

                # Escreve o arquivo de auditoria físico (.txt)
                if hasattr(self, '_caminho_audit_log') and self._caminho_audit_log:
                    try:
                        with open(self._caminho_audit_log, "w", encoding="utf-8") as f_log:
                            f_log.write("=" * 55 + "\n")
                            f_log.write(f"LOG DE AUDITORIA FORENSE - {NOME_APP} - versão {VERSAO_APP}\n")
                            f_log.write("=" * 55 + "\n\n")
                            f_log.write(
                                f"Data/Hora Conclusão: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")

                            if hasattr(self, '_raw_metodo_escolhido'):
                                f_log.write(f"Metodologia: {self._raw_metodo_escolhido}\n")

                            f_log.write(f"Alvo da Extração: {self._raw_device}\n")
                            f_log.write(f"{str_bytes}\n\n")
                            f_log.write("CADEIA DE CUSTÓDIA - HASHE(S) DA IMAGEM:\n")
                            for linha in texto_hashes:
                                f_log.write(f" -> {linha}\n")
                            f_log.write("\n" + "=" * 55 + "\n")
                    except Exception as e:
                        self.texto_saida.append(f"\nERRO: Falha ao gerar arquivo de auditoria físico: {e}")
            else:
                self.texto_saida.append(f"ERRO: {payload.get('error')}")

            self.texto_saida.append("")
            self._desativar_modo_admin_visual()
            self.destravar_interface()
            self.barra_arquivo.setValue(0)
            self.barra_total.setValue(100)
            self.lbl_progresso_arquivo.setText("Progresso do Arquivo Atual")
            self.lbl_progresso_total.setText("Progresso RAW - Concluído!")

            # --- LIMPEZA DO DIRETÓRIO TEMPORÁRIO ---
            try:
                diretorio_temp = os.path.dirname(self._raw_out_json)
                if os.path.exists(diretorio_temp):
                    shutil.rmtree(diretorio_temp, ignore_errors=True)
                    if DEBUG_MESSAGES:
                        print(f"[DEBUG] Diretório temporário apagado: {diretorio_temp}")
            except Exception as e:
                if DEBUG_MESSAGES:
                    print(f"[DEBUG] Falha ao tentar apagar diretório temporário: {e}")
            # ---------------------------------------------

    def acao_cancelar(self):
        self.cancelar_operacao = True
        self.btn_cancelar.setText("CANCELANDO PROCESSAMENTO...")
        self.btn_cancelar.setEnabled(False)
        QApplication.processEvents()

        # Verifica se está em um processo de RAW Hash
        caminho_flag = getattr(self, "_raw_cancel_flag", None)
        if caminho_flag:
            if DEBUG_MESSAGES:
                print(f"[DEBUG] Tentando cancelar o RAW Hash. Caminho da flag: {caminho_flag}")

            try:
                # 1. Garante que o diretório exista
                os.makedirs(os.path.dirname(caminho_flag), exist_ok=True)

                # 2. Cria o arquivo forçando o modo de escrita 'w'
                with open(caminho_flag, "w", encoding="utf-8") as f:
                    f.write("CANCELAR")
                    f.flush()
                    os.fsync(f.fileno())  # Força sincronização de disco

                if DEBUG_MESSAGES:
                    print(f"[DEBUG] Arquivo flag criado fisicamente em: {caminho_flag}")
            except Exception as e:
                print(f"[ERRO CRÍTICO] Falha ao escrever flag de cancelamento: {e}")
                import traceback
                traceback.print_exc()
        else:
            if DEBUG_MESSAGES:
                print("[DEBUG] Nenhuma operação RAW em andamento para cancelar.")

    def closeEvent(self, event):
        """Salva as configurações atuais e limpa rastros ao fechar a janela."""
        config = {
            'chk_metadados': self.chk_metadados.isChecked(),
            'chk_subdiretorios': self.chk_subdiretorios.isChecked(),
            'hashes': {algo: chk.isChecked() for algo, chk in self.chk_hashes.items()}
        }
        salvar_config(config)

        # --- LIMPEZA DE RASTROS AO FECHAR ---
        self.limpar_arquivos_temporarios()

        event.accept()

    def limpar_arquivos_temporarios(self):
        """
        Varre a pasta Temp do Windows, cria flags de cancelamento e remove diretórios órfãos.
        Remove apenas temporários RAW antigos (>24h). NÃO cancela operações ativas.
        """
        try:
            diretorio_temp_so = tempfile.gettempdir()
            agora = time.time()
            limite = 24 * 3600  # 24h

            for item in os.listdir(diretorio_temp_so):
                if not item.startswith("ERS_IC_NIC_RAW_"):
                    continue

                caminho_completo = os.path.join(diretorio_temp_so, item)
                if not os.path.isdir(caminho_completo):
                    continue

                try:
                    mtime_dir = os.path.getmtime(caminho_completo)
                except Exception:
                    continue

                # Só apaga se for claramente "órfão/antigo"
                if (agora - mtime_dir) > limite:
                    shutil.rmtree(caminho_completo, ignore_errors=True)
        except Exception as e:
            if DEBUG_MESSAGES:
                print(f"[DEBUG] Erro ao executar limpeza global de temporários: {e}")

    def eventFilter(self, obj, event):
        # Verifica se o alvo é o checkbox de metadados, algum dos checkboxes de hash ou a label de alerta
        alvos_tooltip = [self.chk_metadados, self.lbl_alerta_versao] + list(self.chk_hashes.values())

        if obj in alvos_tooltip:
            # 1. Quando o mouse ENTRA (Ação imediata)
            if event.type() == QEvent.Type.Enter:
                from PySide6.QtGui import QCursor
                from PySide6.QtWidgets import QToolTip

                pos_mouse = QCursor.pos()

                # A) Se for o Tooltip de Nova Versão, exibe o HTML costumizado e empurra MUITO pra esquerda
                if obj == self.lbl_alerta_versao and hasattr(self.lbl_alerta_versao, 'custom_tooltip_text'):
                    pos_mouse.setX(pos_mouse.x() - 500)
                    pos_mouse.setY(pos_mouse.y() + 15)
                    QToolTip.showText(pos_mouse, self.lbl_alerta_versao.custom_tooltip_text, obj)
                    return True

                # B) Se for o tooltip GIGANTE de Metadados, empurra um pouco pra esquerda
                elif obj == self.chk_metadados:
                    pos_mouse.setX(pos_mouse.x() - 320)
                    pos_mouse.setY(pos_mouse.y() + 15)
                    QToolTip.showText(pos_mouse, obj.toolTip(), obj)
                    return True

                # C) Se for os de Hashes (menores), deixa perto do mouse e para a direita
                else:
                    pos_mouse.setX(pos_mouse.x() + 15)
                    pos_mouse.setY(pos_mouse.y() + 15)
                    QToolTip.showText(pos_mouse, obj.toolTip(), obj)
                    return True

            # 2. Quando o mouse SAI
            elif event.type() == QEvent.Type.Leave:
                from PySide6.QtWidgets import QToolTip
                QToolTip.hideText()
                return True

            # 3. Ignora o delay padrão do Windows
            elif event.type() == QEvent.Type.ToolTip:
                return True

        # Para todos os outros botões e eventos de tela, segue o comportamento normal
        return super().eventFilter(obj, event)

    def mostrar_sobre(self):
        dialog = QDialog(self)
        dialog.setWindowTitle(F"Funcionalidades Forenses, Licença e Termos de Uso - {NOME_APP} - v.{VERSAO_APP}")
        dialog.resize(800, 680)

        layout_principal = QVBoxLayout()

        # --- CABEÇALHO: ÍCONE + INFOS BÁSICAS (Fora das abas, visível sempre) ---
        layout_cabecalho = QHBoxLayout()

        # 1. Ícone do App - Usando QIcon para evitar desfoque
        lbl_icone = QLabel()
        if os.path.exists(ICON_PATH):
            # QIcon.pixmap busca a maior resolução no .ico para reduzir com qualidade
            pixmap = QIcon(ICON_PATH).pixmap(80, 80)
            lbl_icone.setPixmap(pixmap)
        layout_cabecalho.addWidget(lbl_icone)
        layout_cabecalho.addSpacing(20)

        # 2. Informações principais: Nome, Versão, Desenvolvedor e Contato
        lbl_infos_topo = QLabel(
            f"<div style='line-height: 140%;'>"
            f"<h2 style='margin-bottom: 2px;'>{NOME_APP}</h2>"
            f"<b>Versão:</b> {VERSAO_APP}<br>"
            f"<b>Desenvolvedor:</b> {DESENVOLVEDOR}<br>"
            f"<b>Contato / Reportar Bugs:</b> <a href='mailto:{EMAIL_CONTATO}'>{EMAIL_CONTATO}</a><br>"
            f"<b>Projeto e Atualizações:</b> <a href='{LINK_GITHUB}'>Repositório no GitHub</a>"
            f"</div>"
        )
        lbl_infos_topo.setOpenExternalLinks(True)
        layout_cabecalho.addWidget(lbl_infos_topo)
        layout_cabecalho.addStretch()
        layout_principal.addLayout(layout_cabecalho)

        # Linha Divisória
        linha = QFrame()
        linha.setFrameShape(QFrame.HLine)
        linha.setFrameShadow(QFrame.Sunken)
        layout_principal.addWidget(linha)

        # --- SISTEMA DE ABAS ---
        abas = QTabWidget()
        layout_principal.addWidget(abas)

        # ==============================================================
        # ABA 1: FUNCIONALIDADES E SEGURANÇA FORENSE (O SEU CÓDIGO ORIGINAL)
        # ==============================================================
        aba_sobre = QWidget()
        layout_sobre = QVBoxLayout(aba_sobre)
        layout_sobre.setContentsMargins(0, 0, 0, 0)  # Tira as bordas internas duplas

        # CORPO: TEXTO TÉCNICO COM ROLAGEM
        texto_sobre = QTextEdit()
        texto_sobre.setReadOnly(True)
        texto_sobre.setStyleSheet("background-color: #ffffff; font-size: 10pt; border: none;")

        # Descrição geral das funcionalidades da versão (Exatamente o seu HTML)
        conteudo_html = (
            "<p>Ferramenta pericial desenvolvida para extração rápida de hashes criptográficos e metadados de uma vasta gama de arquivos, "
            "além de permitir a <b>Aquisição Forense (Bit-a-bit)</b> de unidades lógicas e físicas, incluindo:</p>"
            "<ul>"
            "<li>Imagens, Áudios e Vídeos (Nativos e RAW)</li>"
            "<li>Documentos (PDF, Pacote Office, RTF)</li>"
            "<li>Executáveis e Atalhos do Windows (LNK)</li>"
            "<li>E-mails Exportados (EML, MSG)</li>"
            "<li>Arquivos Compactados (ZIP, RAR, 7Z) e Torrents</li>"
            "</ul>"
            "<p><i>Dica: Para visualizar a lista exata de todas as extensões analisadas, clique no botão <b>'Formatos Suportados'</b> na tela inicial.</i></p>"

            "<h3>🛡️ Segurança e Integridade Forense (Software Read-Only):</h3>"
            "<ul>"
            "<li><b>Acesso em Nível de Kernel:</b> Nas operações RAW, o software utiliza a flag <i>GENERIC_READ</i> da API do Windows, solicitando ao sistema operacional acesso estrito de leitura.</li>"
            "<li><b>Escrita Zero:</b> O software opera de forma estritamente unidirecional, sem enviar comandos de gravação ao dispositivo. Ressalta-se que esta proteção lógica <b>não substitui</b> o uso de bloqueadores de hardware (Write Blockers) para assegurar a integridade absoluta da prova contra alterações do sistema operacional.</li>"
            "<li><b>File Lock:</b> Arquivos individuais são travados durante a leitura (MSVCRT Locking) para evitar corrupção ou alteração do hash por processos paralelos.</li>"
            "<li><b>Detecção de Arquivos em Uso:</b> Tratamento seguro de exceções de permissão e travas do sistema, diferenciando arquivos abertos para leitura daqueles trancados exclusivamente pelo S.O.</li>"
            "<li><b>Isolamento de Nuvem (Anti-Download):</b> Detecta e bloqueia a leitura de arquivos 'Apenas Online' (OneDrive/Google Drive) marcados com <i>Recall on Data Access</i>, evitando alteração da evidência local e tráfego de rede.</li>"
            "<li><b>Seleção Literal (Anti-Redirecionamento):</b> A interface ignora as resoluções nativas do Windows para Links Simbólicos, Junções de Diretório e Atalhos, garantindo o hash estrito do item selecionado.</li>"
            "<li><b>Detecção de Arquivos Vazios:</b> Reconhecimento automático de hashes universalmente conhecidos (0 bytes) para todos os algoritmos.</li>"
            "<li><b>Tratamento Transparente de Erros:</b> Diferencia claramente bibliotecas ausentes, arquivos corrompidos e metadados intencionalmente removidos.</li>"
            "</ul>"

            "<h3>💾 Aquisição RAW e Imagem Forense (.dd):</h3>"
            "<ul>"
            "<li><b>Extração Setor-por-Setor:</b> Realiza a leitura sequencial completa da mídia, capturando dados ativos, remanescentes em espaços não alocados (Unallocated Space) e artefatos de arquivos deletados.</li>"
            "<li><b>Integridade On-the-Fly:</b> O cálculo dos hashes selecionados ocorre simultaneamente à leitura e gravação, garantindo a autenticidade da evidência sem a necessidade de reprocessamento da imagem gerada.</li>"
            "<li><b>Mapeamento de Hardware:</b> Capacidade de aquisição de discos físicos inteiros (incluindo tabelas MBR/GPT) ou volumes lógicos específicos, permitindo flexibilidade conforme a estratégia pericial.</li>"
            "<li><b>Documentação de Custódia:</b> Registro automático de metadados do hardware de origem e logs de auditoria detalhados para fundamentar a preservação da evidência em relatórios oficiais.</li>"
            "<li><b>Diagnóstico de Baixo Nível:</b> Sistema de tradução de códigos de erro do Windows para identificação clara de falhas físicas (como erros de CRC ou I/O) durante o processo de extração.</li>"
            "</ul>"

            "<h3>🔍 Análises Forenses Integradas:</h3>"
            "<ul>"
            "<li><b>Extração Profunda de Mídia (ExifTool + Fallbacks):</b> Usa múltiplas engenharias em cascata (ExifTool, OpenCV, TinyTag, Pillow) para vasculhar dados de geolocalização com link para mapas, resoluções internas, taxa de bits (bitrate) e até edições/muxing em arquivos de mídia.</li>"
            "<li><b>Detecção de Lavagem de Metadados (Metadata Stripping):</b> Análise heurística que identifica padrões de nomes de arquivos gerados pelo WhatsApp, Telegram, Instagram, Facebook e Twitter, emitindo alertas sobre metadados originais destruídos pela plataforma.</li>"
            "<li><b>Detecção NTFS ADS:</b> Varredura automática e em profundidade por Alternate Data Streams (dados ocultos em partições NTFS), identificando <i>Mark of the Web</i> e gerando comandos de extração para o PowerShell caso payloads maliciosos grandes sejam detectados.</li>"
            "<li><b>Entropia de Shannon:</b> Cálculo de aleatoriedade para detecção de arquivos criptografados, compactados ou ofuscados (Packed).</li>"
            "<li><b>Metadados Avançados:</b> Extração de coordenadas GPS (com links para mapas), datas internas de criação, marcas de dispositivos e rastreios de autoria/edição de software.</li>"
            "<li><b>Validação de Assinatura e Binários:</b> Checagem de certificados Authenticode em executáveis (EXE/DLL/SYS) e extração do Data/Hora exata de compilação registrada no cabeçalho PE.</li>"
            "</ul>"
            
            "<h3>🔗 Validação Automática da Cadeia de Custódia:</h3>"
            "<ul>"
            "<li><b>Conferência de Listagens de Hashes:</b> Permite o <i>Drag & Drop</i> (arrastar e soltar) de laudos e listagens de hashes de origem (nos formatos PDF, DOCX, XLSX, TXT) ou inserção de texto livre, para auditar a extração feita pelo responsável pela coleta original dos dados e preservar intacta a Cadeia de Custódia.</li>"
            "<li><b>Limpeza Forense de Texto:</b> Motor de extração blindado contra sujeiras de formatação e artefatos visuais de PDFs (como espaços invisíveis e quebras de linha fantasmas), garantindo a leitura exata do nome e do hash.</li>"
            "<li><b>Busca Heurística Inteligente:</b> O algoritmo rastreia o texto (na mesma linha ou em linhas anteriores) para associar o hash ao nome correto do arquivo. Exclusivamente para laudos em PDF, a ferramenta aciona uma busca bidirecional (progressiva) para compensar quebras irregulares de página, sempre utilizando 'barreiras de algoritmo' para evitar falsos positivos.</li>"
            "<li><b>Rastreabilidade (A Prova da Prova):</b> Ao arrastar um arquivo de referência, a ferramenta calcula e registra no relatório final o hash SHA-256 do próprio documento utilizado para a conferência, amarrando a auditoria.</li>"
            "<li><b>Alerta de CRC32:</b> Hashes CRC32 eventualmente presentes nos laudos de referência são intencionalmente ignorados no cruzamento de dados para evitar falsos positivos (por colidirem com datas ou números sequenciais em texto plano).</li>"
            "</ul>"

            "<h3>🔓 Transparência, Velocidade e Auditoria:</h3>"
            "<ul>"
            "<li><b>Compilação em Código Nativo:</b> Graças ao backend em C, os tempos de leitura em lote e cálculo de hashes simultâneos são rigorosamente mais rápidos que aplicações comuns.</li>"
            "<li><b>Atualizações Seguras:</b> Conta com uma rotina em thread separada que comunica-se passivamente com a API do GitHub apenas para alertar o analista sobre novas versões, preservando a estabilidade da interface principal.</li>"
            "<li><b>Código Aberto:</b> Em conformidade com as boas práticas forenses, o algoritmo de processamento é aberto para auditoria através do botão 'Baixar Código Fonte para Auditoria (.py)' abaixo.</li>"
            f"<li><b>Assinatura Digital do Código (SHA-256):</b> Este hash valida a integridade do arquivo 'extrator_hashes_metadados.py' incluído neste pacote (mesmo usado para a compilação desta versão {VERSAO_APP}).<br>"
            f"<code style='color: #d9534f; background-color: #f9f2f4; padding: 2px 4px; border-radius: 4px; font-family: Consolas;'>{HASH_DO_CODIGO_FONTE}</code></li>"
            "</ul>"

            "<h3>⚙️ Requisitos de Sistema:</h3>"
            "<ul>"
            "<li><b>Arquitetura:</b> Exclusivo para Windows 64-bits (x64). Sistemas 32-bits (x86) não são suportados devido a limitações de endereçamento de memória na aquisição forense RAW.</li>"
            "<li><b>Privilégios:</b> Execução padrão como Usuário Comum. Privilégios de Administrador (UAC) são solicitados sob demanda apenas durante a extração de discos físicos.</li>"
            "</ul>"
        )

        texto_sobre.setHtml(conteudo_html)
        layout_sobre.addWidget(texto_sobre)
        abas.addTab(aba_sobre, "Funcionalidades Forenses")

        # ==============================================================
        # ABA 2: TERMOS DE USO E LICENÇA
        # ==============================================================
        aba_licenca = QWidget()
        layout_licenca = QVBoxLayout(aba_licenca)
        layout_licenca.setContentsMargins(0, 0, 0, 0)

        texto_licenca_ui = QTextEdit()
        texto_licenca_ui.setPlainText(TEXTO_LICENCA)  # A variável global criada antes
        texto_licenca_ui.setReadOnly(True)
        # Um fundo ligeiramente diferente para destacar que é um documento legal
        texto_licenca_ui.setStyleSheet(
            "background-color: #f8f9fa; color: #333; font-family: Consolas, monospace; font-size: 10pt; border: none; padding: 10px;")

        layout_licenca.addWidget(texto_licenca_ui)
        abas.addTab(aba_licenca, "Licença e Termos de Uso")

        # --- RODAPÉ ---
        layout_botoes = QHBoxLayout()
        btn_audit = QPushButton("📂 Baixar Código Fonte para Auditoria (.py)")
        btn_audit.setMinimumHeight(35)
        btn_audit.setStyleSheet("font-weight: bold; color: #005a9e;")
        btn_audit.clicked.connect(self.exportar_codigo_fonte)

        # Botão para fechar
        btn_fechar = QPushButton("Fechar")
        btn_fechar.setMinimumHeight(35)
        btn_fechar.clicked.connect(dialog.accept)

        layout_botoes.addWidget(btn_audit)
        layout_botoes.addStretch()
        layout_botoes.addWidget(btn_fechar)
        layout_principal.addLayout(layout_botoes)

        dialog.setLayout(layout_principal)
        dialog.exec()

    def mostrar_formatos(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Formatos Suportados para Metadados Básicos")
        dialog.resize(600, 550)

        layout = QVBoxLayout()

        texto_formatos = QTextEdit()
        texto_formatos.setReadOnly(True)
        texto_formatos.setStyleSheet("background-color: #ffffff; font-size: 10pt;")

        conteudo_html = f"""
            <h2>Formatos Suportados para Extração de Metadados Básicos</h2>
            <p>A ferramenta utiliza o <b>ExifTool</b> e bibliotecas nativas para analisar os seguintes arquivos:</p>

            <h3>📷 Imagens</h3>
            <p>{', '.join([ext.upper() for ext in FORMATOS_IMAGEM])}</p>
            
            <h3>🎬 Vídeos</h3>
            <p>{', '.join([ext.upper() for ext in FORMATOS_VIDEO])}</p>
            
            <h3>🎵 Áudios</h3>
            <p>{', '.join([ext.upper() for ext in FORMATOS_AUDIO])}</p>
            
            <h3>📄 Documentos e Outros (Análise Nativa/Heurística)</h3>
            <p>{', '.join([ext.upper() for ext in FORMATOS_GERAIS])}</p>
        """

        texto_formatos.setHtml(conteudo_html)
        layout.addWidget(texto_formatos)

        btn_fechar = QPushButton("Fechar")
        btn_fechar.clicked.connect(dialog.accept)
        layout.addWidget(btn_fechar)

        dialog.setLayout(layout)
        dialog.exec()

    def travar_interface(self):
        self.processando = True
        self.btn_arquivo.setEnabled(False)
        self.btn_diretorio.setEnabled(False)
        self.chk_subdiretorios.setEnabled(False)
        self.btn_unidade_raw.setEnabled(False)
        self.chk_metadados.setEnabled(False)
        self.btn_limpar.setEnabled(False)
        self.btn_copiar.setEnabled(False)
        self.btn_formatos.setEnabled(False)
        self.btn_sobre.setEnabled(False)
        self.setAcceptDrops(False)
        self.btn_salvar.setEnabled(False)
        self.texto_referencia.setEnabled(False)
        self.btn_limpar_custodia.setEnabled(False)

        for chk in self.chk_hashes.values():
            chk.setEnabled(False)

    def destravar_interface(self):
        self.processando = False
        self.btn_arquivo.setEnabled(True)
        self.btn_diretorio.setEnabled(True)
        self.chk_subdiretorios.setEnabled(True)
        self.btn_unidade_raw.setEnabled(True)
        self.chk_metadados.setEnabled(True)
        self.btn_limpar.setEnabled(True)
        self.btn_copiar.setEnabled(True)
        self.btn_formatos.setEnabled(True)
        self.btn_sobre.setEnabled(True)
        self.setAcceptDrops(True)
        self.btn_salvar.setEnabled(True)
        self.texto_referencia.setEnabled(True)
        self.btn_limpar_custodia.setEnabled(True)

        for chk in self.chk_hashes.values():
            chk.setEnabled(True)

    # --- EXTRAÇÃO AVANÇADA DE METADADOS ---
    def obter_metadados_avancados(self, caminho_arquivo):
        """Distribui o arquivo para o extrator correto baseado na extensão."""
        metadados_extras = []
        extensao = caminho_arquivo.lower().split('.')[-1]

        # --- DETECÇÃO DE ADS (Roda para todos os arquivos) ---
        streams = detectar_ads_windows(caminho_arquivo)
        if streams:
            metadados_extras.extend(streams)
        # -----------------------------------------------------

        # --- ANÁLISE HEURÍSTICA DE NOME DE ARQUIVO (LAVAGEM DE METADADOS) ---
        nome_base = os.path.basename(caminho_arquivo).lower()
        plataforma_detectada = None

        if "whatsapp" in nome_base or nome_base.startswith("aud-") or nome_base.startswith("ptt-"):
            plataforma_detectada = "WhatsApp"
        elif "telegram" in nome_base:
            plataforma_detectada = "Telegram"
        elif "instagram" in nome_base:
            plataforma_detectada = "Instagram"
        elif "fb_img" in nome_base or "received_" in nome_base:
            plataforma_detectada = "Facebook/Messenger"
        elif "twimg" in nome_base or "twitter" in nome_base:
            plataforma_detectada = "Twitter/X"

        if plataforma_detectada:
            metadados_extras.append(
                f"⚠️ ALERTA: Padrão de nomenclatura do {plataforma_detectada} detectado no título.")
            metadados_extras.append(
                f"   ↳ Nota: A plataforma {plataforma_detectada} realiza 'Metadata Stripping' (Lavagem de Metadados).")
            metadados_extras.append(
                f"   ↳ Dados originais como Câmera, GPS e Data de Criação interna são destruídos em envios via {plataforma_detectada}.")
        # --------------------------------------------------------------------

        # 1. IMAGENS (Todos os formatos visuais/imagem suportados pelo ExifTool + fallback do Pillow)
        if extensao in FORMATOS_IMAGEM:
            caminho_exiftool = obter_caminho_exiftool()
            usou_exiftool = False

            max_wait_time = 15

            # --- TENTATIVA 1: ExifTool (Forense e Completo) ---
            if caminho_exiftool:
                try:
                    # O parâmetro -c "%+.6f" força o GPS a sair em graus decimais prontos para mapas.
                    cmd = [caminho_exiftool, "-j", "-G", "-c", "%+.6f", caminho_arquivo]

                    processo = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=max_wait_time,
                        creationflags=0x08000000 if os.name == 'nt' else 0
                    )

                    if processo.returncode == 0:
                        dados_json = json.loads(processo.stdout)
                        if dados_json:
                            meta = dados_json[0]
                            usou_exiftool = True

                            # Resolução e Formato
                            largura = meta.get('File:ImageWidth') or meta.get('Composite:ImageWidth') or meta.get(
                                'EXIF:ExifImageWidth')
                            altura = meta.get('File:ImageHeight') or meta.get('Composite:ImageHeight') or meta.get(
                                'EXIF:ExifImageHeight')
                            if largura and altura:
                                metadados_extras.append(f"Resolução: {largura}x{altura} pixels")

                            formato = meta.get('File:FileType')
                            if formato:
                                metadados_extras.append(f"Formato: {formato}")

                            dpi_x = meta.get('EXIF:XResolution') or meta.get('IFD0:XResolution')
                            dpi_y = meta.get('EXIF:YResolution') or meta.get('IFD0:YResolution')
                            if dpi_x and dpi_y:
                                metadados_extras.append(f"DPI: {int(dpi_x)}x{int(dpi_y)}")
                            else:
                                metadados_extras.append("DPI: Não especificado (Padrão: 96x96)")

                            # Dados Forenses (Dispositivo e Data)
                            marca = meta.get('IFD0:Make') or meta.get('EXIF:Make')
                            modelo = meta.get('IFD0:Model') or meta.get('EXIF:Model')
                            if modelo:
                                disp = f"{marca} {modelo}" if marca else modelo
                                metadados_extras.append(f"📷 Dispositivo (EXIF): {disp.strip()}")

                            data_captura = meta.get('EXIF:DateTimeOriginal') or meta.get('IFD0:ModifyDate')
                            if data_captura:
                                fuso = meta.get('EXIF:OffsetTimeOriginal') or meta.get('EXIF:OffsetTime')
                                if fuso:
                                    metadados_extras.append(
                                        f"⏱️ Data de Captura (EXIF): {data_captura} (Fuso: {fuso})")
                                else:
                                    metadados_extras.append(f"⏱️ Data de Captura (EXIF): {data_captura}")

                            software = meta.get('IFD0:Software') or meta.get('EXIF:Software') or meta.get(
                                'XMP:CreatorTool')
                            if software:
                                metadados_extras.append(f"💻 Software/Editor: {software}")

                            # Coordenadas GPS
                            gps_lat = meta.get('Composite:GPSLatitude')
                            gps_lon = meta.get('Composite:GPSLongitude')
                            if gps_lat and gps_lon:
                                try:
                                    # Como passamos -c "%+.6f", o valor já vem como string pronta "+23.553889"
                                    lat_float = float(gps_lat)
                                    lon_float = float(gps_lon)
                                    link_maps = f"https://www.google.com/maps/search/?api=1&query={lat_float:.6f},{lon_float:.6f}"
                                    metadados_extras.append(
                                        f"📍 GPS (Latitude, Longitude): {lat_float:.6f}, {lon_float:.6f}")
                                    metadados_extras.append(f"   ↳ Visualizar no Mapa: {link_maps}")
                                except ValueError:
                                    # Fallback se vier algum formato estranho
                                    metadados_extras.append(f"📍 GPS (Bruto): {gps_lat}, {gps_lon}")

                except subprocess.TimeoutExpired:
                    metadados_extras.append(f"⚠️ ExifTool abortado: Timeout ao ler imagem (mais de {str(max_wait_time)}s).")
                except Exception as e:
                    metadados_extras.append(f"⚠️ Erro ao ler metadados da imagem com ExifTool: {e}")

            else:
                # SE O EXIFTOOL NÃO FOR ENCONTRADO, AVISA IMEDIATAMENTE.
                pasta_esperada = "exiftool-13.51_64" if sys.maxsize > 2 ** 32 else "exiftool-13.51_32"
                metadados_extras.append(
                    f"⚠️ ExifTool ausente: O programa exige a pasta '{pasta_esperada}' no diretório do executável para extrair GPS e datas reais.")

            # --- TENTATIVA 2: Fallback para o Pillow (Se o ExifTool falhar ou não existir) ---
            if not usou_exiftool:
                if HAS_PIL:
                    try:
                        with Image.open(caminho_arquivo) as img:
                            metadados_extras.append(f"Resolução (Pillow): {img.width}x{img.height} pixels")
                            metadados_extras.append(f"Formato (Pillow): {img.format}")
                            metadados_extras.append(f"Modo de Cor: {img.mode}")
                    except Exception as e:
                        metadados_extras.append(f"⚠️ Erro ao ler metadados com Pillow: {e}")
                else:
                    metadados_extras.append(
                        "⚠️ Biblioteca Pillow (PIL) ausente: Não foi possível realizar a leitura secundária da imagem.")

        # 2. VÍDEOS (Busca Abrangente Universal)
        elif extensao in FORMATOS_VIDEO:

            # --- PARTE 1: OpenCV (Dados Estruturais) ---
            if HAS_CV2:
                try:
                    cap = cv2.VideoCapture(caminho_arquivo)
                    if cap.isOpened():
                        largura = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
                        altura = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
                        fps = cap.get(cv2.CAP_PROP_FPS)
                        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))

                        if largura > 0 and altura > 0:
                            metadados_extras.append(f"Resolução do Vídeo: {largura}x{altura}")
                        if fps > 0:
                            metadados_extras.append(f"FPS: {fps:.3f}")
                            if total_frames > 0:
                                # Adiciona a contagem exata de frames
                                metadados_extras.append(f"Total de Frames: {total_frames}")

                                # Calcula a duração com precisão de milissegundos
                                duracao = total_frames / fps
                                mins, secs = divmod(duracao, 60)
                                horas, mins = divmod(mins, 60)

                                # Extrai a parte fracionária dos segundos e converte para milissegundos
                                milisegundos = int(round((duracao - int(duracao)) * 1000))

                                metadados_extras.append(
                                    f"Duração Calculada (via FPS): {int(horas):02d}h{int(mins):02d}min{int(secs):02d},{milisegundos:03d}s")
                        cap.release()
                    else:
                        metadados_extras.append(
                            "⚠️ OpenCV falhou ao abrir o vídeo (Formato não suportado nativamente ou arquivo corrompido).")
                except Exception as e:
                    metadados_extras.append(f"⚠️ Erro ao processar estrutura do vídeo com OpenCV: {e}")
            else:
                metadados_extras.append(
                    "⚠️ Biblioteca OpenCV (cv2) ausente: Impossível extrair resolução e duração estimadas nativamente.")

            # --- PARTE 2: ExifTool (Metadados Dinâmicos) ---
            caminho_exiftool = obter_caminho_exiftool()
            if caminho_exiftool:
                try:
                    cmd = [caminho_exiftool, "-j", "-G", "-c", "%+.6f", caminho_arquivo]
                    processo = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=15,
                        creationflags=0x08000000 if os.name == 'nt' else 0
                    )

                    if processo.returncode == 0:
                        dados_json = json.loads(processo.stdout)
                        if dados_json:
                            meta = dados_json[0]

                            # Função auxiliar para buscar qualquer tag que termine com palavras-chave (ignora se é QuickTime, Matroska, RIFF, etc)
                            def buscar_tag_dinamica(dicionario, sufixos):
                                for chave, valor in dicionario.items():
                                    if any(chave.endswith(f":{s}") or chave == s for s in sufixos):
                                        return valor
                                return None

                            # 1. Data de Criação (Varre os nomes mais comuns em todos os formatos)
                            data_criacao = buscar_tag_dinamica(meta,
                                                               ['CreateDate', 'DateTimeOriginal', 'CreationDate',
                                                                'MediaCreateDate', 'DateTime'])
                            if data_criacao:
                                if str(data_criacao).startswith("0000:00:00"):
                                    metadados_extras.append(
                                        f"⏱️ Data de Criação (Interna): {data_criacao} [Zerada / Lavada]")
                                else:
                                    metadados_extras.append(f"⏱️ Data de Criação (Interna): {data_criacao}")

                            # 2. Dispositivo de Gravação (Marca e Modelo)
                            marca = buscar_tag_dinamica(meta, ['Make'])
                            modelo = buscar_tag_dinamica(meta, ['Model', 'CameraModelName'])
                            if modelo:
                                disp = f"{marca} {modelo}" if marca else modelo
                                metadados_extras.append(f"📷 Dispositivo de Gravação: {disp.strip()}")

                            # 3. Coordenadas GPS (Otimizado com Link)
                            gps = buscar_tag_dinamica(meta, ['GPSPosition', 'GPSCoordinates'])
                            if gps:
                                try:
                                    partes = gps.split(',')
                                    if len(partes) == 2:
                                        lat = partes[0].strip()
                                        lon = partes[1].strip()
                                        link_maps = f"https://www.google.com/maps/search/?api=1&query={lat},{lon}"
                                        metadados_extras.append(f"📍 GPS (Vídeo): {lat}, {lon}")
                                        metadados_extras.append(f"   ↳ Visualizar no Mapa: {link_maps}")
                                    else:
                                        metadados_extras.append(f"📍 GPS (Vídeo): {gps}")
                                except Exception:
                                    metadados_extras.append(f"📍 GPS (Vídeo): {gps}")

                            # 4. Software de Edição / Criação
                            software = buscar_tag_dinamica(meta,
                                                           ['Software', 'CreatorTool', 'WritingApp', 'MuxingApp'])
                            if software:
                                metadados_extras.append(f"💻 Software/Muxer: {software}")

                            # 5. --- VERIFICAÇÃO DE FAIXAS DE MÍDIA ---
                            tem_audio = any('audio' in k.lower() for k in meta.keys())
                            tem_video = any('video' in k.lower() or 'image' in k.lower() for k in meta.keys())

                            faixas = []
                            if tem_video: faixas.append("Vídeo 🎬")
                            if tem_audio: faixas.append("Áudio 🎵")

                            if faixas:
                                metadados_extras.append(f"Faixas Presentes no Arquivo: {' + '.join(faixas)}")
                            else:
                                metadados_extras.append(
                                    "Faixas Presentes no Arquivo: Nenhuma faixa estruturada detectada.")
                    else:
                        erro_oculto = processo.stderr.strip() if processo.stderr else "Falha interna."
                        metadados_extras.append(f"⚠️ ExifTool falhou ao executar. Erro: {erro_oculto}")

                except subprocess.TimeoutExpired:
                    metadados_extras.append("⚠️ Metadados avançados abortados: Timeout do ExifTool (>15s).")
                except Exception as e:
                    metadados_extras.append(f"⚠️ Erro ao ler metadados com ExifTool: {e}")
            else:
                pasta_esperada = "exiftool-13.51_64" if sys.maxsize > 2 ** 32 else "exiftool-13.51_32"
                metadados_extras.append(
                    f"⚠️ ExifTool ausente (Esperado: '{pasta_esperada}'). Metadados internos indisponíveis.")

        # 3. PDFs
        elif extensao in FORMATOS_PDF:
            if HAS_PYPDF:
                try:
                    reader = PdfReader(caminho_arquivo)
                    metadados_extras.append(f"Total de Páginas: {len(reader.pages)}")
                    meta = reader.metadata

                    extraiu_algo = False
                    if meta:
                        if meta.title:
                            metadados_extras.append(f"Título: {meta.title}")
                            extraiu_algo = True
                        if meta.author:
                            metadados_extras.append(f"Autor: {meta.author}")
                            extraiu_algo = True
                        if meta.creator:
                            metadados_extras.append(f"Criador/Software: {meta.creator}")
                            extraiu_algo = True

                    if not extraiu_algo:
                        metadados_extras.append("ℹ️ Metadados de Autoria ou Título não localizados neste PDF.")

                except Exception as e:
                    metadados_extras.append(f"⚠️ Erro ao tentar processar PDF com pypdf: {e}")
            else:
                metadados_extras.append(
                    "⚠️ Biblioteca pypdf ausente: Não foi possível extrair os metadados do PDF.")

        # 4. PACOTE OFFICE (docx, xlsx, pptx) - Lendo direto do XML interno sem bibliotecas extras
        elif extensao in FORMATOS_OFFICE_XML:
            try:
                with zipfile.ZipFile(caminho_arquivo, 'r') as z:
                    if 'docProps/core.xml' in z.namelist():
                        conteudo_xml = z.read('docProps/core.xml')
                        root = ET.fromstring(conteudo_xml)
                        extraiu_algo = False

                        # Namespaces usados nos arquivos Office
                        ns = {
                            'dc': 'http://purl.org/dc/elements/1.1/',
                            'cp': 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties'
                        }

                        criador = root.find('.//dc:creator', ns)
                        modificador = root.find('.//cp:lastModifiedBy', ns)
                        titulo = root.find('.//dc:title', ns)

                        if criador is not None and criador.text:
                            metadados_extras.append(f"Autor (Office): {criador.text}")
                            extraiu_algo = True
                        if modificador is not None and modificador.text:
                            metadados_extras.append(f"Último a Modificar (Office): {modificador.text}")
                            extraiu_algo = True
                        if titulo is not None and titulo.text:
                            metadados_extras.append(f"Título Interno (Office): {titulo.text}")
                            extraiu_algo = True

                        if not extraiu_algo:
                            metadados_extras.append(
                                "ℹ️ Metadados de autoria (Office XML) não localizados ou removidos.")
                    else:
                        metadados_extras.append(
                            "⚠️ Arquivo Office inválido: A estrutura XML esperada (docProps/core.xml) não foi encontrada.")


            except zipfile.BadZipFile:
                metadados_extras.append(
                    "⚠️ Erro ao ler Office: O arquivo está corrompido ou não é um ZIP válido (arquivos .docx/.xlsx/.pptx são ZIPs internamente).")
            except ET.ParseError:
                metadados_extras.append("⚠️ Erro ao ler Office: O XML de metadados está malformado ou corrompido.")
            except Exception as e:
                metadados_extras.append(f"⚠️ Erro ao tentar processar metadados XML do Office: {e}")


        # 5. PACOTE OFFICE LEGADO (doc, xls, ppt)
        elif extensao in FORMATOS_OFFICE_LEGADO:
            if HAS_OLEFILE:
                try:
                    if olefile.isOleFile(caminho_arquivo):
                        with olefile.OleFileIO(caminho_arquivo) as ole:
                            meta = ole.get_metadata()
                            extraiu_algo = False

                            # olefile pode retornar bytes ou strings. isto é tratado aqui
                            def decodificar(valor):
                                if isinstance(valor, bytes):
                                    return valor.decode('utf-8', errors='ignore')
                                return str(valor) if valor else None

                            autor = decodificar(meta.author)
                            modificador = decodificar(meta.last_saved_by)
                            titulo = decodificar(meta.title)

                            if autor and autor != "None":
                                metadados_extras.append(f"Autor (Legacy): {autor}")
                                extraiu_algo = True
                            if modificador and modificador != "None":
                                metadados_extras.append(f"Último a Modificar (Legacy): {modificador}")
                                extraiu_algo = True
                            if titulo and titulo != "None":
                                metadados_extras.append(f"Título Interno (Legacy): {titulo}")
                                extraiu_algo = True

                            if not extraiu_algo:
                                metadados_extras.append(
                                    "ℹ️ Metadados avançados (título, autoria) não localizados ou arquivo lavado.")
                    else:
                        metadados_extras.append("⚠️ O arquivo possui extensão legada, mas não é um formato OLE válido.")
                except Exception as e:
                    metadados_extras.append(f"⚠️ Erro ao ler o arquivo Office legado: {e}")
            else:
                metadados_extras.append(
                    "⚠️ Biblioteca ausente: O módulo 'olefile' não foi encontrado. Impossível analisar arquivos do Office 97-2003.")

        # 6. ATALHOS DO WINDOWS (.lnk)
        elif extensao in FORMATOS_ATALHOS:
            if HAS_LNKPARSE:
                try:
                    with open(caminho_arquivo, 'rb') as indata:
                        lnk = LnkParse3.lnk_file(indata)
                        extraiu_algo = False

                        # A forma mais segura e à prova de falhas: extrair tudo como Dicionário (JSON)
                        dados = lnk.get_json()

                        # 1. Caminhos Locais e Dados do Disco (Pendrive/HD)
                        info_link = dados.get('link_info', {})
                        if info_link:
                            caminho_base = info_link.get('local_base_path')
                            if caminho_base:
                                metadados_extras.append(f"Caminho Alvo (Local): {caminho_base}")
                                extraiu_algo = True

                            # Os dados do disco ficam dentro de 'location_info'
                            loc_info = info_link.get('location_info', {})
                            if loc_info:
                                vol_label = loc_info.get('volume_label')
                                if vol_label:
                                    metadados_extras.append(f"Rótulo do Volume: {vol_label}")
                                    extraiu_algo = True

                                serial = loc_info.get('drive_serial_number')
                                if serial:
                                    # Formata o serial para Hexadecimal maiúsculo se for número inteiro
                                    if isinstance(serial, int):
                                        serial_fmt = hex(serial).upper().replace('0X', '')
                                    else:
                                        serial_fmt = str(serial).upper()
                                    metadados_extras.append(f"Serial do Volume (Hex): {serial_fmt}")
                                    extraiu_algo = True

                        # 2. Caminhos Relativos, Argumentos e Diretórios
                        info_dados = dados.get('data', {})
                        if info_dados:
                            caminho_relativo = info_dados.get('relative_path')
                            if caminho_relativo:
                                metadados_extras.append(f"Caminho Alvo (Relativo): {caminho_relativo}")
                                extraiu_algo = True

                            dir_trab = info_dados.get('working_dir')
                            if dir_trab:
                                metadados_extras.append(f"Diretório de Trabalho: {dir_trab}")
                                extraiu_algo = True

                            args = info_dados.get('command_line_arguments')
                            if args:
                                metadados_extras.append(f"Argumentos (Execução): {args}")
                                extraiu_algo = True

                            desc = info_dados.get('description') or info_dados.get('name_string')
                            if desc:
                                metadados_extras.append(f"Descrição/Nome Interno: {desc}")
                                extraiu_algo = True

                        # 3. MAC Address de Origem
                        info_extra = dados.get('extra_data', {})
                        tracker = info_extra.get('TRACKER_DATA_BLOCK', {})
                        mac = tracker.get('mac_address')
                        if mac:
                            metadados_extras.append(f"MAC Address de Origem: {mac}")
                            extraiu_algo = True
                        else:
                            # Adiciona o aviso explícito de ausência
                            metadados_extras.append("MAC Address de Origem: [Não localizado neste atalho]")

                        if not extraiu_algo:
                            metadados_extras.append(
                                "ℹ️ O alvo deste atalho está ofuscado ou aponta para um item virtual do Windows (Shell Item ID).")
                except Exception as e:
                    metadados_extras.append(f"⚠️ Erro ao analisar atalho .lnk: {e}")
            else:
                metadados_extras.append(
                    "⚠️ Biblioteca ausente: O módulo 'LnkParse3' não foi encontrado. Análise de atalhos indisponível.")


        # 7. EXECUTÁVEIS E DLLs (.exe, .dll, .sys)
        elif extensao in FORMATOS_EXECUTAVEIS:
            if HAS_PEFILE:
                try:
                    pe = pefile.PE(caminho_arquivo)

                    # O TimeDateStamp é obrigatório e gravado em UTC no momento da compilação
                    timestamp = pe.FILE_HEADER.TimeDateStamp
                    data_compilacao = dt.datetime.fromtimestamp(timestamp, dt.timezone.utc).strftime(
                        '%d/%m/%Y %H:%M:%S UTC')
                    metadados_extras.append(f"Data de Compilação (TimeDateStamp): {data_compilacao}")

                    # --- CHECAGEM DE ASSINATURA DIGITAL ---
                    try:
                        dir_seguranca = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
                        if dir_seguranca.VirtualAddress > 0 and dir_seguranca.Size > 0:
                            metadados_extras.append("Assinatura Digital: ✅ PRESENTE (Contém certificado Authenticode)")
                        else:
                            metadados_extras.append(
                                "Assinatura Digital: ⚠️ AUSENTE (Arquivo não assinado - Suspeito se disser ser do Windows/Microsoft)")
                    except Exception:
                        metadados_extras.append("Assinatura Digital: [Erro ao verificar]")
                    # --------------------------------------

                    # Busca nomes originais e empresas ocultas nas tabelas de strings
                    if hasattr(pe, 'FileInfo'):
                        for fileinfo in pe.FileInfo:
                            for info in fileinfo:
                                if hasattr(info, 'StringTable'):
                                    for st in info.StringTable:
                                        for entrada in st.entries.items():
                                            chave = entrada[0].decode('utf-8', errors='ignore')
                                            valor = entrada[1].decode('utf-8', errors='ignore')
                                            if chave in ['OriginalFilename', 'CompanyName', 'FileDescription']:
                                                metadados_extras.append(f"{chave}: {valor}")

                except Exception as e:
                    metadados_extras.append(f"⚠️ Erro ao ler metadados do PE (Executável): {e}")
            else:
                metadados_extras.append(
                    "⚠️ Biblioteca ausente: O módulo 'pefile' não foi encontrado. Impossível extrair dados do executável.")


        # 8. E-MAILS EXPORTADOS (.eml, .msg)
        elif extensao in FORMATOS_EMAIL_EML:
            try:
                with open(caminho_arquivo, 'rb') as f:
                    msg = BytesParser(policy=policy.default).parse(f)
                    extraiu_algo = False

                    if msg['from']:
                        metadados_extras.append(f"Remetente: {msg['from']}")
                        extraiu_algo = True
                    if msg['to']:
                        metadados_extras.append(f"Destinatário: {msg['to']}")
                        extraiu_algo = True
                    if msg['subject']:
                        metadados_extras.append(f"Assunto: {msg['subject']}")
                        extraiu_algo = True
                    if msg['date']:
                        metadados_extras.append(f"Data de Envio: {msg['date']}")
                        extraiu_algo = True

                    # O último 'Received' geralmente revela o IP/Servidor de origem que o criminoso usou
                    received = msg.get_all('Received')
                    if received:
                        metadados_extras.append(
                            f"1º Servidor de Trânsito (Origem): {received[-1].split(';')[-1].strip()}")
                        extraiu_algo = True

                    if not extraiu_algo:
                        metadados_extras.append(
                            "ℹ️ Cabeçalhos de e-mail (Remetente, Destinatário, Assunto) não localizados ou arquivo malformado.")

            except Exception as e:
                metadados_extras.append(f"⚠️ Erro ao analisar estrutura do e-mail (.eml): {e}")

        elif extensao in FORMATOS_EMAIL_MSG:
            if HAS_EXTRACT_MSG:
                try:
                    msg = extract_msg.Message(caminho_arquivo)
                    extraiu_algo = False

                    if msg.sender:
                        metadados_extras.append(f"Remetente (MSG): {msg.sender}")
                        extraiu_algo = True
                    if msg.to:
                        metadados_extras.append(f"Destinatário (MSG): {msg.to}")
                        extraiu_algo = True
                    if msg.subject:
                        metadados_extras.append(f"Assunto (MSG): {msg.subject}")
                        extraiu_algo = True
                    if msg.date:
                        metadados_extras.append(f"Data de Envio (MSG): {msg.date}")
                        extraiu_algo = True

                    msg.close()

                    if not extraiu_algo:
                        metadados_extras.append("ℹ️ Propriedades do Outlook (Remetente, Assunto) vazias neste arquivo.")

                except Exception as e:
                    metadados_extras.append(f"⚠️ Erro ao ler metadados do Outlook (.msg): {e}")
            else:
                metadados_extras.append(
                    "⚠️ Biblioteca ausente: O módulo 'extract_msg' não foi encontrado. Impossível ler e-mails nativos do Outlook (.msg).")

        # 9. ARQUIVOS DE ÁUDIO (TinyTag primário + ExifTool Fallback)
        elif extensao in FORMATOS_AUDIO:
            extraiu_algo = False
            caminho_exiftool = None

            # --- TENTATIVA 1: TinyTag (Extremamente rápido para MP3, WAV, M4A) ---
            if HAS_TINYTAG:
                try:
                    tag = TinyTag.get(caminho_arquivo)
                    if tag.duration is not None:
                        mins, secs = divmod(tag.duration, 60)
                        horas, mins = divmod(mins, 60)
                        metadados_extras.append(f"Duração Exata: {int(horas):02d}:{int(mins):02d}:{int(secs):02d}")
                        extraiu_algo = True
                    if tag.bitrate:
                        metadados_extras.append(f"Bitrate: {int(tag.bitrate)} kbps")
                        extraiu_algo = True
                    if tag.artist:
                        metadados_extras.append(f"Artista/Criador: {tag.artist}")
                        extraiu_algo = True
                    if tag.comment:
                        metadados_extras.append(f"Comentários: {tag.comment}")
                        extraiu_algo = True
                except Exception:
                    # Falhou silenciosamente (formato não suportado pelo TinyTag, ex: .dss, .ts).
                    # A flag 'extraiu_algo' continuará False, acionando o ExifTool abaixo.
                    pass

            # --- TENTATIVA 2: ExifTool (Formatos exóticos, de gravadores policiais ou falha do TinyTag) ---
            if not extraiu_algo:
                caminho_exiftool = obter_caminho_exiftool()
                if caminho_exiftool:
                    try:
                        cmd = [caminho_exiftool, "-j", "-G", caminho_arquivo]
                        processo = subprocess.run(
                            cmd, capture_output=True, text=True, timeout=15,
                            creationflags=0x08000000 if os.name == 'nt' else 0
                        )

                        if processo.returncode == 0:
                            dados_json = json.loads(processo.stdout)
                            if dados_json:
                                meta = dados_json[0]
                                extraiu_pelo_exiftool = False

                                # Duração (ExifTool converte formatos estranhos para texto, ex: "0:01:23")
                                duracao = meta.get('Composite:Duration') or meta.get('System:Duration')
                                if duracao:
                                    metadados_extras.append(f"Duração (ExifTool): {duracao}")
                                    extraiu_pelo_exiftool = True

                                # Autoria/Artista (Varredura dinâmica de chaves)
                                artista = None
                                for chave, valor in meta.items():
                                    if chave.endswith(':Artist') or chave.endswith(':Author') or chave.endswith(
                                            ':Creator'):
                                        artista = valor
                                        break

                                if artista:
                                    metadados_extras.append(f"Autor/Criador (ExifTool): {artista}")
                                    extraiu_pelo_exiftool = True

                                if not extraiu_pelo_exiftool:
                                    metadados_extras.append(
                                        "ℹ️ Formato lido pelo ExifTool, mas nenhum dado de autoria ou duração encontrado.")
                                else:
                                    extraiu_algo = True
                    except subprocess.TimeoutExpired:
                        metadados_extras.append("⚠️ Leitura de áudio via ExifTool abortada (>15s).")
                    except Exception as e:
                        metadados_extras.append(f"⚠️ Erro no fallback do ExifTool para áudio: {e}")
                else:
                    if not HAS_TINYTAG:
                        metadados_extras.append(
                            "⚠️ Bibliotecas TinyTag e ExifTool ausentes. Extração de áudio impossível.")
                    else:
                        metadados_extras.append(
                            "ℹ️ Formato de áudio não suportado nativamente e ExifTool ausente para tentar leitura secundária.")

            if not extraiu_algo and HAS_TINYTAG and caminho_exiftool:
                metadados_extras.append(
                    "ℹ️ O arquivo foi analisado com sucesso, mas não contém metadados de autoria ou duração legíveis.")


        # 10. COMPACTADOS, TORRENTS E RTF (Lidos via ExifTool)
        elif extensao in (FORMATOS_COMPACTADOS + FORMATOS_TORRENT + FORMATOS_RTF):
            caminho_exiftool = obter_caminho_exiftool()
            if caminho_exiftool:
                try:
                    cmd = [caminho_exiftool, "-j", "-G", caminho_arquivo]
                    processo = subprocess.run(cmd, capture_output=True, text=True, timeout=15,
                                              creationflags=0x08000000 if os.name == 'nt' else 0)

                    if processo.returncode == 0:
                        dados_json = json.loads(processo.stdout)
                        if dados_json:
                            meta = dados_json[0]
                            extraiu_algo = False

                            # Tenta puxar comentários de ZIPs ou Torrents
                            comentario = meta.get('ZIP:Comment') or meta.get('Bencode:Comment')
                            if comentario:
                                metadados_extras.append(f"Comentário Embutido: {comentario}")
                                extraiu_algo = True

                            # Tenta puxar criador de RTF ou Torrent
                            criador = meta.get('RTF:Author') or meta.get('Bencode:CreatedBy')
                            if criador:
                                metadados_extras.append(f"Autor/Criador: {criador}")
                                extraiu_algo = True

                            # Tenta puxar data de criação do Torrent
                            data_criacao = meta.get('Bencode:CreationDate')
                            if data_criacao:
                                metadados_extras.append(f"Data de Criação (Interna): {data_criacao}")
                                extraiu_algo = True

                            # --- FEEDBACK VISUAL PRECISO E ISOLADO ---
                            if not extraiu_algo:
                                metadados_extras.append("ℹ️ Metadados avançados não localizados.")
                                metadados_extras.append(
                                    "   ↳ O ExifTool analisou o arquivo, mas não encontrou informações de autoria ou comentários suportados para este formato. A estrutura interna permanece preservada.")


                except subprocess.TimeoutExpired:
                    metadados_extras.append(
                        "⚠️ Leitura de arquivo compactado/documento abortada (ExifTool demorou mais que 15s).")
                except Exception as e:
                    metadados_extras.append(
                        f"⚠️ Erro inesperado ao processar arquivo compactado/documento com ExifTool: {e}")
            else:
                # SE O EXIFTOOL NÃO FOR ENCONTRADO, AVISA IMEDIATAMENTE.
                pasta_esperada = "exiftool-13.51_64" if sys.maxsize > 2 ** 32 else "exiftool-13.51_32"
                metadados_extras.append(
                    f"⚠️ ExifTool ausente: Não foi possível extrair metadados estruturais, criadores ou comentários do arquivo compactado/documento. Pasta esperada: '{pasta_esperada}'.")

        return metadados_extras

    def obter_metadados_e_hashes(self, caminho_arquivo, algos_selecionados):
        try:
            # --- PROTEÇÃO FORENSE: BLOQUEIO DE ARQUIVOS EM NUVEM E ACESSO ---
            if os.name == 'nt':
                try:
                    # Lê os atributos do Windows sem acionar a abertura do conteúdo do arquivo
                    stat_info = os.stat(caminho_arquivo)

                    # Substitui o 'pass' silencioso por uma checagem elegante e segura
                    if hasattr(stat_info, 'st_file_attributes'):
                        atributos = stat_info.st_file_attributes

                        # 0x400000 = FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS (Baixa da nuvem ao abrir)
                        # 0x1000   = FILE_ATTRIBUTE_OFFLINE (Armazenamento remoto/fita)
                        if (atributos & 0x400000) or (atributos & 0x1000):
                            return {
                                'sucesso': False,
                                'erro': 'ARQUIVO EM NUVEM DETECTADO: Arquivo "Apenas Online" (ex: OneDrive). Leitura bloqueada para evitar download e alteração da evidência local.'
                            }
                except OSError as e:
                    # Captura erros reais de sistema de arquivos (ex: Caminho muito longo, Permissão Negada na raiz)
                    return {
                        'sucesso': False,
                        'erro': f'ACESSO NEGADO PELO S.O.: Não foi possível ler os atributos do arquivo no disco ({e}).'
                    }
            # -------------------------------------------------------------------

            tamanho_bytes = os.path.getsize(caminho_arquivo)
            tamanho_mb = tamanho_bytes / (1024 * 1024)
            data_modificacao_raw = os.path.getmtime(caminho_arquivo)
            data_modificacao = datetime.datetime.fromtimestamp(data_modificacao_raw).strftime('%d/%m/%Y %H:%M:%S')

            objetos_hash = {}
            if "CRC32" in algos_selecionados: objetos_hash["CRC32"] = 0
            if "MD5" in algos_selecionados: objetos_hash["MD5"] = hashlib.md5()
            if "SHA-1" in algos_selecionados: objetos_hash["SHA-1"] = hashlib.sha1()
            if "SHA-256" in algos_selecionados: objetos_hash["SHA-256"] = hashlib.sha256()
            if "SHA-384" in algos_selecionados: objetos_hash["SHA-384"] = hashlib.sha384()
            if "SHA-512" in algos_selecionados: objetos_hash["SHA-512"] = hashlib.sha512()

            contagem_bytes = Counter()  # <--- Inicializa o contador para entropia de Shannon

            self.barra_arquivo.setMaximum(100)
            self.barra_arquivo.setValue(0)
            bytes_processados = 0
            tamanho_chunk = 65536

            try:
                with open(caminho_arquivo, 'rb') as f:
                    # --- INÍCIO DO FILE LOCK ---
                    if os.name == 'nt' and tamanho_bytes > 0:  # Só tranca se tiver conteúdo
                        try:
                            # Tenta trancar o primeiro 1 byte do arquivo (simbolicamente)
                            # O modo LK_NBLCK (Non-Blocking Lock) falha imediatamente se o arquivo estiver em uso
                            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                        except OSError:
                            return {'sucesso': False,
                                    'erro': 'ARQUIVO EM USO: Modificação ativa detectada. Leitura abortada por segurança pericial.'}
                    # ---------------------------
                    try:
                        while True:
                            chunk = f.read(tamanho_chunk)
                            if not chunk:  # Se retornou vazio (fim do arquivo), quebra o loop
                                break

                            if self.cancelar_operacao:
                                return {'sucesso': False, 'erro': 'OPERAÇÃO CANCELADA PELO USUÁRIO'}

                            for algo in algos_selecionados:
                                if algo == "CRC32":
                                    objetos_hash["CRC32"] = zlib.crc32(chunk, objetos_hash["CRC32"])
                                else:
                                    objetos_hash[algo].update(chunk)

                            contagem_bytes.update(chunk)  # <--- Conta a frequência dos bytes para entropia de Shannon
                            bytes_processados += len(chunk)

                            self.bytes_processados_total += len(chunk)

                            if bytes_processados % (tamanho_chunk * 16) == 0:
                                percentual = int((bytes_processados / tamanho_bytes) * 100) if tamanho_bytes > 0 else 100
                                self.barra_arquivo.setValue(percentual)
                                QApplication.processEvents()
                    finally:
                        # --- FIM DO FILE LOCK ---
                        if os.name == 'nt' and tamanho_bytes > 0:
                            try:
                                # Destranca o arquivo retornando o ponteiro para o início
                                f.seek(0)
                                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                            except Exception:
                                pass
            except PermissionError:
                # Captura a falha ANTES mesmo do arquivo abrir (ex: aberto no Word/Excel ou falta de privilégios)
                return {'sucesso': False,
                        'erro': 'ACESSO NEGADO / ARQUIVO EM USO: O sistema operacional bloqueou a leitura (arquivo aberto em outro programa ou falta de privilégios de Administrador).'}

            self.barra_arquivo.setValue(100)

            # --- CÁLCULO DA ENTROPIA DE SHANNON ---
            entropia = 0.0
            if tamanho_bytes > 0:
                for contagem in contagem_bytes.values():
                    probabilidade = contagem / tamanho_bytes
                    entropia -= probabilidade * math.log2(probabilidade)

            # Identifica a extensão para evitar falsos positivos de compressão natural
            _, ext_arquivo = os.path.splitext(caminho_arquivo)
            ext_arquivo = ext_arquivo.lower().replace('.', '')
            formatos_comprimidos = ['jpg', 'jpeg', 'png', 'webp', 'gif', 'zip', 'rar', '7z', 'gz', 'mp4', 'mkv', 'avi',
                                    'mp3', 'm4a', 'pdf']

            status_entropia = ""
            if entropia > 7.9:
                if ext_arquivo in formatos_comprimidos:
                    status_entropia = " (Normal para o formato comprimido deste arquivo)"
                else:
                    status_entropia = " (⚠️ ALERTA: Alta entropia - Possível Criptografia / Arquivo Packed)"
            elif entropia < 1.0:
                status_entropia = " (Baixa entropia - Arquivo altamente repetitivo ou vazio)"
            else:
                # --- Mensagem para a faixa normal (entre 1.0 e 7.9) ---
                status_entropia = " (Entropia normal - Sem indícios de ofuscação ou criptografia)"
            # --------------------------------------------

            resultados_hash = {}
            for algo in algos_selecionados:
                if algo == "CRC32":
                    # O 'X' maiúsculo no final da formatação já converte para maiúsculas
                    resultados_hash["CRC32"] = f"{objetos_hash['CRC32'] & 0xFFFFFFFF:08X}"
                else:
                    # O .upper() converte o resultado do hexdigest para maiúsculas
                    resultados_hash[algo] = objetos_hash[algo].hexdigest().upper()

            # --- DETECÇÃO DE ARQUIVO VAZIO ATRAVÉS DOS HASHES ---
            hashes_arquivo_vazio = {
                "CRC32": "00000000",
                "MD5": "D41D8CD98F00B204E9800998ECF8427E",
                "SHA-1": "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
                "SHA-256": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
                "SHA-384": "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B",
                "SHA-512": "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E",
            }

            arquivo_vazio_detectado = False
            for algoritmo, hash_esperado in hashes_arquivo_vazio.items():
                if algoritmo in resultados_hash and resultados_hash[algoritmo] == hash_esperado:
                    arquivo_vazio_detectado = True
                    break

            return {
                'sucesso': True,
                'hashes': resultados_hash,
                'bytes': tamanho_bytes,
                'mb': tamanho_mb,
                'data': data_modificacao,
                'entropia': f"{entropia:.4f}{status_entropia}",
                'arquivo_vazio': arquivo_vazio_detectado
            }
        except Exception as e:
            return {'sucesso': False, 'erro': repr(e)}

    # --- EVENTOS DE DRAG AND DROP ---
    def dragEnterEvent(self, event):
        if self.processando:
            event.ignore()
            return
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dragMoveEvent(self, event):
        if self.processando:
            event.ignore()
            return
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        if self.processando:
            return
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            caminhos = [url.toLocalFile() for url in urls]

            event.acceptProposedAction()
            QTimer.singleShot(100, lambda: self.coletar_e_processar(caminhos))

    def copiar_para_area_transferencia(self):
        conteudo = self.texto_saida.toPlainText()
        if conteudo.strip() and conteudo.strip() != MENSAGEM_INICIAL:
            QApplication.clipboard().setText(conteudo)
            self.btn_copiar.setText("Copiado!")
            QApplication.processEvents()
            import time
            time.sleep(1)
            self.btn_copiar.setText("Copiar Relatório")

    def salvar_relatorio(self):
        conteudo = self.texto_saida.toPlainText()

        # Evita salvar se a tela estiver vazia ou só com a mensagem inicial
        if not conteudo.strip() or conteudo.strip() == MENSAGEM_INICIAL:
            QMessageBox.warning(self, "Aviso", "Não há relatório para ser salvo.")
            return

        # Pega a data e hora atuais para formatar o nome do arquivo
        agora = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        # Define o nome padrão dependendo se os metadados foram exigidos
        if self.chk_metadados.isChecked():
            nome_padrao = f"hashes_e_metadados_{agora}.txt"
        else:
            nome_padrao = f"hashes_{agora}.txt"

        # Abre a janela do sistema para o usuário escolher a pasta de destino
        caminho_salvar, _ = QFileDialog.getSaveFileName(
            self,
            "Salvar Relatório",
            nome_padrao,
            "Arquivo de Texto (*.txt)"
        )

        # Se o usuário escolheu um caminho e não cancelou a janela
        if caminho_salvar:
            try:
                # Salva usando UTF-8 para garantir que acentos e emojis (como as lixeiras, relógios e avisos) fiquem perfeitos
                with open(caminho_salvar, 'w', encoding='utf-8') as f:
                    f.write(conteudo)

                # Feedback visual rápido de sucesso no botão
                texto_original = self.btn_salvar.text()
                self.btn_salvar.setText("Salvo com sucesso!")
                QApplication.processEvents()
                import time
                time.sleep(1.5)
                self.btn_salvar.setText(texto_original)

            except Exception as e:
                QMessageBox.critical(self, "Erro", f"Ocorreu um erro ao salvar o relatório:\n{e}")

    def limpar_tela(self):
        # # --- LINHA TEMPORÁRIA PARA TESTAR O CRASH_LOG - FOI USADA APENAS NA FASE DE DESENVOLVIMENTO ---
        # raise RuntimeError("CRASH FORÇADO: Testando o sistema de log de erros!")
        # # ------------------------------------------------------------

        self.texto_saida.clear()
        self.texto_saida.append(MENSAGEM_INICIAL + "\n")
        self.barra_arquivo.setValue(0)
        self.barra_total.setValue(0)
        self.lbl_progresso_arquivo.setText("Progresso do Arquivo Atual:")

    def selecionar_arquivo(self):
        if self.processando: return

        # O argumento options=QFileDialog.Option.DontResolveSymlinks impede que o Windows
        # redirecione atalhos (.lnk) para o seu arquivo de destino original.
        caminhos, _ = QFileDialog.getOpenFileNames(
            self,
            "Selecione um ou mais arquivos",
            dir="",
            filter="Todos os Arquivos (*)",
            options=QFileDialog.Option.DontResolveSymlinks
        )

        if caminhos:
            self.coletar_e_processar(caminhos)

    def selecionar_diretorio(self):
        if self.processando: return

        # Combina as regras para garantir que apenas a pasta exata clicada seja retornada,
        # ignorando atalhos de pasta (.lnk) ou junções NTFS.
        opcoes = QFileDialog.Option.ShowDirsOnly | QFileDialog.Option.DontResolveSymlinks

        diretorio = QFileDialog.getExistingDirectory(
            self,
            "Selecione um diretório",
            dir="",
            options=opcoes
        )

        if diretorio:
            self.coletar_e_processar([diretorio])

    def coletar_e_processar(self, caminhos_iniciais):
        arquivos_encontrados = []
        incluir_sub = self.chk_subdiretorios.isChecked()

        # --- VERIFICAÇÃO: É a raiz de um Pendrive/HD? ---
        info_drive = None
        if len(caminhos_iniciais) == 1:
            # Pega o caminho exato e normaliza (transforma barras invertidas, etc.)
            caminho_origem = os.path.abspath(caminhos_iniciais[0])

            # Checa se é diretório e se o "pai" dele é ele mesmo (ex: E:\ == E:\)
            if os.path.isdir(caminho_origem) and os.path.dirname(caminho_origem) == caminho_origem:
                info_drive = obter_info_volume(caminho_origem)
        # -----------------------------------------------------

        for caminho in caminhos_iniciais:
            if os.path.isfile(caminho):
                arquivos_encontrados.append(caminho)
            elif os.path.isdir(caminho):
                if incluir_sub:
                    for raiz, _, arquivos in os.walk(caminho):
                        for arquivo in arquivos:
                            arquivos_encontrados.append(os.path.join(raiz, arquivo))
                else:
                    for item in os.listdir(caminho):
                        caminho_completo = os.path.join(caminho, item)
                        if os.path.isfile(caminho_completo):
                            arquivos_encontrados.append(caminho_completo)

        # --- Captura o texto colado da Cadeia de Custódia ---
        texto_custodia = ""
        # Verifica se o componente foi criado na UI antes de tentar ler
        if hasattr(self, 'texto_referencia'):
            texto_custodia = self.texto_referencia.toPlainText().strip()
        # ----------------------------------------------------------------------

        # Passa a informação do drive (se existir) para o processamento final
        self.processar_arquivos(arquivos_encontrados, info_drive, texto_custodia)

    def processar_arquivos(self, lista_arquivos, info_drive=None, texto_custodia=""):
        algos_selecionados = [algo for algo, chk in self.chk_hashes.items() if chk.isChecked()]
        total_arquivos = len(lista_arquivos)

        # Verifica se o usuário quer extrair metadados extras
        extrair_meta = self.chk_metadados.isChecked()

        if total_arquivos == 0:
            self.texto_saida.append("Nenhum arquivo encontrado para processamento.\n")
            return

        self.travar_interface()

        if self.texto_saida.toPlainText().strip() == MENSAGEM_INICIAL:
            self.texto_saida.clear()

        if not algos_selecionados:
            self.texto_saida.append("[AVISO] Nenhum algoritmo de hash selecionado. Apenas metadados serão extraídos.\n")

        if extrair_meta and not HAS_PIL and not HAS_CV2 and not HAS_PYPDF:
            self.texto_saida.append(
                "[AVISO] Nenhuma biblioteca extra (Pillow, OpenCV, pypdf) detectada. Metadados de PDFs, Imagens e Vídeos serão ignorados.\n")

        self.cancelar_operacao = False
        self.btn_cancelar.setText("CANCELAR PROCESSAMENTO")
        self.btn_cancelar.setEnabled(True)
        self.barra_total.setMaximum(total_arquivos)
        self.barra_total.setValue(0)

        # Inicializa o validador se houver texto
        validador = None
        qtd_validados = 0
        qtd_alertas = 0
        qtd_nao_validados = 0
        qtd_alertas_parciais = 0

        if texto_custodia:
            # Verifica se o texto veio de um PDF arrastado
            veio_de_pdf = False
            nome_ref = getattr(self.texto_referencia, 'nome_arquivo_origem', None)
            if nome_ref and nome_ref.lower().endswith('.pdf'):
                veio_de_pdf = True

            validador = ValidadorCustodia(texto_custodia, is_pdf=veio_de_pdf)

        # Pré-calcula o tamanho total em bytes para o ETA funcionar
        self.total_bytes_processar = 0
        for arq in lista_arquivos:
            try:
                self.total_bytes_processar += os.path.getsize(arq)
            except OSError:
                pass  # Ignora arquivos inacessíveis no pré-cálculo

        self.bytes_processados_total = 0
        self.tempo_inicio_total = time.time()
        self.timer_tempo.start(INTERVALO_ATUALIZACAO_BARRA_PREVISAO_PROGRESSO_TOTAL*1000)

        self.texto_saida.append(f"Processando {total_arquivos} arquivo(s)...\n")

        # --- IMPRIME AS INFOS DA UNIDADE APENAS SE FOR RAIZ ---
        if info_drive:
            self.texto_saida.append("💿 INFORMAÇÕES DA UNIDADE DE ORIGEM (Extração de Unidade Lógica):")
            self.texto_saida.append(f"  ↳ Letra: {info_drive['unidade']}")
            self.texto_saida.append(f"  ↳ Rótulo (Label): {info_drive['rotulo']}")
            self.texto_saida.append(f"  ↳ Serial do Volume: {info_drive['serial']}")
            self.texto_saida.append(f"  ↳ Formato (FS): {info_drive['sistema_arquivos']}")
            self.texto_saida.append("")  # Linha em branco para separar
        # ------------------------------------------------------

        self.texto_saida.append("-" * 60 + "\n")
        QApplication.processEvents()

        contagem_extensoes = {}
        arquivos_processados_qtd = 0

        for indice, arquivo in enumerate(lista_arquivos):
            if self.cancelar_operacao:
                self.texto_saida.append("\n[!] PROCESSO INTERROMPIDO PELO USUÁRIO.\n")
                self.lbl_progresso_arquivo.setText("Progresso do Arquivo Atual: Cancelado")
                break

            nome_arquivo = os.path.basename(arquivo)
            self.lbl_progresso_arquivo.setText(f"Progresso do Arquivo Atual: {nome_arquivo}")

            self.texto_saida.append(f"Arquivo: {arquivo}")

            resultado = self.obter_metadados_e_hashes(arquivo, algos_selecionados)

            if resultado['sucesso']:
                arquivos_processados_qtd += 1
                _, extensao = os.path.splitext(arquivo)
                extensao = extensao.upper()
                if not extensao:
                    extensao = "SEM EXTENSÃO"
                else:
                    extensao = extensao[1:]
                contagem_extensoes[extensao] = contagem_extensoes.get(extensao, 0) + 1

                # 1. BLOCO BÁSICO E HASHES NO TOPO
                self.texto_saida.append(f"Tamanho: {resultado['bytes']} bytes ({resultado['mb']:.2f} MB)")
                self.texto_saida.append(f"Modificado em: {resultado['data']}")

                for algo in algos_selecionados:
                    self.texto_saida.append(f"{algo}: {resultado['hashes'][algo]}")

                # 2. PULA UMA LINHA PARA SEPARAR OS ASSUNTOS
                self.texto_saida.append("")

                # 3. BLOCO DE ANÁLISES (ENTROPIA E METADADOS) NA PARTE INFERIOR
                self.texto_saida.append(f"Entropia (Shannon): {resultado['entropia']}")

                if resultado.get('arquivo_vazio', False):
                    self.texto_saida.append(
                        "ℹ️ ARQUIVO VAZIO: Hash universalmente conhecido (0 bytes - Criado pelo sistema mas nunca utilizado)")

                # --- Força a interface a mostrar a primeira parte ANTES de ler metadados pesados
                QApplication.processEvents()

                # --- INSERÇÃO DOS METADADOS EXTRAS AQUI (SE MARCADO) ---
                if extrair_meta:
                    metadados_midia = self.obter_metadados_avancados(arquivo)
                    for meta in metadados_midia:
                        self.texto_saida.append(meta)
                # --------------------------------------------------------

                # --- INTEGRAÇÃO: VALIDAÇÃO DA CADEIA DE CUSTÓDIA ---
                if validador:
                    status, msg_custodia = validador.validar(arquivo, resultado['hashes'])
                    self.texto_saida.append("")
                    self.texto_saida.append(msg_custodia)

                    # Atualiza os contadores pro resumo final
                    if status == 1:
                        qtd_validados += 1
                    elif status == 2:
                        qtd_alertas += 1
                    elif status == 4:
                        qtd_alertas_parciais += 1
                    else:
                        qtd_nao_validados += 1

                # --------------------------------------------------------
            else:
                self.texto_saida.append(f"Erro: {resultado['erro']}")

            self.texto_saida.append("-" * 60 + "\n")

            self.barra_total.setValue(indice + 1)

            scrollbar = self.texto_saida.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())
            QApplication.processEvents()

        self.texto_saida.append("Resumo do conteúdo:")

        extensoes_ordenadas = sorted(contagem_extensoes.items(), key=lambda item: item[1], reverse=True)
        for ext, qtd in extensoes_ordenadas:
            self.texto_saida.append(f"{qtd} arquivo(s) {ext}")

        self.texto_saida.append(f"Total de arquivos processados: {arquivos_processados_qtd} arquivo(s)\n")
        self.texto_saida.append("-" * 60)

        # --- RESUMO FINAL DA CADEIA DE CUSTÓDIA ---
        if validador:
            # --- LISTA LIMPA DE REFERÊNCIA ENVIADA PELA DELEGACIA OU REQUISITANTE DO EXAME ---
            lista_referencia = validador.obter_lista_limpa()
            if lista_referencia:
                # Verifica se a caixa lembra do nome e do hash
                nome_ref = self.texto_referencia.nome_arquivo_origem
                hash_ref = getattr(self.texto_referencia, 'hash_arquivo_origem', None)

                if nome_ref and hash_ref:
                    self.texto_saida.append(
                        f"\n=== RELAÇÃO ORIGINAL DE HASHES (Extraída de: {nome_ref} - SHA-256: {hash_ref}) ===")
                elif nome_ref:
                    self.texto_saida.append(f"\n=== RELAÇÃO ORIGINAL DE HASHES (Extraída de: {nome_ref}) ===")
                else:
                    self.texto_saida.append("\n=== RELAÇÃO ORIGINAL DE HASHES (CADEIA DE CUSTÓDIA) ===")

                for item in lista_referencia:
                    self.texto_saida.append(item)
                self.texto_saida.append("\n" + "-" * 60)

            self.texto_saida.append("\n=== RESUMO DA VALIDAÇÃO DE CUSTÓDIA ===")
            self.texto_saida.append(f"✅ Arquivos validados com sucesso: {qtd_validados}")
            if qtd_alertas > 0:
                self.texto_saida.append(f"⚠️ Arquivos com alerta (hash bate, nome diverge): {qtd_alertas}")

            if qtd_alertas_parciais > 0:
                self.texto_saida.append(f"⚠️ Arquivos com alerta (algum hash com divergência): {qtd_alertas_parciais}")

            self.texto_saida.append(f"❌ Arquivos não validados/não encontrados: {qtd_nao_validados}")
            self.texto_saida.append("-" * 60)
            # ------------------------------------------
        # ------------------------------------------

        # --- BLOCO DE FINALIZAÇÃO DO TEMPO (FORMATO AMIGÁVEL) ---
        self.timer_tempo.stop()  # Para o cronômetro

        if not self.cancelar_operacao:
            # Calcula o tempo total exato que a operação levou
            tempo_total = time.time() - self.tempo_inicio_total
            horas, resto = divmod(tempo_total, 3600)
            minutos, segundos = divmod(resto, 60)

            h = int(horas)
            m = int(minutos)
            s = int(segundos)

            # Constrói o texto dinamicamente (ex: 1h20min30s, 35min20s ou 17s)
            if h > 0:
                str_tempo_final = f"{h}h{m}min{s}s"
            elif m > 0:
                str_tempo_final = f"{m}min{s}s"
            else:
                str_tempo_final = f"{s}s" if s > 0 else "< 1s"

            # Atualiza a barra mantendo o tempo final visível
            self.lbl_progresso_arquivo.setText("Progresso do Arquivo Atual: Concluído!")
            self.lbl_progresso_total.setText(
                f"Progresso Total (Arquivos) - Concluído! (Tempo Decorrido: {str_tempo_final})")

            # Adiciona o tempo no relatório de texto para ficar salvo se o usuário exportar
            self.texto_saida.append(f"Processamento concluído com sucesso em {str_tempo_final}!\n")
        else:
            self.lbl_progresso_total.setText("Progresso Total (Arquivos) - Cancelado pelo usuário.")
        # ------------------------------------------------------

        self.btn_cancelar.setEnabled(False)
        self.btn_cancelar.setText("CANCELAR PROCESSAMENTO")

        scrollbar = self.texto_saida.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

        self.destravar_interface()


if __name__ == "__main__":
    def manipulador_excecoes_global(exc_type, exc_value, exc_traceback):
        # 1. Formata as datas (uma para o texto interno, outra segura para o nome do arquivo)
        agora = datetime.datetime.now()
        str_data_hora = agora.strftime("%d/%m/%Y %H:%M:%S")
        str_arquivo_data = agora.strftime("%Y%m%d_%H%M%S")

        # 2. Define o nome dinâmico do arquivo de log
        nome_arquivo = f"crash_log_{str_arquivo_data}.txt"
        caminho_log = BASE_DIR / nome_arquivo

        # 3. Extrai a trilha completa do erro
        log_msg = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))

        # 4. Monta o texto amigável e instrutivo do log
        texto_log = (
            f"=== RELATÓRIO DE ERRO CRÍTICO ({NOME_APP}) ===\n"
            f"Data e Hora: {str_data_hora}\n"
            f"Versão do Programa: {VERSAO_APP}\n"
            f"--------------------------------------------------\n"
            f"ATENÇÃO:\n"
            f"O programa encontrou um erro inesperado e precisou ser encerrado.\n\n"
            f"Por favor, ajude a corrigir este problema enviando ESTE ARQUIVO\n"
            f"({nome_arquivo}) como anexo para o desenvolvedor no e-mail:\n\n"
            f"-> {EMAIL_CONTATO} <-\n\n"
            f"Faça um breve relato do que ocorreu.\n"
            f"--------------------------------------------------\n\n"
            f"DETALHES TÉCNICOS DO ERRO (Traceback):\n"
            f"{log_msg}\n"
        )

        # 5. Salva o arquivo fisicamente (usamos 'w' para criar um arquivo novo e limpo por crash)
        try:
            with open(caminho_log, "w", encoding="utf-8") as f:
                f.write(texto_log)
        except Exception:
            pass  # Se o próprio sistema de log falhar por falta de permissão, ignoramos para não criar um loop de erros

        # 6. Exibe a caixa de aviso na interface ANTES de fechar o programa
        # Verifica se a QApplication ainda está rodando para podermos desenhar a janela
        app_instancia = QApplication.instance()
        if app_instancia:
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Critical)
            msg_box.setWindowTitle("Erro Crítico Inesperado")
            msg_box.setText("Ocorreu um erro fatal e o extrator precisará ser encerrado.")
            msg_box.setInformativeText(
                f"Um relatório de erro foi salvo automaticamente em:<br>"
                f"<b>{caminho_log}</b><br><br>"
                f"Por favor, envie este arquivo gerado para o e-mail:<br>"
                f"<b>{EMAIL_CONTATO}</b><br>"
                f"com um breve relato do que ocorreu.<br><br>"
                f"Isso ajudará a investigar e corrigir o problema nas próximas versões."
            )
            msg_box.exec()

        # 7. Dispara o comportamento padrão do sistema para finalizar o fechamento
        sys.__excepthook__(exc_type, exc_value, exc_traceback)


    # Injeta a função manipulador_excecoes_global como o "para-quedas" oficial do Python para exceções não tratadas
    sys.excepthook = manipulador_excecoes_global

    # Se for modo helper (elevado), roda e sai antes de subir GUI
    try:
        if "--raw-hash" in sys.argv:
            raise SystemExit(cli_raw_mode_main(sys.argv[1:]))
    except SystemExit:
        raise
    except Exception:
        # se falhar no helper, ainda tentamos subir GUI (ou você pode abortar)
        pass

    # Inicialização normal da interface
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    # --- ESTILO GLOBAL PARA TOOLTIPS ---
    app.setStyleSheet("""
            QToolTip {
                background-color: #ffffff;
                color: #000000;
                border: 1px solid #cccccc;
                padding: 2px;
                font-size: 10pt;
            }
        """)
    # -----------------------------------------

    if os.path.exists(ICON_PATH):
        app.setWindowIcon(QIcon(ICON_PATH))

    janela = JanelaHashes()
    janela.show()
    sys.exit(app.exec())