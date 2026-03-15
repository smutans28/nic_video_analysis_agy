import os
import time
import json
import subprocess
from pymediainfo import MediaInfo


# Defina a constante do caminho se necessário
# MEDIAINFO_CLI_PATH = 'MediaInfo.exe' # Usaremos isso se estiver no PATH

def _run_exiftool(file_path, is_full_report=False):
    """
    Roda o binário do ExifTool (invisível) sobre o arquivo de vídeo e retorna o texto completo.
    Procura o binário na pasta 'bin/exiftool-13.51_64/exiftool.exe'.
    """
    try:
        # Se for standalone Nuitka, os arquivos vão para sys._MEIPASS ou o folder base onde o binário rodou
        if '__compiled__' in globals():
            # Nuitka runtime: __file__ cai em <Temp>/ONEFIL~1/modules/file_info.py
            # Voltamos 2 níveis pra sair de /modules/ e cair na raiz do ONEFIL~1
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        else:
            # Desenvolvimento local: O arquivo atual está dentro de 'modules/'
            # Voltamos 2 níveis pra sair de /modules/ e cair na raiz do projeto
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            
        exiftool_exe = os.path.join(base_dir, "bin", "exiftool-13.51_64", "exiftool.exe")
        
        if not os.path.exists(exiftool_exe):
            return f"[EXIFTOOL AUSENTE]\nBinário não encontrado em: {exiftool_exe}\n"
            
        # Parâmetros definidos pelo usuário
        if is_full_report:
            # Completo para exportação TXT. A flag -ee varre blocos inteiros e é muito lenta.
            cmd = [exiftool_exe, "-a", "-u", "-U", "-ee", "-g1", file_path]
            # O timeout precisa ser beeeem maior para não triggar o fallback do except.
            subprocess_timeout = 60
        else:
            # Básico para exibir na aba da UI (rapido)
            cmd = [exiftool_exe, file_path]
            subprocess_timeout = 10
        
        # Ocultar a janela do CMD no Windows
        creationflags = 0
        if os.name == 'nt':
            creationflags = 0x08000000 # CREATE_NO_WINDOW
            
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, creationflags=creationflags, timeout=subprocess_timeout)
        if result.stdout:
             return result.stdout.strip()
        else:
             return "[EXIFTOOL]\nExtração vazia.\n"
    except subprocess.TimeoutExpired:
        return f"[EXIFTOOL MOOT_TIMEOUT]\nA extração do Exiftool demorou mais que {subprocess_timeout} segundos e foi abortada para não travar a aplicação."
    except Exception as e:
        return f"[ERRO EXIFTOOL]\nFalha ao executar extração: {str(e)}\n"

def get_forensic_data(file_path):
    """
    Extrai dados chave (para a interface) e o relatório completo (para exportação).
    """
    if not os.path.exists(file_path):
        return {
            "simplified": {
                "Erro": "Arquivo não encontrado."},
            "full_text": ""}

    stats = os.stat(file_path)
    simplified_data = {}
    full_report_text = ""

    # 1. Dados Extrínsecos (MAC Times) - Sempre incluídos
    simplified_data["Caminho do Arquivo"] = file_path
    simplified_data["Tamanho (MB)"] = f"{stats.st_size / (1024 * 1024):.2f} MB"
    simplified_data["Criado - (MAC)"] = time.ctime(stats.st_ctime)
    simplified_data["Modificado - (MAC)"] = time.ctime(stats.st_mtime)

    # 2. Extração de Metadados Chave (JSON)
    try:
        # Obter o JSON para extração estruturada
        media_info_json_str = MediaInfo.parse(file_path, output='JSON')
        info_json = json.loads(media_info_json_str)

        tracks = info_json.get('media', {}).get('track', [])
        general_track = next(
            (t for t in tracks if t.get('@type') == 'General'), {})
        video_track = next(
            (t for t in tracks if t.get('@type') == 'Video'), {})

        def translate_framerate_mode(mode):
            mode = str(mode).upper()
            if mode in ['CFR', 'CONSTANT']:
                return 'Constante'
            elif mode in ['VFR', 'VARIABLE']:
                return 'Variável'
            # Adiciona o modo de taxa de quadros original detectado pelo
            # mediainfo
            original_mode = video_track.get('FrameRate_Mode_Original', '')
            if original_mode and original_mode not in [mode, 'N/D']:
                return f"{mode} (Original: {original_mode})"
            return mode

        # --- CAMPOS SELECIONADOS ---
        simplified_data["--- INFORMAÇÕES CHAVE FORENSE ---"] = ""

        # Seção Básica
        simplified_data["Caminho do Arquivo"] = file_path
        simplified_data["Tamanho (MB)"] = f"{stats.st_size / (1024 * 1024):.2f} MB"

        # Seção Stream
        simplified_data["--- INFO STREAM (Container / Vídeo / Áudio) ---"] = ""
        simplified_data["Container Format"] = general_track.get(
            'Format', 'N/D')
        simplified_data["Duração"] = general_track.get(
            'Duration_String5', 'N/D')  # Usa o formato hh:mm:ss.ms

        simplified_data["Codec (Vídeo)"] = video_track.get('Format', 'N/D')
        simplified_data["Resolução"] = f"{video_track.get('Width')}x{video_track.get('Height')}"

        # Aplica a tradução
        raw_mode = video_track.get('FrameRate_Mode', 'N/D')
        simplified_data["Taxa de Quadros (Modo)"] = translate_framerate_mode(
            raw_mode)

        simplified_data["Frame Rate (FPS)"] = video_track.get(
            'FrameRate', 'N/D')
        simplified_data["Total Frames"] = video_track.get('FrameCount', 'N/D')

        # Novo: Trilha de Áudio (Verificação simples)
        has_audio = next(
            (t for t in tracks if t.get('@type') == 'Audio'), None)
        simplified_data["Possui Trilha de Áudio"] = 'Sim' if has_audio else 'Não'

        # --- METADADOS INTRÍNSECOS ---
        simplified_data["--- METADADOS INTRÍNSECOS ---"] = ""

        # Data de Criação Interna do Container
        simplified_data["Data de Criação (Interna)"] = general_track.get(
            'Encoded_Date', 'N/D')

        # Data de Modificação Interna do Container (usando o campo local)
        simplified_data["Data de Modificação (Interna)"] = general_track.get(
            'File_last_modification_date_local', 'N/D')

        # Produtor e Software
        simplified_data["Fabricante/Modelo (Producer)"] = general_track.get(
            'Make', 'N/D')
        simplified_data["Software de Codificação"] = general_track.get(
            'Encoded_Application', 'N/D')

        # Biblioteca de Codificação
        simplified_data["Biblioteca de Codificação"] = video_track.get(
            'Encoded_Library_Name', 'N/D')

    except Exception as e:
        simplified_data["Erro MediaInfo"] = f"Falha ao analisar JSON: {e}"

    # 3. Obter o Relatório Bruto (Texto) para Exportação
    # Desacoplamos os blocos Try/Except para evitar que uma exceção no Exiftool-Full mate as outras strings
    try:
        media_text = MediaInfo.parse(file_path, output='Text')
    except Exception as e:
        media_text = f"Erro ao gerar relatório MediaInfo: {e}"

    exif_text_basic = _run_exiftool(file_path, is_full_report=False)
    exif_text_full = _run_exiftool(file_path, is_full_report=True)

    return {
        "simplified": simplified_data,
        "media_text": media_text,
        "exif_text_basic": exif_text_basic,
        "exif_text_full": exif_text_full
    }
