# modules/file_info.py (REFATORADO - SAÍDA JSON + TEXTO BRUTO)
import os
import time
import json
from pymediainfo import MediaInfo


# Defina a constante do caminho se necessário
# MEDIAINFO_CLI_PATH = 'MediaInfo.exe' # Usaremos isso se estiver no PATH

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
    try:
        full_report_text = MediaInfo.parse(file_path, output='Text')
    except Exception as e:
        full_report_text = f"Erro ao gerar relatório completo: {e}"

    return {
        "simplified": simplified_data,
        "full_text": full_report_text
    }
