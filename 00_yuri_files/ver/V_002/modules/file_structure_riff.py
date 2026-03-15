# modules/file_structure_riff.py

import os
from construct import (
    Int32ul, Int16ul, Bytes, Struct, PaddedString
)

# ... (Mantenha as estruturas de GLOSSÁRIO, ChunkHeader, AvihData, StrhData
# CHUNK_PAYLOAD_MAP, CONTAINER_CHUNKS e parse_riff_tree IGUAIS ao anterior) ...
# Vou replicar apenas a parte final (analyze_avi_structure) e a função de contagem para economizar espaço aqui,
# mas no seu arquivo final, mantenha as definições de construct.

# ... (INSIRA AQUI TODO O CÓDIGO DE DEFINIÇÕES E PARSE_RIFF_TREE DA VERSÃO ANTERIOR) ...
# --- GLOSSÁRIO RIFF/AVI ---
CHUNK_DESCRIPTIONS = {
    'RIFF': "Resource Interchange File Format - O container pai.",
    'AVI ': "Audio Video Interleave - O tipo de formulário RIFF.",
    'LIST': "List Chunk - Um container que agrupa outros chunks (ex: hdrl, movi).",
    'hdrl': "Header List - Contém os cabeçalhos globais e de stream.",
    'avih': "Main AVI Header - Informações globais (FPS, Resolução, Total Frames).",
    'strl': "Stream List - Define uma trilha (Vídeo ou Áudio).",
    'strh': "Stream Header - Tipo da trilha (vids, auds) e codec (handler).",
    'strf': "Stream Format - Formato específico do codec (BitmapInfoHeader / WaveFormatEx).",
    'movi': "Movie List - Contém os dados reais (frames) intercalados.",
    'idx1': "Index 1 - Tabela de índice para busca rápida (Keyframes/Offsets).",
    'JUNK': "Junk Chunk - Espaço reservado. Pode ser alinhamento ou ocultação de dados.",
    'INFO': "Information List - Metadados de autoria (similar ao udta do MP4).",
    'ISFT': "Software - Software usado para criar o arquivo.",
    'ICOP': "Copyright - Informações de direitos autorais.",
    'IART': "Artist - Autor/Artista.",
    'INAM': "Name - Título do conteúdo.",
    'vids': "Video Stream Identifier.",
    'auds': "Audio Stream Identifier.",
    '00dc': "Video Frame (Stream 00, Compressed) - Dados de vídeo.",
    '01wb': "Audio Data (Stream 01, Waveform Byte) - Dados de áudio.",
    '00db': "Video Frame (Stream 00, Uncompressed) - Dados de vídeo RAW."}

# --- ESTRUTURAS CONSTRUCT (Little Endian) ---

ChunkHeader = Struct(
    "fourcc" / PaddedString(4, "ascii"),
    "size" / Int32ul
)

AvihData = Struct(
    "micro_sec_per_frame" / Int32ul,
    "max_bytes_per_sec" / Int32ul,
    "padding_granularity" / Int32ul,
    "flags" / Int32ul,
    "total_frames" / Int32ul,
    "initial_frames" / Int32ul,
    "streams" / Int32ul,
    "suggested_buffer_size" / Int32ul,
    "width" / Int32ul,
    "height" / Int32ul,
    "reserved" / Bytes(16)
)

StrhData = Struct(
    "fcc_type" / PaddedString(4, "ascii"),
    "fcc_handler" / PaddedString(4, "ascii"),
    "flags" / Int32ul,
    "priority" / Int16ul,
    "language" / Int16ul,
    "initial_frames" / Int32ul,
    "scale" / Int32ul,
    "rate" / Int32ul,
    "start" / Int32ul,
    "length" / Int32ul,
    "suggested_buffer_size" / Int32ul,
    "quality" / Int32ul,
    "sample_size" / Int32ul,
    "frame" / Bytes(8)
)

CHUNK_PAYLOAD_MAP = {
    'avih': AvihData,
    'strh': StrhData
}

CONTAINER_CHUNKS = ['RIFF', 'LIST']


# --- PARSER RECURSIVO ---

def parse_riff_tree(stream, start_offset, end_offset):
    tree = []
    current_offset = start_offset

    while current_offset < end_offset:
        stream.seek(current_offset)

        try:
            header = ChunkHeader.parse_stream(stream)
            chunk_size = header.size
            chunk_type = header.fourcc
            padding = 1 if (chunk_size % 2 != 0) else 0
        except Exception:
            break

        if chunk_size == 0 and chunk_type not in ['JUNK', 'LIST']:
            if current_offset + 8 >= end_offset:
                break

        chunk_entry = {
            "type": chunk_type,
            "size": chunk_size,
            "offset": current_offset,
            "contents": None,
            "children": [],
            "list_type": None,
            "forensic_flags": []
        }

        payload_start = current_offset + 8
        payload_end = payload_start + chunk_size

        try:
            if chunk_type in CONTAINER_CHUNKS:
                stream.seek(payload_start)
                list_type = stream.read(4).decode('ascii', errors='ignore')
                chunk_entry["list_type"] = list_type
                chunk_entry["display_type"] = f"{chunk_type} ({list_type})"

                if list_type == 'movi':
                    chunk_entry["contents"] = {
                        "info": "Contém dados de frames (Interleaved Data). Detalhes ocultos para clareza."}
                else:
                    chunk_entry["children"] = parse_riff_tree(
                        stream, payload_start + 4, payload_end
                    )

            elif chunk_type in CHUNK_PAYLOAD_MAP:
                stream.seek(payload_start)
                data = CHUNK_PAYLOAD_MAP[chunk_type].parse_stream(stream)
                chunk_entry["contents"] = dict(data)
                chunk_entry["display_type"] = chunk_type

                if chunk_type == 'avih':
                    fps = 1000000.0 / data.micro_sec_per_frame if data.micro_sec_per_frame > 0 else 0
                    chunk_entry["contents"]["calc_fps"] = fps

            elif chunk_type == 'JUNK':
                chunk_entry["forensic_flags"].append(
                    "Chunk de Lixo/Padding (Ocultação potencial)")
                chunk_entry["display_type"] = chunk_type

            else:
                chunk_entry["display_type"] = chunk_type
                if chunk_type.startswith('I') or chunk_type == 'strn':
                    stream.seek(payload_start)
                    raw = stream.read(min(chunk_size, 255))
                    try:
                        val = raw.replace(b'\x00', b'').decode('ascii')
                        chunk_entry["contents"] = {"text_value": val}
                    except BaseException:
                        pass

        except Exception as e:
            chunk_entry["forensic_flags"].append(f"Erro: {str(e)}")

        tree.append(chunk_entry)
        current_offset += 8 + chunk_size + padding

    return tree


def count_chunks_recursive(nodes):
    count = 0
    for node in nodes:
        count += 1
        if node['children']:
            count += count_chunks_recursive(node['children'])
    return count


# --- FUNÇÃO PRINCIPAL DE ANÁLISE ---

def analyze_avi_structure(file_path):
    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)

    with open(file_path, "rb") as f:
        signature = f.read(4)
        if signature != b'RIFF':
            return {"Forensic Report": "Erro: Arquivo não é um RIFF/AVI válido."}

        tree = parse_riff_tree(f, 0, file_size)

    found_types = set()

    # Contagem e Sequência
    total_structures = count_chunks_recursive(tree)
    # Para AVI, a sequência raiz é interessante mas geralmente é só RIFF.
    # Vamos pegar o segundo nível (dentro de RIFF) que é mais útil (hdrl,
    # movi, idx1)
    root_sequence = ""
    if tree and tree[0]['children']:
        root_sequence = "RIFF >> " + " >> ".join([
            c.get('list_type') if c['type'] == 'LIST' else c['type']
            for c in tree[0]['children']
        ])
    else:
        root_sequence = "RIFF"

    def format_tree(nodes, level=0):
        lines = []
        indent = "  " * level
        col_type_width = 40
        col_size_width = 12

        for node in nodes:
            d_type = node.get("display_type", node["type"])
            found_types.add(node["type"])
            if node["list_type"]:
                found_types.add(node["list_type"])

            str_type = f"{indent}| {d_type}"
            type_col = f"{str_type:<{col_type_width}}"
            size_col = f"{node['size']:>{col_size_width}}"
            offset_col = f"0x{node['offset']:08X}"

            line = f"| {type_col} | Size: {size_col} | Offset: {offset_col} |"
            if node['forensic_flags']:
                line += f" FLAGS: {', '.join(node['forensic_flags'])}"
            lines.append(line)

            if node['contents']:
                c_indent = " " * (level * 2 + 4)
                for k, v in node['contents'].items():
                    if k == 'calc_fps':
                        lines.append(f"{c_indent}>>> FPS Calculado: {v:.2f}")
                    elif k == 'text_value':
                        lines.append(f"{c_indent}>>> TEXTO: {v}")
                    elif k not in ['reserved', 'flags', '_io', 'micro_sec_per_frame']:
                        lines.append(f"{c_indent}- {k}: {v}")

            if node['children']:
                lines.extend(format_tree(node['children'], level + 1))
        return lines

    tree_visual = "\n".join(format_tree(tree))

    final_report = f"ARQUIVO: {file_name} (Formato AVI/RIFF)\n"
    final_report += "=" * 85 + "\n\n"

    header = f"| {'ESTRUTURA DETALHADA (CHUNKS)':<41}| {'TAMANHO':>18} | {'OFFSET':<18} |"
    final_report += f"{header}\n" + "-" * 85 + "\n"
    final_report += tree_visual + "\n\n"

    final_report += "=" * 85 + "\n"
    final_report += "--- GLOSSÁRIO ESTRUTURAL AVI (Detectado) ---\n"
    for t in sorted(list(found_types)):
        desc = CHUNK_DESCRIPTIONS.get(t, "Descrição não disponível.")
        final_report += f"[{t}] : {desc}\n"

    final_report += "\n" + "=" * 85 + "\n"
    final_report += "-- ANÁLISE FORENSE DA ESTRUTURA AVI --\n"
    final_report += "=" * 85 + "\n"

    # --- NOVO: RESUMO ESTRUTURAL ---
    final_report += "[+] RESUMO ESTRUTURAL:\n"
    final_report += f"  - Sequência de Raiz: {root_sequence}\n"
    final_report += f"  - Total de Estruturas (Chunks): {total_structures}\n\n"

    # Análise de JUNKs
    def find_junks_recursive(nodes):
        found = []
        for n in nodes:
            if n['type'] == 'JUNK':
                found.append(n)
            if n['children']:
                found.extend(find_junks_recursive(n['children']))
        return found

    all_junks = find_junks_recursive(tree)

    if all_junks:
        final_report += f"\n[!] FORAM DETECTADOS {len(all_junks)} CHUNKS 'JUNK' (LIXO/RESERVADO):\n"

        has_large_junk = False
        for j in all_junks:
            note = "Pequeno (Provável Alinhamento)"
            if j['size'] > 4096:
                note = "GRANDE (Suspeito: Esteganografia/Metadados Ocultos)"
                has_large_junk = True
            elif j['size'] > 100:
                note = "Médio (Possível resquício de edição)"

            final_report += f"  - Offset 0x{j['offset']:X} | Tamanho: {j['size']} bytes | {note}\n"

        final_report += "\n[GUIA DE INTERPRETAÇÃO JUNK]:\n"
        final_report += "  1. NORMAL: Pequenos JUNK (< 4KB) usados apenas para alinhamento de memória.\n"
        final_report += "  2. EDIÇÃO: Editores de vídeo muitas vezes deixam lixo de metadados antigos em JUNKs médios.\n"
        final_report += "  3. SUSPEITO: JUNKs enormes no início ou fim podem conter dados ocultos (Esteganografia/Vírus).\n"

        if has_large_junk:
            final_report += "\n⚠️ ALERTA: A presença de JUNKs grandes exige verificação hexadecimal manual.\n"

    else:
        final_report += "\n[OK] Nenhum chunk de lixo (JUNK) detectado. Estrutura otimizada.\n"

    final_report += "\n" + "=" * 85 + "\n"
    final_report += "REFERÊNCIA TÉCNICA (ESTRUTURA RIFF/AVI):\n"
    final_report += "[1] Microsoft Docs. AVI RIFF File Reference.\n"
    final_report += "    https://learn.microsoft.com/en-us/windows/win32/directshow/avi-riff-file-reference\n"

    return {"Forensic Report": final_report}
