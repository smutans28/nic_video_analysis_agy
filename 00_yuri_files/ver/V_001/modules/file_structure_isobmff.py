# modules/file_structure_isobmff.py

import os
import datetime
from construct import (
    Int32ub,
    Bytes,
    Struct,
    PaddedString,
    Int64ub,
    Array,
    If,
    Int16ub,
    Computed,
    GreedyBytes)

# --- 1. GLOSSÁRIO FORENSE ---
ATOM_DESCRIPTIONS = {
    'ftyp': "File Type - Cabeçalho que define a compatibilidade (Brand) e versão.",
    'moov': "Movie Container - O 'cérebro' do arquivo. Contém todos os metadados.",
    'mdat': "Media Data - O 'corpo' do arquivo. Contém os bits brutos de áudio/vídeo.",
    'free': "Free Space - Espaço reservado ignorado (pode indicar edição/re-save).",
    'skip': "Skip - Similar ao 'free', espaço ignorado pelo player.",
    'wide': "Wide - Reserva espaço para expandir o tamanho do arquivo (64-bit).",
    'trak': "Track Container - Define uma trilha individual (Vídeo, Áudio, Texto).",
    'tkhd': "Track Header - Características da trilha (duração, resolução, volume).",
    'edts': "Edit Container - Gere a linha do tempo e edições não lineares.",
    'elst': "Edit List - Mapeia o tempo da mídia para o tempo de apresentação.",
    'mdia': "Media Container - Informações sobre o tipo de mídia da trilha.",
    'mdhd': "Media Header - Escala de tempo (timescale) e duração da mídia.",
    'hdlr': "Handler Reference - Identifica o tipo da trilha (vide, soun, hint).",
    'minf': "Media Information - Container específico para o tipo de mídia.",
    'vmhd': "Video Media Header - Cabeçalho visual (cor, modo gráfico).",
    'smhd': "Sound Media Header - Cabeçalho sonoro (balanço).",
    'dinf': "Data Information - Container de localização dos dados.",
    'dref': "Data Reference - Tabela de URLs onde os dados estão.",
    'url ': "Data Entry URL - Localização dos dados.",
    'stbl': "Sample Table - A tabela de alocação. O mapa para decodificar o vídeo.",
    'stsd': "Sample Description - Define o formato de codificação (Codec).",
    'avc1': "AVC Video - O codec de vídeo H.264.",
    'avcC': "AVC Configuration - Configuração do decodificador H.264 (SPS/PPS).",
    'mp4a': "AAC Audio - O codec de áudio AAC.",
    'esds': "Elem. Stream Desc. - Configuração do decodificador AAC.",
    'stts': "Time-to-Sample - Define a duração de cada frame.",
    'ctts': "Composition Offset - Ajuste de tempo para B-Frames.",
    'stss': "Sync Sample - Lista de Keyframes (I-Frames).",
    'stsc': "Sample-to-Chunk - Agrupa amostras em blocos.",
    'stsz': "Sample Size - Tamanho em bytes de cada frame.",
    'stco': "Chunk Offset - Onde cada bloco começa (32-bit).",
    'co64': "Chunk Offset 64 - Onde cada bloco começa (64-bit).",
    'udta': "User Data - Metadados de usuário, tags e assinaturas.",
    'meta': "Metadata - Container genérico para metadados.",
    'ilst': "Item List - Lista de tags de metadados (Apple/iTunes).",
    'data': "Data Box - Contém o valor real de um metadado.",
    'pasp': "Pixel Aspect Ratio - Define a proporção do pixel.",
    'colr': "Color Parameter - Define perfil de cor e gama.",
    'clef': "Clean Aperture - Define a área visível da imagem.",
    'enof': "Production Aperture - Define as dimensões originais.",
    'mvhd': "Movie Header - Informações globais do filme (duração, timescale).",
    'sgpd': "Sample Group Desc - Propriedades de grupos de amostras.",
    'sbgp': "Sample to Group - Mapeamento de amostras para grupos.",
    'beam': "Beam - Átomo legado comum em transferências Android (WhatsApp antigo).",
    '©too': "Encoding Tool - Software usado para criar o arquivo.",
    '©xyz': "GPS Coordinates - Geolocalização.",
    '©day': "Creation Date - Data de criação em formato texto.",
    '©mak': "Maker - Fabricante do dispositivo.",
    '©mod': "Model - Modelo do dispositivo.",
    '©swr': "Software - Software usado no processamento.",
}


# --- 2. FUNÇÕES AUXILIARES ---

def mp4_timestamp_to_datetime(timestamp):
    if timestamp > 0:
        try:
            return datetime.datetime(1904, 1, 1) + \
                datetime.timedelta(seconds=timestamp)
        except BaseException:
            return "Data Inválida"
    return "N/D"


def fixed_point_to_float(value):
    return value / 65536.0


# --- 3. ESTRUTURAS CONSTRUCT (ATOMS) ---

BasicAtomHeader = Struct(
    "size32" / Int32ub,
    "type" / PaddedString(4, "ascii"),
    "size_extended" / If(lambda ctx: ctx.size32 == 1, Int64ub),
    "size" / Computed(lambda ctx: ctx.size_extended if ctx.size32 == 1 else ctx.size32)
)

# --- PAYLOADS DETALHADOS ---

FtypData = Struct(
    "major_brand" / PaddedString(4, "ascii"),
    "minor_version" / Int32ub,
    "compatible_brands_raw" / GreedyBytes
)

HdlrData = Struct(
    "version_flags" / Int32ub,
    "pre_defined" / Int32ub,
    "handler_type" / PaddedString(4, "ascii"),
    "reserved" / Bytes(12),
    "name_raw" / GreedyBytes
)

TkhdData = Struct(
    "version_flags" /
    Int32ub,
    "creation_time_raw" /
    Int32ub,
    "modification_time_raw" /
    Int32ub,
    "track_ID" /
    Int32ub,
    "reserved1" /
    Int32ub,
    "duration" /
    Int32ub,
    "reserved2" /
    Int64ub,
    "layer" /
    Int16ub,
    "alternate_group" /
    Int16ub,
    "volume" /
    Int16ub,
    "reserved3" /
    Int16ub,
    "matrix" /
    Array(
        9,
        Int32ub),
    "width_raw" /
    Int32ub,
    "height_raw" /
    Int32ub,
    "creation_time_dt" /
    Computed(
        lambda ctx: mp4_timestamp_to_datetime(
            ctx.creation_time_raw)),
    "modification_time_dt" /
    Computed(
        lambda ctx: mp4_timestamp_to_datetime(
            ctx.modification_time_raw)),
    "width_float" /
    Computed(
        lambda ctx: fixed_point_to_float(
            ctx.width_raw)),
    "height_float" /
    Computed(
        lambda ctx: fixed_point_to_float(
            ctx.height_raw)),
)

MvhdData = Struct(
    "version_flags" /
    Int32ub,
    "creation_time_raw" /
    Int32ub,
    "modification_time_raw" /
    Int32ub,
    "timescale" /
    Int32ub,
    "duration" /
    Int32ub,
    "rate" /
    Int32ub,
    "volume" /
    Int16ub,
    "reserved" /
    Bytes(10),
    "matrix" /
    Array(
        9,
        Int32ub),
    "pre_defined" /
    Array(
        6,
        Int32ub),
    "next_track_ID" /
    Int32ub,
    "creation_time_dt" /
    Computed(
        lambda ctx: mp4_timestamp_to_datetime(
            ctx.creation_time_raw)),
    "modification_time_dt" /
    Computed(
        lambda ctx: mp4_timestamp_to_datetime(
            ctx.modification_time_raw)),
)

DataAtomData = Struct(
    "type_indicator" / Int32ub,
    "locale" / Int32ub,
    "raw_value" / GreedyBytes,
)

DrefData = Struct("version_flags" / Int32ub, "entry_count" / Int32ub)
VisualSampleEntryHeader = Struct(
    "reserved1" /
    Bytes(6),
    "data_reference_index" /
    Int16ub,
    "reserved2" /
    Int16ub,
    "reserved3" /
    Int16ub,
    "reserved4" /
    Array(
        3,
        Int32ub),
    "width" /
    Int16ub,
    "height" /
    Int16ub,
    "horiz_resolution" /
    Int32ub,
    "vert_resolution" /
    Int32ub,
    "reserved5" /
    Int32ub,
    "frame_count" /
    Int16ub,
    "compressor_name" /
    PaddedString(
        32,
        "ascii"),
    "depth" /
    Int16ub,
    "pre_defined" /
    Int16ub)
AudioSampleEntryHeader = Struct(
    "reserved1" /
    Bytes(6),
    "data_reference_index" /
    Int16ub,
    "reserved2" /
    Array(
        2,
        Int32ub),
    "channel_count" /
    Int16ub,
    "sample_size" /
    Int16ub,
    "pre_defined" /
    Int16ub,
    "reserved3" /
    Int16ub,
    "sample_rate" /
    Int32ub)

ATOM_PAYLOAD_MAP = {
    'tkhd': TkhdData, 'mvhd': MvhdData, 'dref': DrefData,
    'avc1': VisualSampleEntryHeader, 'mp4a': AudioSampleEntryHeader,
    'data': DataAtomData,
    'ftyp': FtypData,
    'hdlr': HdlrData
}

CONTAINER_ATOMS = [
    'moov', 'trak', 'mdia', 'minf', 'stbl', 'udta', 'meta', 'ilst',
    'edts', 'dinf', 'stsd', 'avc1', 'mp4a', 'dref', 'url '
]

CONTAINER_SKIP_BYTES = {
    'dref': 8, 'stsd': 8, 'avc1': 78, 'mp4a': 28, 'meta': 4
}


# --- 4. PARSING RECURSIVO ---

def parse_atom_tree(stream, start_offset, end_offset):
    tree = []
    current_offset = start_offset

    while current_offset < end_offset:
        stream.seek(current_offset)
        try:
            header = BasicAtomHeader.parse_stream(stream)
            atom_size = header.size
            atom_type = header.type
            header_len = stream.tell() - current_offset
        except Exception:
            break

        if atom_size == 0 or current_offset + atom_size > end_offset:
            break

        atom_entry = {
            "type": atom_type,
            "size": atom_size,
            "offset": current_offset,
            "contents": None,
            "children": [],
            "forensic_flags": []
        }

        payload_absolute_start = current_offset + header_len

        try:
            is_metadata_key = atom_type.startswith(
                b'\xa9'.decode('latin1')) or atom_type in [
                'covr', 'gnre', 'trkn', 'disk']

            if atom_type in CONTAINER_ATOMS or is_metadata_key:
                skip = CONTAINER_SKIP_BYTES.get(atom_type, 0)
                atom_entry["children"] = parse_atom_tree(
                    stream, payload_absolute_start + skip, current_offset + atom_size)

            elif atom_type in ATOM_PAYLOAD_MAP:
                stream.seek(payload_absolute_start)

                if atom_type == 'data':
                    raw_data = stream.read(atom_size - header_len)
                    parsed = ATOM_PAYLOAD_MAP['data'].parse(raw_data)
                    atom_entry["contents"] = parsed
                    if parsed.type_indicator == 1 and parsed.raw_value:
                        try:
                            atom_entry["contents"]["text_value"] = parsed.raw_value.decode(
                                'utf-8', errors='ignore')
                        except BaseException:
                            pass

                elif atom_type == 'ftyp':
                    raw_data = stream.read(atom_size - header_len)
                    parsed = ATOM_PAYLOAD_MAP['ftyp'].parse(raw_data)
                    atom_entry["contents"] = dict(parsed)
                    try:
                        atom_entry["contents"]["compatible_brands"] = parsed.compatible_brands_raw.decode(
                            'ascii', errors='ignore').replace('\x00', '')
                    except BaseException:
                        pass

                elif atom_type == 'hdlr':
                    raw_data = stream.read(atom_size - header_len)
                    parsed = ATOM_PAYLOAD_MAP['hdlr'].parse(raw_data)
                    atom_entry["contents"] = dict(parsed)
                    try:
                        atom_entry["contents"]["handler_name"] = parsed.name_raw.replace(
                            b'\x00', b'').decode('ascii', errors='ignore')
                    except BaseException:
                        pass

                else:
                    data = ATOM_PAYLOAD_MAP[atom_type].parse_stream(stream)
                    atom_entry["contents"] = data.as_dict()

                if atom_type == 'tkhd' and data.width_float == 0 and data.height_float == 0:
                    atom_entry["forensic_flags"].append("Dimensões Zero")

        except Exception:
            pass

        tree.append(atom_entry)
        current_offset += atom_size

    return tree


def count_atoms_recursive(nodes):
    """Conta o número total de átomos na árvore recursivamente."""
    count = 0
    for node in nodes:
        count += 1
        if node['children']:
            count += count_atoms_recursive(node['children'])
    return count


def get_full_atom_analysis(file_path):
    if not os.path.exists(file_path):
        return {"tree": [], "report": "Arquivo não encontrado."}
    try:
        file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as f:
            atom_tree = parse_atom_tree(f, 0, file_size)
        return {"tree": atom_tree, "report": "Análise concluída."}
    except Exception as e:
        return {"tree": [], "report": f"Erro fatal: {e}"}


# --- 5. EXTRAÇÃO DE DADOS FORENSES ---

def extract_forensic_artifacts(tree, results=None):
    if results is None:
        results = {
            "dates": [],
            "software": [],
            "inconsistencies": [],
            "brands": [],
            "handlers": []}

    for atom in tree:
        if atom['type'] in ['free', 'skip', 'wide']:
            results["inconsistencies"].append(
                f"🔎 **Espaço Livre Detectado:** '{atom['type']}' no offset 0x{atom['offset']:X}."
            )

        if atom['type'] == 'ftyp' and atom['contents']:
            maj = atom['contents'].get('major_brand', '')
            comp = atom['contents'].get('compatible_brands', '')
            results["brands"].append(f"Major: {maj} | Compatible: {comp}")

        if atom['type'] == 'hdlr' and atom['contents']:
            h_name = atom['contents'].get('handler_name', '')
            h_type = atom['contents'].get('handler_type', '')
            if h_name:
                results["handlers"].append(f"{h_type}: {h_name}")

        if atom['type'] in ['mvhd', 'tkhd', 'mdhd'] and atom['contents']:
            c_date = atom['contents'].get('creation_time_dt')
            m_date = atom['contents'].get('modification_time_dt')
            if c_date and c_date != 'N/D':
                results["dates"].append(f"[{atom['type']}] Criação: {c_date}")
            if m_date and m_date != 'N/D':
                results["dates"].append(
                    f"[{atom['type']}] Modificação: {m_date}")

        for child in atom['children']:
            if child['type'] == 'data' and child['contents'] and 'text_value' in child['contents']:
                key_name = atom['type']
                value = child['contents']['text_value']
                clean_key = key_name
                if isinstance(clean_key, bytes):
                    clean_key = clean_key.decode('latin1')
                results["software"].append(f"{clean_key}: {value}")
        if atom['children']:
            extract_forensic_artifacts(atom['children'], results)
    return results


# --- 6. PONTO DE ENTRADA FORENSE ---

def analyze_atom_structure(file_path):
    full_analysis = get_full_atom_analysis(file_path)
    if "Erro" in full_analysis.get("report"):
        return {"Forensic Report": full_analysis["report"]}

    atom_tree = full_analysis["tree"]
    file_name = os.path.basename(file_path)

    deep_data = extract_forensic_artifacts(atom_tree)
    stats = os.stat(file_path)
    sys_ctime = datetime.datetime.fromtimestamp(stats.st_ctime)
    sys_mtime = datetime.datetime.fromtimestamp(stats.st_mtime)

    found_atom_types = []

    # Contagem Total
    total_structures = count_atoms_recursive(atom_tree)

    # Sequência de Raiz (Fingerprint Rápido)
    root_sequence = " >> ".join([a['type'] for a in atom_tree])

    # Formatação da Tabela
    def format_tree(nodes, level=0):
        output = []
        col_type_width = 40
        col_size_width = 12
        for atom in nodes:
            if atom['type'] not in found_atom_types:
                found_atom_types.append(atom['type'])

            indent_str = "  " * level + "| " + str(atom['type'])
            type_col = f"{indent_str:<{col_type_width}}"
            size_col = f"{atom['size']:>{col_size_width}}"
            offset_col = f"0x{atom['offset']:08X}"

            line = f"| {type_col} | Size: {size_col} | Offset: {offset_col} |"
            if atom['forensic_flags']:
                line += f" FLAGS: {', '.join(atom['forensic_flags'])}"
            output.append(line)

            if atom['contents']:
                content_indent = " " * (level * 2 + 4)
                for k, v in atom['contents'].items():
                    if k in [
                        'major_brand',
                        'compatible_brands',
                        'handler_name',
                            'text_value']:
                        output.append(f"{content_indent}>>> {k.upper()}: {v}")
                    elif k.endswith('_dt') and v:
                        output.append(f"{content_indent}- {k}: {v}")
                    elif k.endswith('_float'):
                        output.append(f"{content_indent}- {k}: {v:.2f}")
                    elif k == 'compressor_name':
                        output.append(f"{content_indent}- Compressor: {v}")

            if atom['children']:
                output.extend(format_tree(atom['children'], level + 1))
        return output

    def format_clean_tree(nodes, level=0):
        output = []
        indent = "  " * level
        for atom in nodes:
            output.append(f"{indent}{atom['type']}")
            if atom['children']:
                output.extend(format_clean_tree(atom['children'], level + 1))
        return output

    tree_visual_detailed = "\n".join(format_tree(atom_tree))
    tree_visual_clean = "\n".join(format_clean_tree(atom_tree))

    # --- MONTAGEM DO TEXTO FINAL ---
    final_report = f"ARQUIVO: {file_name}\n"
    final_report += "=" * 85 + "\n\n"

    header = f"| {'ESTRUTURA DETALHADA (TABELA)':<41}| {'TAMANHO':>18} | {'OFFSET':<18} |"
    final_report += f"{header}\n" + "-" * 85 + "\n"
    final_report += tree_visual_detailed + "\n\n"

    final_report += "=" * 85 + "\n"
    final_report += "--- ESTRUTURA DE ÁTOMOS (FINGERPRINT) ---\n"
    final_report += "(Copie esta seção para comparar com assinaturas conhecidas)\n"
    final_report += "=" * 85 + "\n"
    final_report += tree_visual_clean + "\n\n"

    final_report += "=" * 85 + "\n"
    final_report += "--- GLOSSÁRIO ESTRUTURAL (Ordem de Aparição) ---\n"
    for atom_type in found_atom_types:
        clean_type = atom_type
        if isinstance(clean_type, bytes):
            clean_type = clean_type.decode('latin1', errors='ignore')
        desc = ATOM_DESCRIPTIONS.get(clean_type, "Descrição não disponível.")
        final_report += f"[{clean_type}] : {desc}\n"

    final_report += "\n" + "=" * 85 + "\n"
    final_report += "-- ANÁLISE FORENSE DA ESTRUTURA --\n"
    final_report += "=" * 85 + "\n"

    # --- NOVO: RESUMO ESTRUTURAL ---
    final_report += "[+] RESUMO ESTRUTURAL:\n"
    final_report += f"  - Sequência de Raiz: {root_sequence}\n"
    final_report += f"  - Total de Estruturas (Átomos): {total_structures}\n\n"

    moov_atom = next((a for a in atom_tree if a['type'] == 'moov'), None)
    mdat_atom = next((a for a in atom_tree if a['type'] == 'mdat'), None)

    if moov_atom and mdat_atom:
        final_report += "[+] Interpretação do Layout (Atom Order):\n"
        if moov_atom['offset'] > mdat_atom['offset']:
            final_report += "  - 'moov' (Metadados) no FIM. (Download Progressivo/Câmera/WhatsApp).\n"
        else:
            final_report += "  - 'moov' (Metadados) no INÍCIO. (Fast-Start/Streaming/Edição).\n"

    if deep_data["brands"]:
        final_report += "\n[+] Marcas de Compatibilidade (FTYP):\n"
        for b in deep_data["brands"]:
            final_report += f"  - {b}\n"

    if deep_data["inconsistencies"]:
        final_report += "\n[!] Anomalias Estruturais Detectadas:\n"
        for inc in deep_data["inconsistencies"]:
            final_report += f"{inc}\n"

    final_report += "\n[+] Cronologia de Datas (SO):\n"
    final_report += f"  - [Sistema] Criação: \t{sys_ctime}\n"
    final_report += f"  - [Sistema] Modificação: \t{sys_mtime}\n"
    unique_dates = sorted(list(set(deep_data["dates"])))
    for d in unique_dates:
        final_report += f"  - {d}\n"

    if deep_data["software"]:
        final_report += "\n[+] Artefatos de Software/Metadados:\n"
        for s in deep_data["software"]:
            tag_key = s.split(':')[0]
            desc = ATOM_DESCRIPTIONS.get(tag_key, "Tag Customizada")
            final_report += f"  - {s} ({desc})\n"

    # BIBLIOGRAFIA
    final_report += "\n" + "=" * 85 + "\n"
    final_report += "REFERÊNCIAS CIENTÍFICAS (BASE DA ANÁLISE):\n"
    final_report += "[1] Huamán, C. Q., Orozco, A. L. S., & Villalba, L. J. G. (2020). Authentication and\n"
    final_report += "    integrity of smartphone videos through multimedia container structure analysis.\n"
    final_report += "    Future Generation Computer Systems, 108, 15-33.\n\n"
    final_report += "[2] Ramos López, R., Almaraz Luengo, E., Sandoval Orozco, A. L., & García Villalba, L. J.\n"
    final_report += "    (2020). Digital Video Source Identification based on Container's Structure Analysis.\n"
    final_report += "    IEEE Access, 8, 2020.\n"

    return {"Forensic Report": final_report}
