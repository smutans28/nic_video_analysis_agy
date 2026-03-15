# modules/frame_analysis.py

import os
from collections import Counter
from construct import (
    Struct, Int32ub, Int32ul, Array, If, PaddedString
)
from modules import file_structure

# --- ESTRUTURAS BINÁRIAS MP4 (Big Endian) ---
FullAtomHeader = Struct("version_flags" / Int32ub)

StssBox = Struct(
    "header" / FullAtomHeader,
    "entry_count" / Int32ub,
    "sample_numbers" / Array(lambda ctx: ctx.entry_count, Int32ub)
)

StszBox = Struct("header" / FullAtomHeader,
                 "sample_size" / Int32ub,
                 "sample_count" / Int32ub,
                 "entry_sizes" / If(lambda ctx: ctx.sample_size == 0,
                                    Array(lambda ctx: ctx.sample_count,
                                          Int32ub)))

# --- ESTRUTURAS BINÁRIAS AVI (Little Endian) ---
AviIndexEntry = Struct(
    "ckid" / PaddedString(4, "ascii"),
    "flags" / Int32ul,
    "offset" / Int32ul,
    "length" / Int32ul
)


# --- FUNÇÕES AUXILIARES ---
def find_atom_recursive(nodes, target_type):
    for node in nodes:
        if node['type'] == target_type:
            return node
        if node['children']:
            found = find_atom_recursive(node['children'], target_type)
            if found:
                return found
    return None


def get_mp4_video_data(file_path):
    analysis = file_structure.get_full_atom_analysis(file_path)
    tree = analysis.get("tree", [])
    if not tree:
        return {"error": "Estrutura MP4 inválida ou vazia."}

    moov = find_atom_recursive(tree, 'moov')
    if not moov:
        return {"error": "Moov não encontrado."}

    video_track = None
    for track in moov['children']:
        mdia = find_atom_recursive(track.get('children', []), 'mdia')
        if mdia:
            hdlr = find_atom_recursive(mdia.get('children', []), 'hdlr')
            if hdlr:
                video_track = track
                break

    if not video_track:
        return {"error": "Trilha de vídeo não identificada."}

    stbl = find_atom_recursive(video_track['children'], 'stbl')
    if not stbl:
        return {"error": "STBL não encontrado."}

    stss = find_atom_recursive(stbl['children'], 'stss')
    stsz = find_atom_recursive(stbl['children'], 'stsz')

    results = {'type': 'MP4'}
    try:
        with open(file_path, "rb") as f:
            if stss:
                f.seek(stss['offset'] + 8)
                data = f.read(stss['size'] - 8)
                parsed = StssBox.parse(data)
                results['keyframes'] = list(parsed.sample_numbers)
            else:
                results['keyframes'] = []

            if stsz:
                f.seek(stsz['offset'] + 8)
                data = f.read(stsz['size'] - 8)
                parsed = StszBox.parse(data)
                if parsed.sample_size > 0:
                    results['sizes'] = [
                        parsed.sample_size] * parsed.sample_count
                else:
                    results['sizes'] = list(parsed.entry_sizes)
            else:
                return {"error": "Tabela de tamanhos (stsz) ausente."}
    except Exception as e:
        return {"error": str(e)}

    return results


def get_avi_video_data(file_path):
    results = {'type': 'AVI', 'keyframes': [], 'sizes': []}
    try:
        file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as f:
            f.seek(12)
            while f.tell() < file_size:
                header_bytes = f.read(8)
                if len(header_bytes) < 8:
                    break
                chunk_id = header_bytes[:4].decode('ascii', errors='ignore')
                chunk_size = int.from_bytes(header_bytes[4:8], 'little')

                if chunk_id == 'idx1':
                    num_entries = chunk_size // 16
                    for i in range(num_entries):
                        entry_data = f.read(16)
                        if len(entry_data) < 16:
                            break
                        parsed = AviIndexEntry.parse(entry_data)
                        if b'dc' in parsed.ckid.encode(
                                'ascii') or b'db' in parsed.ckid.encode('ascii'):
                            frame_index = len(results['sizes']) + 1
                            results['sizes'].append(parsed.length)
                            if parsed.flags & 16:
                                results['keyframes'].append(frame_index)
                    return results

                seek_size = chunk_size + (chunk_size % 2)
                f.seek(seek_size, 1)
    except Exception as e:
        return {"error": f"Erro ao ler AVI: {str(e)}"}
    return {"error": "Índice AVI (idx1) não encontrado."}


# --- ANÁLISE PRINCIPAL ---

def analyze_gop_structure(file_path):
    is_avi = False
    try:
        with open(file_path, "rb") as f:
            if f.read(4) == b'RIFF':
                is_avi = True
    except BaseException:
        pass

    if is_avi:
        data = get_avi_video_data(file_path)
    else:
        data = get_mp4_video_data(file_path)

    if "error" in data:
        return {"report": f"ERRO: {data['error']}"}

    keyframes = set(data['keyframes'])
    sizes = data['sizes']
    total_frames = len(sizes)

    if total_frames == 0:
        return {"report": "Vídeo sem frames detectados."}

    non_key_sizes = [
        s for i, s in enumerate(sizes) if (
            i + 1) not in keyframes]
    avg_size = sum(non_key_sizes) / len(non_key_sizes) if non_key_sizes else 0

    gop_pattern = ""
    i_count = 0
    p_count = 0
    b_count = 0
    gop_lengths = []
    last_i = 0
    display_limit = 200

    for i in range(total_frames):
        frame_num = i + 1
        size = sizes[i]
        char = "?"
        if frame_num in keyframes:
            char = "I"
            i_count += 1
            if i > 0:
                gop_lengths.append(i - last_i)
                if len(gop_pattern) < display_limit:
                    gop_pattern += "|"
                last_i = i
        else:
            if size > avg_size * 0.85:
                char = "P"
                p_count += 1
            else:
                char = "B"
                b_count += 1

        if len(gop_pattern) < display_limit:
            gop_pattern += char

    if total_frames > last_i:
        gop_lengths.append(total_frames - last_i)

    if gop_lengths:
        gops_to_analyze = gop_lengths[:-
                                      1] if len(gop_lengths) > 1 else gop_lengths
        common_gop = Counter(gops_to_analyze).most_common(1)[0][0]
    else:
        common_gop = 0

    avg_gop_frames = sum(gop_lengths) / len(gop_lengths) if gop_lengths else 0

    anomalies = []
    for idx, length in enumerate(gop_lengths):
        if idx == len(gop_lengths) - 1:
            continue
        if length < common_gop * 0.7 or length > common_gop * 1.3:
            anomalies.append(
                f"⚠️ GOP Irregular no Frame ~{idx * common_gop} (Tamanho: {length}). Padrão: {common_gop}.")

    # --- RELATÓRIO COM EXPLICAÇÃO DIDÁTICA ---
    report = f"--- ANÁLISE DE GOP HEURÍSTICA (ESTRUTURA {data['type']}) ---\n"

    if data['type'] == 'MP4':
        report += "METODOLOGIA: Análise baseada nas tabelas de átomos do container (sem decodificação).\n"
        report += "Para montar o mapa dos frames (I, P, B), extraímos dados de três átomos específicos:\n"
        report += "  1. stss (Sync Sample): Lista os IDs dos I-Frames (Keyframes).\n"
        report += "  2. stsz (Sample Size): Lista o tamanho em bytes. Usado para diferenciar P de B (P > B).\n"
        report += "  3. stts (Time-to-Sample): Define a duração de cada frame.\n"
    else:
        report += "METODOLOGIA: Análise baseada na tabela de índice 'idx1' do container AVI.\n"
        report += "Identificação de Keyframes baseada nas flags do índice e diferenciação P/B por tamanho.\n"

    report += "\n" + "=" * 60 + "\n"
    report += f"Total de Frames: {total_frames}\n\n"

    report += "[DISTRIBUIÇÃO ESTIMADA]\n"
    report += f"  - I-Frames (Key): \t{i_count} \t({(i_count / total_frames) * 100:.1f}%)\n"
    report += f"  - P-Frames (Est): \t{p_count} \t({(p_count / total_frames) * 100:.1f}%)\n"
    report += f"  - B-Frames (Est): \t{b_count} \t({(b_count / total_frames) * 100:.1f}%)\n\n"

    report += "[ESTRUTURA E CONSISTÊNCIA]\n"
    report += f"  - Tamanho Padrão (Moda): {common_gop} frames\n"
    report += f"  - Tamanho Médio: \t{avg_gop_frames:.2f} frames\n\n"

    if anomalies:
        report += "[!] POSSÍVEIS PONTOS DE EDIÇÃO/CORTE:\n"
        for anomaly in anomalies[:10]:
            report += f"  {anomaly}\n"
        if len(anomalies) > 10:
            report += f"  ... e mais {len(anomalies) - 10} anomalias.\n"
    else:
        report += "[OK] Estrutura de GOP consistente.\n"

    report += f"\n[VISUALIZAÇÃO ({display_limit} iniciais: )]\n{gop_pattern}...\n"

    return {"report": report}
