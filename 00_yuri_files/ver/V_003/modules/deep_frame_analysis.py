# modules/deep_frame_analysis.py
import subprocess
import os
import sys
import json
from collections import Counter


def get_binary_path(binary_name):
    if '__compiled__' in globals():
        # Quando compilado com Nuitka, os binários estarão na pasta base do
        # executável
        base_path = os.path.dirname(sys.executable)
    elif getattr(sys, 'frozen', False):
        # Fallback para o PyInstaller (Onefile/Dir)
        base_path = getattr(sys, '_MEIPASS', os.path.abspath("."))
    else:
        # Modo de desenvolvimento
        base_path = os.path.abspath(".")
    return os.path.join(base_path, "bin", binary_name)


def get_ffprobe_gop_analysis(file_path):
    ffprobe_path = get_binary_path("ffprobe.exe")

    if not os.path.exists(ffprobe_path):
        return {
            "error": f"Executável não encontrado em:\n{ffprobe_path}\n\nVerifique se a pasta 'bin' existe na raiz."}

    cmd = [
        ffprobe_path,
        '-v',
        'error',
        '-select_streams',
        'v:0',
        '-show_entries',
        'frame=pict_type,pkt_size,coded_picture_number',
        '-of',
        'json',
        file_path]

    try:
        startupinfo = None
        if os.name == 'nt' and hasattr(subprocess, 'STARTUPINFO'):
            startupinfo = getattr(subprocess, 'STARTUPINFO')()
            startupinfo.dwFlags |= getattr(
                subprocess, 'STARTF_USESHOWWINDOW', 1)

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            startupinfo=startupinfo,
            encoding='utf-8')

        if result.returncode != 0:
            return {"error": f"Erro interno do FFprobe: {result.stderr}"}
        try:
            data = json.loads(result.stdout)
        except BaseException:
            return {"error": "Falha JSON."}

        frames = data.get('frames', [])
        total = len(frames)
        if total == 0:
            return {"error": "Nenhum frame decodificado."}

        i_count = 0
        p_count = 0
        b_count = 0
        gop_string = ""
        gop_lengths = []
        gop_start_indices = []
        last_i_index = 0
        display_limit = 200

        for idx, frame in enumerate(frames):
            p_type = frame.get('pict_type', '?').upper()
            if p_type == 'I':
                i_count += 1
                if idx > 0:
                    gop_string += "|"
                    gop_lengths.append(idx - last_i_index)
                    gop_start_indices.append(last_i_index + 1)
                    last_i_index = idx
            elif p_type == 'P':
                p_count += 1
            elif p_type == 'B':
                b_count += 1

            if len(gop_string) < display_limit:
                gop_string += p_type

        gop_lengths.append(total - last_i_index)
        gop_start_indices.append(last_i_index + 1)

        avg_gop = sum(gop_lengths) / len(gop_lengths) if gop_lengths else 0

        interpretation = []
        anomalies = []

        if len(gop_lengths) > 1:
            # ignora o último que pode ser incompleto
            ref_gops = gop_lengths[:-1]
            common_gop = Counter(ref_gops).most_common(1)[0][0]
            for idx, length in enumerate(gop_lengths[:-1]):
                if length < common_gop * 0.7 or length > common_gop * 1.3:
                    anomalies.append(
                        f"⚠️ GOP Irregular no Frame {gop_start_indices[idx]} (Tamanho: {length}). Padrão: {common_gop}.")
            interpretation.append(
                f"Padrão de GOP Detectado: Aprox. {common_gop} frames.")
            interpretation.append(
                "Veredito Estrutural: IRREGULAR (Indícios de Edição/Cortes)." if anomalies else "Veredito Estrutural: REGULAR.")
        elif len(gop_lengths) == 1:
            interpretation.append(
                "Padrão: GOP Único (Long GOP). Apenas 1 Keyframe inicial.")

        if b_count == 0 and p_count > 0:
            interpretation.append(
                "Perfil: Baseline/Simples (Sem B-Frames). Típico de CFTV/Real-Time.")
        elif b_count > 0:
            interpretation.append(
                "Perfil: Avançado/High (Com B-Frames). Comum em câmeras modernas.")

        # --- RELATÓRIO ---
        report = "--- ANÁLISE PROFUNDA (BITSTREAM REAL) ---\n"
        report += "METODOLOGIA: Leitura direta do fluxo de bits (Bitstream) utilizando o decodificador FFprobe.\n"
        report += "Diferente da análise heurística, este método identifica o tipo real de cada quadro (I, P, B)\n"
        report += "conforme gravado no stream de vídeo, garantindo precisão absoluta sobre a estrutura.\n"
        report += "\n" + "=" * 60 + "\n"

        report += f"Total Frames Decodificados: {total}\n\n"
        report += "[DISTRIBUIÇÃO REAL]\n"
        report += f"  - I-Frames (Intra): {i_count} \t({(i_count / total) * 100:.1f}%)\n"
        report += f"  - P-Frames (Pred):  {p_count} \t({(p_count / total) * 100:.1f}%)\n"
        report += f"  - B-Frames (Bi-dir):{b_count} \t({(b_count / total) * 100:.1f}%)\n\n"
        report += "[ESTRUTURA GOP]\n"
        report += f"  - Tamanho Médio: {avg_gop:.2f} frames\n"
        report += f"  - Quantidade de GOPs: {len(gop_lengths)}\n\n"

        report += "[INTERPRETAÇÃO FORENSE DO PERITO]\n"
        for item in interpretation:
            report += f"  - {item}\n"

        if anomalies:
            report += "\n[!] ANOMALIAS DE CONTINUIDADE (CORTES/DROPS):\n"
            for anomaly in anomalies[:15]:
                report += f"  {anomaly}\n"
            if len(anomalies) > 15:
                report += f"  ... e mais {len(anomalies) - 15} anomalias.\n"
            report += "\n  NOTA TÉCNICA: GOPs irregulares sugerem cortes manuais ou drops de gravação."

        # report += f"\n\n[VISUALIZAÇÃO (Início)]\n{gop_string}...\n"
        report += f"\n[VISUALIZAÇÃO ({display_limit} iniciais: )]\n{gop_string}...\n"

        report += "\n" + "=" * 60 + "\n"
        report += "METODOLOGIA APLICADA:\n"
        report += "Ferramenta: FFprobe (FFmpeg Suite)\n"
        report += "Sintaxe: ffprobe -v error -select_streams v:0 -show_entries frame=pict_type,pkt_size,coded_picture_number -of json <arquivo>\n"

        return {"report": report}

    except Exception as e:
        return {"error": f"Falha na execução: {str(e)}"}
