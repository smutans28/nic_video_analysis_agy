# modules/ai_detection.py

from modules import file_info, file_structure

# --- ASSINATURAS CONHECIDAS ---

# Softwares que indicam edição manual/ferramentas (Penalidade)
SOFTWARE_SIGNATURES = [
    "Lavf", "ffmpeg", "HandBrake", "Adobe", "Premiere", "After Effects",
    "Sony Vegas", "DaVinci", "OBS", "XSplit", "Android Encoder", "microsoft",
    "VirtualDub", "MEncoder", "Bandicam"
]

# Handlers Genéricos (Podem ser IA ou Social Media - Depende do contexto)
GENERIC_HANDLERS = ["VideoHandler", "SoundHandler"]

# Softwares/Marcas de Câmeras (Bonificação)
CAMERA_SIGNATURES = [
    "Apple", "iPhone", "Samsung", "Galaxy", "Canon", "Nikon", "Sony",
    "GoPro", "DJI", "xiaomi", "Huawei", "LG", "Motorola", "Core Media"
]

# --- BASE DE CONHECIMENTO (FINGERPRINTS) ---
KNOWN_SIGNATURES_MP4 = {
    # 1. Mensageiros (Processamento Local)
    "WhatsApp (Android Legacy/Beam)": {
        "criteria": lambda atoms, moov_pos, info: "beam" in atoms,
        "source": "Huamán et al., 2020",
        "desc": "Processamento local Android (átomo 'beam')."
    },
    "WhatsApp / Instagram (Modern Android)": {
        "criteria": lambda atoms, moov_pos, info:
        atoms[:3] == ['ftyp', 'free', 'mdat'] and moov_pos == "end",
        "source": "Observed Pattern & Yang et al. (2024)",
        "desc": "Padrão moderno de codificação Android."
    },
    "Telegram (Android)": {
        "criteria": lambda atoms, moov_pos, info:
        atoms[:2] == ['ftyp', 'mdat'] and moov_pos == "end" and "beam" not in atoms,
        "source": "Huamán et al., 2020",
        "desc": "Processamento Telegram."
    },

    # 2. Redes Sociais / Streaming (Processamento Servidor)
    "Facebook / Instagram / Twitter (Meta Generic)": {
        "criteria": lambda atoms, moov_pos, info:
        # Baseado na Tabela 11 de Huamán et al. (2020)
        "isom" in info["major"] and
        ("VideoHandler" in str(info.get("handler_name", ""))
         or "SoundHandler" in str(info.get("handler_name", ""))),
        "source": "Huamán et al., 2020 (Table 11)",
        "desc": "Padrão 'isom' com Handler genérico. Típico de Facebook, Instagram e Twitter."
    },
    "YouTube (Streaming)": {
        "criteria": lambda atoms, moov_pos, info:
        "mp42" in info["major"] and "isommp42" in info["comp"] and moov_pos == "start",
        "source": "Yang et al., 2024 & Huamán et al.",
        "desc": "Assinatura de streaming do YouTube."
    },
    "YouTube (Google Servers)": {
        "criteria": lambda atoms, moov_pos, info:
        "Google" in str(info.get("handler_name", "")),
        "source": "Ramos López et al., 2020",
        "desc": "Handler explícito 'Google Inc'."
    },

    # 3. Originais e Editores
    "iPhone Original (Camera)": {
        "criteria": lambda atoms, moov_pos, info:
        "wide" in atoms and "qt" in info["major"].strip(
        ) and moov_pos == "end",
        "source": "Huamán et al., 2020",
        "desc": "Captura original iOS (QuickTime)."
    },
    "Adobe Premiere / Editing": {
        "criteria": lambda atoms, moov_pos, info: "uuid" in atoms,
        "source": "Yang et al., 2021",
        "desc": "Presença de átomo 'uuid' (XMP Metadata)."
    }
}


# --- EXTRAÇÃO ---
def extract_info_from_tree(tree):
    info = {"major": "", "comp": "", "handler_name": [], "all_strings": []}
    if not tree:
        return info

    def traverse(nodes):
        for node in nodes:
            if node['type'] == 'ftyp' and node.get('contents'):
                info["major"] = node['contents'].get('major_brand', '')
                info["comp"] = node['contents'].get('compatible_brands', '')
            if node['type'] == 'hdlr' and node.get('contents'):
                h_name = node['contents'].get('handler_name', '')
                if h_name:
                    info["handler_name"].append(h_name)
            if node.get('contents') and 'text_value' in node['contents']:
                info["all_strings"].append(node['contents']['text_value'])
            if node.get('children'):
                traverse(node['children'])

    traverse(tree)
    return info


def match_platform_signature(tree_structure, extracted_info):
    if not tree_structure:
        return []
    root_atoms = [node['type'] for node in tree_structure]
    moov_idx = -1
    mdat_idx = -1
    for i, atom in enumerate(root_atoms):
        if atom == 'moov':
            moov_idx = i
        if atom == 'mdat':
            mdat_idx = i
    moov_pos = "start" if moov_idx < mdat_idx and moov_idx != -1 else "end"

    matches = []
    for name, signature in KNOWN_SIGNATURES_MP4.items():
        try:
            if signature["criteria"](root_atoms, moov_pos, extracted_info):
                matches.append(
                    f"✅ **{name}**\n    Ref: {signature['source']}\n    Nota: {signature['desc']}")
        except BaseException:
            pass
    return matches


# --- HELPER AVI ---
def find_avi_software_tag(tree):
    found = []
    for node in tree:
        if node['type'] == 'ISFT' and node['contents'] and 'text_value' in node['contents']:
            found.append(node['contents']['text_value'])
        if node['children']:
            found.extend(find_avi_software_tag(node['children']))
    return found


def calculate_avi_score(tree, info_data):
    score = 50
    report = ["--- RELATÓRIO DE SCORE DE AUTENTICIDADE (AVI/RIFF) ---"]
    softwares = find_avi_software_tag(tree)
    has_editing = False
    if softwares:
        sw_str = ", ".join(softwares)
        report.append(f"Software (ISFT): {sw_str}")
        if any(sig.lower() in sw_str.lower() for sig in SOFTWARE_SIGNATURES):
            score += 40
            has_editing = True
            report.append("🔴 [+40] Edição detectada.")
        elif any(sig.lower() in sw_str.lower() for sig in CAMERA_SIGNATURES):
            score -= 30
            report.append("🟢 [-30] Câmera detectada.")
    else:
        report.append("⚪ [ 0] Nenhuma assinatura ISFT.")

    codec = info_data.get("Codec (Vídeo)", "").lower()
    if "hevc" in codec or "h265" in codec:
        score -= 10
        report.append("🟢 [-10] HEVC em AVI (Típico DVR).")

    score = max(0, min(100, score))
    verdict = "ALTA PROBABILIDADE DE EDIÇÃO" if has_editing else "INDETERMINADO" if score > 40 else "COMPATÍVEL COM ORIGINAL (DVR)"
    return {
        "score": score,
        "report": "\n".join(report) +
        f"\n\nSCORE: {score}/100\nRESULTADO: {verdict}",
        "verdict": verdict}


# --- CÁLCULO MPEG-PS (MPG) ---
def calculate_mpg_score(struct_data, info_data):
    score = 50
    report = ["--- RELATÓRIO DE SCORE DE AUTENTICIDADE (MPEG-PS) ---"]
    
    # Extrai as estastísticas geradas pelo file_structure_mpg
    stats = struct_data.get("stats", {})
    anomalies = stats.get("anomalies", [])
    
    # 1. Anomalias Temporais (Cortes/Edições)
    if anomalies:
        score += 40
        report.append(f"🔴 [+40] {len(anomalies)} anomalias temporais severas (SCR gaps) detectadas.")
        report.append("     Sinal forte de manipulação (cortes, edição NLE, ou concatenação).")
    else:
        report.append("🟢 [ 0] Continuidade de tempo SCR preservada.")
        
    # 2. Private Streams (Geralmente indica metadados inseridos por câmeras complexas ou softwares de edição)
    private_pes = stats.get("private_pes", 0)
    if private_pes > 0:
        # Penalizamos levemente porque softwares como Premiere e Vegas injetam XMP aqui, 
        # mas câmeras como Sony (Klv) também podem.
        score += 15
        report.append(f"🟠 [+15] Detectados {private_pes} 'Private Streams' (0xBD/0xBF).")
        report.append("     Frequentemente usado por softwares de edição para embutir metadados proprietários.")
        
    # 3. Metadados do Container (via MediaInfo / file_info)
    encoder = info_data.get("Software de Codificação", "N/D").strip()
    if encoder != "N/D":
        if any(sig.lower() in encoder.lower() for sig in SOFTWARE_SIGNATURES):
            score += 30
            report.append(f"🔴 [+30] Software de edição explícito detectado nos metadados: '{encoder}'")
        elif any(sig.lower() in encoder.lower() for sig in CAMERA_SIGNATURES):
            score -= 30
            report.append(f"🟢 [-30] Assinatura de hardware/câmera detectada: '{encoder}'")
        else:
            report.append(f"⚪ Encoder genérico ou não catalogado: '{encoder}'")
    else:
        report.append("⚪ Sem metadados explícitos de encoder.")

    score = max(0, min(100, score))
    
    if score < 30:
        verdict = "COMPATÍVEL COM CAPTURA DIRETA (EX: DVD-Cam / Analógico / DVR Antigo)"
    elif score > 75:
        verdict = "ALTA PROBABILIDADE DE EDIÇÃO/MONTAGEM"
    else:
        verdict = "INDETERMINADO / POSSÍVEL RECODE LEVE"

    return {
        "score": score,
        "report": "\n".join(report) + f"\n\nSCORE: {score}/100\nRESULTADO: {verdict}",
        "verdict": verdict
    }


# --- CÁLCULO PRINCIPAL MP4 ---
def calculate_mp4_score(tree, info_data, file_path):
    score = 50
    report = ["--- RELATÓRIO DE SCORE DE AUTENTICIDADE (ISOBMFF) ---"]

    extended_info = extract_info_from_tree(tree)
    struct_artifacts = file_structure.extract_forensic_artifacts(tree)

    report.append(
        f"Brands: {extended_info['major']} / {extended_info['comp']}")
    handlers = extended_info['handler_name']
    handlers_str = ", ".join(handlers) if handlers else "Nenhum / Vazio"
    report.append(f"Handlers: {handlers_str}")

    handler_hints = []
    for h in handlers:
        if "Core Media" in h:
            handler_hints.append("Apple iOS/macOS (Original)")
        elif "VideoHandle" in h and "r" not in h[-1:]:
            handler_hints.append("Android (Huawei/Samsung/Genérico)")
        elif "VideoHandler" in h:
            handler_hints.append(
                "FFmpeg/Genérico (Possível Edição ou Social Media)")
        elif "Google" in h:
            handler_hints.append("Google/YouTube Services")
    if handler_hints:
        report.append(f"  ↳ Sugestão: {', '.join(list(set(handler_hints)))}")
    elif not handlers:
        report.append(
            "  ↳ Sugestão: Compatível com Social Media (Metadados Removidos)")

    # 1. Fingerprinting
    detected_platforms = match_platform_signature(tree, extended_info)
    is_social_media = False

    if detected_platforms:
        report.append("\n[🔍] FINGERPRINT DETECTADO:")
        for p in detected_platforms:
            report.append(p)
            if "Original" in p:
                score -= 30
            # Se identificou qualquer rede social ou mensageiro
            if any(
                x in p for x in [
                    "WhatsApp",
                    "Facebook",
                    "Instagram",
                    "YouTube",
                    "Telegram",
                    "Line",
                    "Discord",
                    "Meta"]):
                is_social_media = True
                score += 10  # Score base sobe pouco
    else:
        report.append("\n[?] Nenhuma assinatura estrutural conhecida.")

    report.append("\n[ANÁLISE DE METADADOS]")

    # 2. Software e Handlers (Lógica Inteligente)
    all_signatures = struct_artifacts.get("software", []) + handlers
    found_sw_clean = [s.split(":")[1].strip(
    ) if ":" in s else s for s in all_signatures]

    # Verifica assinaturas
    has_explicit_edit = any(sig.lower() in str(
        found_sw_clean).lower() for sig in SOFTWARE_SIGNATURES)
    has_cam = any(sig.lower() in str(found_sw_clean).lower()
                  for sig in CAMERA_SIGNATURES)

    # Verifica se os únicos "softwares" encontrados são os Handlers Genéricos
    only_generic_handlers = False
    if has_explicit_edit:
        # Filtra o que foi achado
        detected_sw = [s for s in found_sw_clean if any(
            x.lower() in s.lower() for x in SOFTWARE_SIGNATURES)]
        # Se tudo o que achamos for "VideoHandler" ou "SoundHandler", e já
        # sabemos que é Social Media...
        if all(any(gh in s for gh in GENERIC_HANDLERS)
               for s in detected_sw) and is_social_media:
            only_generic_handlers = True

    if has_explicit_edit and not only_generic_handlers:
        score += 30
        detected = [s for s in found_sw_clean if any(
            x.lower() in s.lower() for x in SOFTWARE_SIGNATURES)]
        report.append(
            f"🔴 [+30] Software/Library de Edição detectado: {list(set(detected))}")
    elif only_generic_handlers:
        report.append(
            "⚪ [ 0] Handlers genéricos detectados (VideoHandler), esperado para plataforma identificada.")
    elif has_cam:
        score -= 40
        detected = [s for s in found_sw_clean if any(
            x.lower() in s.lower() for x in CAMERA_SIGNATURES)]
        report.append(
            f"🟢 [-40] Assinatura de Câmera/Hardware detectada: {list(set(detected))}")
    else:
        report.append("⚪ [ 0] Nenhuma assinatura explícita de software.")

    # 3. GPS
    struct_report_text = file_structure.analyze_atom_structure(file_path)[
        "Forensic Report"]
    has_gps = "©xyz" in struct_report_text or "location" in struct_report_text.lower()

    if has_gps:
        score -= 40
        report.append("🟢 [-40] GPS encontrado.")
    else:
        pen = 0 if is_social_media else 15
        score += pen
        report.append(f"🟠 [+{pen}] Ausência de GPS.")

    creation_date = info_data.get("Data de Criação (Interna)", "N/D")
    if "1904" in str(creation_date) or "N/D" in str(creation_date):
        pen = 5 if is_social_media else 15
        score += pen
        report.append(f"🟠 [+{pen}] Data interna zerada.")

    score = max(0, min(100, score))
    verdict = ""
    if is_social_media:
        verdict = "PROCESSADO POR REDE SOCIAL (METADADOS DESCARTADOS)"
        if score > 80:
            score = 65
    elif score < 30:
        verdict = "COMPATÍVEL COM ORIGINAL DE CÂMERA"
    elif score > 75:
        verdict = "ALTA PROBABILIDADE DE EDIÇÃO/IA"
    else:
        verdict = "INDETERMINADO / POSSÍVEL EDIÇÃO LEVE"

    final_report = "\n".join(report)
    final_report += "\n" + "=" * 60 + "\n"
    final_report += f"SCORE TÉCNICO: {score}/100\nVEREDITO: {verdict}\n"

    final_report += "\n" + "=" * 60 + "\n"
    final_report += "BIBLIOGRAFIA CIENTÍFICA:\n"
    final_report += "[1] Huamán et al. (2020). Authentication and integrity of smartphone videos.\n"
    final_report += "[2] Ramos López et al. (2020). Digital Video Source Identification.\n"
    final_report += "[3] Yang et al. (2021). Efficient video integrity analysis.\n"
    final_report += "[4] Yang et al. (2024). Video source identification (16 IMAs Case Study).\n"

    return {"score": score, "report": final_report, "verdict": verdict}


# ... (Ponto de entrada continua igual) ...
def calculate_authenticity_score(file_path):
    info_data = file_info.get_forensic_data(file_path)["simplified"]
    try:
        with open(file_path, "rb") as f:
            if f.read(5) == b'DAHUA' or file_path.lower().endswith('.dav'):
                return {
                    "score": 0,
                    "report": "Formato Proprietário DVR (Dahua). Compatível com Original.",
                    "verdict": "ORIGINAL CFTV"}
    except BaseException:
        pass

    analysis = file_structure.get_full_atom_analysis(file_path)
    tree = analysis.get("tree", [])
    video_type = analysis.get("type", "UNKNOWN")

    if video_type == "AVI":
        return calculate_avi_score(tree, info_data)
    elif video_type == "MPEG-PS":
        return calculate_mpg_score(analysis, info_data)
    elif video_type == "ISOBMFF" or (tree and tree[0]['type'] == 'ftyp'):
        return calculate_mp4_score(tree, info_data, file_path)
    else:
        return {
            "score": 0,
            "report": "Formato não suportado.",
            "verdict": "N/A"}
