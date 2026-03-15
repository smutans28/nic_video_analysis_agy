# modules/file_structure.py (O DESPACHANTE V3)
import os

# Importação dinâmica dos módulos
try:
    from modules import file_structure_isobmff
    from modules import file_structure_riff
    from modules import file_structure_dav  # NOVO
    from modules import file_structure_mpg  # NOVO MPEG-PS
except ImportError as e:
    print(f"ERRO CRÍTICO IMPORT: {e}")
    file_structure_isobmff = None
    file_structure_riff = None
    file_structure_dav = None
    file_structure_mpg = None


def identify_container(file_path):
    """Identifica a família do arquivo (MP4, AVI, DAV)."""
    if not os.path.exists(file_path):
        return None

    # 1. Verificação por Extensão (Forte indício para DAV e MPG)
    ext = os.path.splitext(file_path)[1].lower()
    if ext == '.dav':
        return "DAHUA_DAV"
    elif ext in ['.mpg', '.mpeg', '.vob', '.ps']:
        return "MPEG_PS"

    try:
        with open(file_path, "rb") as f:
            header = f.read(12)

            # Assinatura DAV (Magic Bytes)
            if header.startswith(b'DAHUA'):
                return "DAHUA_DAV"

            # Assinatura MPEG-PS (Pack Header 0x000001BA)
            if len(header) >= 4 and header[0:4] == b'\x00\x00\x01\xBA':
                return "MPEG_PS"

            # Assinatura AVI (RIFF)
            if len(header) >= 4 and header[0:4] == b'RIFF':
                return "RIFF_AVI"

            # Assinatura MP4 (ftyp/wide)
            if len(header) >= 8:
                sig = header[4:8]
                if sig in [b'ftyp', b'wide', b'moov', b'mdat']:
                    return "ISOBMFF"

    except Exception:
        pass

    return "UNKNOWN"


# --- FUNÇÕES DE FACHADA ---

def analyze_atom_structure(file_path):
    fmt = identify_container(file_path)

    if fmt == "ISOBMFF" and file_structure_isobmff:
        return file_structure_isobmff.analyze_atom_structure(file_path)
    elif fmt == "RIFF_AVI" and file_structure_riff:
        return file_structure_riff.analyze_avi_structure(file_path)
    elif fmt == "DAHUA_DAV" and file_structure_dav:
        return file_structure_dav.analyze_dav_structure(file_path)
    elif fmt == "MPEG_PS" and file_structure_mpg:
        return file_structure_mpg.analyze_mpg_structure(file_path)
    else:
        return {
            "Forensic Report": f"Formato não suportado ou módulo ausente.\nDetectado: {fmt}"}


def get_full_atom_analysis(file_path):
    fmt = identify_container(file_path)

    if fmt == "ISOBMFF" and file_structure_isobmff:
        return file_structure_isobmff.get_full_atom_analysis(file_path)
    elif fmt == "RIFF_AVI" and file_structure_riff:
        # Reutiliza lógica do AVI para retornar árvore
        try:
            size = os.path.getsize(file_path)
            with open(file_path, "rb") as f:
                if f.read(4) == b'RIFF':
                    tree = file_structure_riff.parse_riff_tree(f, 0, size)
                    return {"tree": tree, "type": "AVI", "report": "OK"}
        except BaseException:
            pass
    elif fmt == "DAHUA_DAV":
        # DAV não tem árvore de átomos
        return {
            "tree": [],
            "type": "DAV",
            "report": "Formato proprietário sem árvore de átomos."}
    elif fmt == "MPEG_PS":
        # Retorna a varredura do MPEG
        if file_structure_mpg:
             return file_structure_mpg.analyze_mpg_structure(file_path)
        return {"tree": [], "type": "MPEG-PS", "report": "Módulo ausente."}

    return {"tree": [], "report": "N/A"}


def extract_forensic_artifacts(tree):
    if file_structure_isobmff:
        return file_structure_isobmff.extract_forensic_artifacts(tree)
    return {}
