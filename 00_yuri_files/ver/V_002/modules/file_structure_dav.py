# modules/file_structure_dav.py
import os
from construct import Struct, Bytes, PaddedString

# Estrutura do Cabeçalho Dahua (Engenharia Reversa comum)
# Geralmente os primeiros bytes são "DAHUA" seguidos de dados
DahuaHeader = Struct(
    "magic" / PaddedString(5, "ascii"),  # "DAHUA"
    "unknown_1" / Bytes(3),  # Padding ou versão
    "archive_header" / Bytes(24),  # Dados variados
    # O resto é stream de vídeo (H.264/H.265)
)


def analyze_dav_structure(file_path):
    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)

    report = f"ARQUIVO: {file_name} (Formato Proprietário DVR)\n"
    report += "=" * 85 + "\n\n"

    try:
        with open(file_path, "rb") as f:
            header_bytes = f.read(32)

            # Verifica Assinatura
            if header_bytes.startswith(b'DAHUA'):
                report += "[OK] Assinatura 'DAHUA' detectada no cabeçalho.\n"
                report += f"     Magic Bytes: {header_bytes[:5]}\n\n"

                report += "--- ANÁLISE FORENSE DVR ---\n"
                report += "1. FABRICANTE: Dahua Technology (ou OEM como Intelbras).\n"
                report += "2. ESTRUTURA: Stream proprietário (não indexado como MP4/AVI).\n"
                report += "3. REPRODUÇÃO: Requer 'SmartPlayer' ou conversão.\n"
                report += "4. INTEGRIDADE: Este formato é difícil de editar sem quebrar o cabeçalho.\n"
                report += f"5. TAMANHO: {file_size} bytes.\n"

                # Tenta adivinhar o codec olhando um pouco à frente
                f.seek(0)
                sample = f.read(2048)
                if b'H264' in sample or b'\x00\x00\x00\x01\x67' in sample:
                    report += "6. CODEC PROVÁVEL: H.264 (AVC) encapsulado.\n"
                elif b'H265' in sample or b'HEVC' in sample or b'\x00\x00\x00\x01\x40' in sample:
                    report += "6. CODEC PROVÁVEL: H.265 (HEVC) encapsulado.\n"

            else:
                report += "[!] ALERTA: Extensão .dav detectada, mas sem assinatura 'DAHUA' no início.\n"
                report += "    Pode ser um arquivo corrompido, criptografado ou de outro fabricante.\n"
                report += f"    Primeiros 16 bytes: {header_bytes[:16].hex()}\n"

    except Exception as e:
        report += f"Erro ao ler arquivo: {e}"

    report += "\n" + "=" * 85 + "\n"
    report += "NOTA TÉCNICA:\n"
    report += "Arquivos .DAV são contêineres proprietários usados em CFTV.\n"
    report += "Para análise de quadros (GOP), recomenda-se a conversão prévia ou\n"
    report += "o uso da Análise Profunda (FFprobe) que pode tentar ler o stream bruto.\n"

    return {"Forensic Report": report}


def extract_forensic_artifacts(tree):
    # DAV não tem metadados textuais padrão como MP4
    return {
        "software": ["Dahua/OEM DVR Firmware"],
        "dates": [],
        "inconsistencies": []}
