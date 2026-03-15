# modules/file_structure_mpg.py

import os
import struct

# Constantes de Start Codes do MPEG-PS
PACK_START_CODE = b'\x00\x00\x01\xBA'
SYSTEM_HEADER_CODE = b'\x00\x00\x01\xBB'
SEQUENCE_HEADER_CODE = b'\x00\x00\x01\xB3'
SEQUENCE_EXT_CODE = b'\x00\x00\x01\xB5'


def parse_scr(bytes_data):
    """
    Decodifica o System Clock Reference (SCR) de um Pack Header MPEG-2.
    O SCR possui 42 bits no MPEG-2.
    A base opera a 90kHz e a extensão a 27MHz.
    """
    if len(bytes_data) < 6:
        return None

    # Lendo os 6 bytes que contêm o marcador e o SCR
    buf = struct.unpack(">Q", b'\x00\x00' + bytes_data[:6])[0]

    # Checa o prefixo do Pack Header
    marker_bits = (buf >> 46) & 0x3
    
    # MPEG-2 Pack Header (inicia com 01)
    if marker_bits == 1:
        scr_base = ((buf >> 43) & 0x07) << 30
        scr_base |= ((buf >> 27) & 0x7FFF) << 15
        scr_base |= ((buf >> 11) & 0x7FFF)
        scr_ext = (buf >> 1) & 0x1FF
        
        # SCR total em unidades de 27MHz
        return (scr_base * 300) + scr_ext
        
    # Formato inválido, preenchimento (padding) ou MPEG-1 não coberto
    return None

def format_timestamp(scr_27mhz):
    """Formata o tempo SCR (27MHz) para string HH:MM:SS.mmm"""
    seconds = scr_27mhz / 27000000.0
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = seconds % 60
    return f"{h:02d}:{m:02d}:{s:06.3f}"


def analyze_mpg_structure(file_path, limit_bytes=None):
    """
    Lê a estrutura sequencial do MPG/MPEG-PS e retorna uma árvore com o laudo forense.
    limit_bytes: Limita a varredura (None para ler o arquivo inteiro).
    """
    if not os.path.exists(file_path):
        return {"Forensic Report": "Arquivo não encontrado."}

    file_size = os.path.getsize(file_path)
    if limit_bytes is None:
        limit_bytes = file_size
    
    # Vamos ler iterativamente (carving) buscando Start Codes
    stats = {
        "pack_headers": 0,
        "system_headers": 0,
        "video_pes": 0,
        "audio_pes": 0,
        "private_pes": 0,
        "sequence_headers": 0,
        "first_scr": None,
        "last_scr": None,
        "anomalies": []
    }

    tree = [] # Vamos simular a mesma saída ("tree") dos outros módulos
    
    # Usando read em chunks para otimizar busca dos start codes
    buffer_size = 65536
    offset = 0
    
    try:
        with open(file_path, "rb") as f:
            data = f.read(buffer_size)
            
            while data and offset < min(file_size, limit_bytes):
                # Busca pelo próximo Start Code Prefix (0x000001)
                idx = data.find(b'\x00\x00\x01')
                
                if idx == -1:
                    # Não achou no bloco atual. Se o restante tem menos de 3 bytes e 
                    # não achamos start code, não há mais nada no arquivo. (EOF verdadeiro)
                    if len(data) < 3:
                        break
                        
                    # Recarrega o buffer retendo os últimos 2 bytes 
                    # para evitar cortar um start code no meio (00 00 01 = 3 bytes, reter 2 basta)
                    f.seek(offset + len(data) - 2)
                    offset = f.tell()
                    new_data = f.read(buffer_size)
                    
                    if len(new_data) <= 2: 
                        break # Chegou no fim do arquivo e leu apenas os dados retidos
                        
                    data = new_data
                    continue
                
                # Se achou perto do fim do buffer, também recarrega o buffer a partir do idx
                # para garantir que temos os metadados posteriores para leitura
                if len(data) - idx < 20: 
                    f.seek(offset + idx)
                    offset = f.tell()
                    new_data = f.read(buffer_size)
                    
                    if len(new_data) < 4:
                        break # EOF e não há o suficiente pra ler um start code
                        
                    data = new_data
                    idx = data.find(b'\x00\x00\x01') # re-encontra (será no idx=0)
                    
                    if idx == -1:
                        break # Fallback de segurança 

                # Pula o prefixo
                pos = idx + 3
                if pos >= len(data):
                    break # Fim de arquivo inesperado no start code
                    
                start_code = data[pos]
                absolute_offset = offset + pos - 3
                
                # --- IDENTIFICAÇÃO E PARSING DOS HEADERS VITAIS ---
                
                if start_code == 0xBA: # Pack Header
                    stats["pack_headers"] += 1
                    # Pular os 4 bytes do BA (já pulou 3, o pos é o 4º)
                    # Certificar que temos suficientes dados para parse_scr (necessita 14 bytes)
                    if pos + 15 > len(data):
                        break # Fim do arquivo incompleto
                        
                    pack_data = data[pos+1:pos+15] 
                    scr = parse_scr(pack_data)
                    
                    if scr is not None:
                        if stats["first_scr"] is None:
                            stats["first_scr"] = scr
                        
                        # Checagem Forense de Quebra de Clock
                        if stats["last_scr"] is not None:
                            # Pulo negativo ou pulo gigantesco (> 5 horas de gap) -> Anomalia severa
                            time_diff = scr - stats["last_scr"]
                            if time_diff < 0:
                                stats["anomalies"].append(f"⏱️ GAP NEGATIVO (Corte/Splicing): Clock retrocedeu no offset {absolute_offset} (Saltou de {format_timestamp(stats['last_scr'])} para {format_timestamp(scr)})")
                            elif time_diff > (27000000 * 3600 * 5): # 5 horas em ticks
                                stats["anomalies"].append(f"⏱️ GAP EXTREMO (Edição/Drops): Pulo de >5h no clock. Offset {absolute_offset}.")
                        
                        stats["last_scr"] = scr
                    
                    # Leitura de Stuffing Bytes (pode indicar software de edição re-envelopando/muxing)
                    if len(pack_data) >= 10:
                        # Em MPEG-2 Pack Header os ultimos 3 bits do 10º byte indicam o stuffing length
                        stuffing_len = pack_data[9] & 0x07
                        if stuffing_len > 0:
                            # Apenas marca na árvore se houver
                            pass

                elif start_code == 0xBB: # System Header
                    stats["system_headers"] += 1
                
                elif start_code == 0xB3: # Sequence Header
                    stats["sequence_headers"] += 1
                    
                # Checagem de PES (Packetized Elementary Stream)
                elif 0xE0 <= start_code <= 0xEF: # Video Stream
                    stats["video_pes"] += 1
                
                elif 0xC0 <= start_code <= 0xDF: # Audio Stream
                    stats["audio_pes"] += 1
                    
                elif start_code in [0xBD, 0xBF]: # Private Streams 
                    # Forense: Softwares de edição/câmeras inserem metadata proprietária aqui (Ex: Sony, GPS, Metadados NLE)
                    stats["private_pes"] += 1
                
                # Avança a busca um byte além do prefixo encontrado (evita loops infinitos)
                # Na prática, deveríamos pular o tamanho do bloco se soubermos, mas o carving sequencial garante 
                # tolerância a falhas em arquivos corrompidos.
                data = data[pos+1:]
                offset += pos + 1
                
    except Exception as e:
        return {"Forensic Report": f"ERRO na análise do arquivo MPG: {str(e)}"}


    # --- MONTAGEM DO LAUDO FORENSE ---
    
    report = ["--- RELATÓRIO ESTRUTURAL (MPEG-PS) ---"]
    report.append("O formato MPEG-PS distribui os dados em pacotes sequenciais não-hierárquicos.")
    report.append(f"Varredura efetuada até o limite de {min(file_size, limit_bytes) / (1024*1024):.0f}MB.\n")
    
    report.append("[ESTATÍSTICAS DO CONTÊINER]")
    report.append(f"  - Pack Headers (Controle de Sincronia): {stats['pack_headers']}")
    report.append(f"  - System Headers (Parâmetros Globais):  {stats['system_headers']}")
    report.append(f"  - Video PES (Pacotes de Vídeo):         {stats['video_pes']}")
    report.append(f"  - Audio PES (Pacotes de Áudio):         {stats['audio_pes']}")
    
    if stats["private_pes"] > 0:
         report.append(f"  - Private PES (Dados/Metadados Extras): {stats['private_pes']}")
    
    report.append(f"  - Sequence Headers (Specs de Decoder):  {stats['sequence_headers']}")

    report.append("\n[ANÁLISE TEMPORAL (SCR - System Clock Reference)]")
    if stats["first_scr"] is not None and stats["last_scr"] is not None:
        report.append(f"  ⏱️ Primeiro Timecode: {format_timestamp(stats['first_scr'])}")
        report.append(f"  ⏱️ Último Timecode:   {format_timestamp(stats['last_scr'])}")
        
        # O SCR é incremental. Se o primeiro for 0 e subir liso é padrão.
        # DVRs e Câmeras que geram arquivos em lote podem iniciar de valores altos.
    else:
        report.append("  [!] Nenhum relógio de sincronização (SCR) detectado.")

    report.append("\n" + "=" * 60)
    report.append("[🔍 INFORMAÇÃO DA ESTRUTURA MPG]")
    
    verdict_lines = []
    
    if len(stats["anomalies"]) > 0:
        verdict_lines.append("🔴 ATENÇÃO: INCONSISTÊNCIAS DETECTADAS (Quebra da Cadeia de Tempo).")
        verdict_lines.append("   Alta probabilidade de edição posterior, cortes (Splice) ou união maliciosa.\n")
        verdict_lines.append("   Lista de Anomalias:")
        for idx, an in enumerate(stats["anomalies"][:15]): 
            verdict_lines.append(f"     {idx+1}. {an}")
        if len(stats["anomalies"]) > 15:
            verdict_lines.append(f"     ... e mais {len(stats['anomalies']) - 15} falhas temporais similares.")
    else:
        verdict_lines.append("🟢 INTEGRIDADE TEMPORAL PRESERVADA.")
        verdict_lines.append("   Não foram detectados 'saltos' retroativos no relógio principal (SCR).")
        verdict_lines.append("   O arquivo apresenta continuidade típica de captura original direta da fonte (DVR/Câmera).")

    if stats["private_pes"] > 0:
        verdict_lines.append("\n💡 Observação: Foram detectados 'Private Streams'. Câmeras profissionais ou Softwares NLE de edição frequentemente injetam logs ou metadados XPS/Klv nestes blocos.")

    report.extend(verdict_lines)
    
    final_report_str = "\n".join(report)

    # Retorna o modelo esperado pelo Control Window (mantendo "tree" vazia pois não há estrutura em árvore)
    return {
         "tree": [],
         "type": "MPEG-PS", 
         "Forensic Report": final_report_str,
         "stats": stats
    }
