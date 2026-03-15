import os
import struct
import datetime

# --- ASF GUID Dictionary ---
# All ASF Objects are identified by exactly 16 bytes.
ASF_GUIDS = {
    bytes.fromhex('3026B2758E66CF11A6D900AA0062CE6C'): "Header Object",
    bytes.fromhex('3626B2758E66CF11A6D900AA0062CE6C'): "Data Object",
    bytes.fromhex('3326B2758E66CF11A6D900AA0062CE6C'): "Simple Index Object",
    bytes.fromhex('D329E2D6DA35D111903400A0C90349BE'): "Index Object",
    bytes.fromhex('A1DCAB8CE47B11CFB92E00A0C90348F6'): "File Properties Object",
    bytes.fromhex('9107DCB7B7A9CF118EE600C00C205365'): "Stream Properties Object",
    bytes.fromhex('11D2D3EBAEDBED11A4F800C04F610340'): "Codec List Object",
    bytes.fromhex('3326b2758E66CF11A6D900AA0062CE6C'): "Script Command Object",
    bytes.fromhex('01CD87F451A9CF118EE600C00C205365'): "Marker Object",
    bytes.fromhex('A2DCAB8CE47B11CFB92E00A0C90348F6'): "Bitrate Mutual Exclusion Object",
    bytes.fromhex('A3DCAB8CE47B11CFB92E00A0C90348F6'): "Error Correction Object",
    bytes.fromhex('3326B2758E66CF11A6D900AA0062CE6C'): "Content Description Object",
    bytes.fromhex('40A4D0D207E3D21197F000A0C95EA850'): "Extended Content Description Object",
    bytes.fromhex('14E68A5CB22BCF118EE600C00C205365'): "Header Extension Object",
    bytes.fromhex('CBEA50599A48CB4D9AC646A7281DD11C'): "Metadata Object",
}

def bytes_to_guid_str(b):
    """Conveter 16 bytes para string legível de GUID (Litlle-Endian no ASF)"""
    if len(b) != 16: return "INVALID"
    # Formato AAAA-BB-CC-DD-EE
    d1 = struct.unpack('<I', b[0:4])[0]
    d2 = struct.unpack('<H', b[4:6])[0]
    d3 = struct.unpack('<H', b[6:8])[0]
    d4 = b[8:10].hex().upper()
    d5 = b[10:16].hex().upper()
    return f"{d1:08X}-{d2:04X}-{d3:04X}-{d4}-{d5}"


def parse_asf_filetime(filetime_val):
    """
    O Windows FILETIME é o número de inteiros de 100-nanosegundos desde 1º Janeiro de 1601.
    Retorna uma string UTC legível.
    """
    if filetime_val == 0:
        return "Not Set / Vazio"
    try:
        # Convertendo 100-ns para segundos
        seconds = filetime_val / 10000000.0
        # A Base Epoch da MS é (1601, 1, 1)
        # O datetime de python aceita (1,1,1) ou a Epoch padrão 1970
        # Um hack elegante: 1601 para 1970 dá ~11644473600 segundos
        unix_time = seconds - 11644473600
        if unix_time < 0: return f"Inválido (Época pré-1970): {filetime_val}"
        
        dt = datetime.datetime.fromtimestamp(unix_time, tz=datetime.timezone.utc)
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception as e:
         return f"Erro de conversão ({filetime_val})"


def safe_utf16_decode(data):
    """Decodificador forense seguro para strings de metadata"""
    try:
        # O ASF frequentemente usa strings terminadas em Null (00 00)
        s = data.decode('utf-16le')
        s = s.rstrip('\x00')
        # Filtra apenas o que é razoavelmente printável para evitar sujeiras da memória
        return "".join(c for c in s if c.isprintable()).strip()
    except Exception:
        return ""


def analyze_asf_structure(file_path):
    """
    Percorre a árvore de Objetos e emite laudo de um WMV/ASF file.
    """
    file_name = os.path.basename(file_path)
    if not os.path.exists(file_path):
        return {"Forensic Report": "Arquivo não encontrado."}
        
    file_size = os.path.getsize(file_path)
    
    # 1. Checa Magic Bytes
    with open(file_path, "rb") as f:
        magic = f.read(16)
        if magic != bytes.fromhex('3026B2758E66CF11A6D900AA0062CE6C'):
             return {"Forensic Report": "Isso não aparenta ser um arquivo ASF/WMV válido (Falta Header Object no byte 0)."}

    # --- COLETA FORENSE ---
    stats = {
        "total_objects": 0,
        "creation_date": None,
        "play_duration": None,
        "strings_found": [],
        "tree_nodes": []
    }
    
    try:
        with open(file_path, "rb") as f:
             # O ASF obriga Objects sequenciais.
             # Loop iterando nos sizes.
             offset = 0
             while offset < file_size:
                 f.seek(offset)
                 guid_bytes = f.read(16)
                 if len(guid_bytes) < 16: break
                 
                 size_bytes = f.read(8)
                 if len(size_bytes) < 8: break
                 
                 obj_size = struct.unpack('<Q', size_bytes)[0]
                 
                 if obj_size < 24: # Tamanho mínimo de um obj ASF (16 GUID + 8 Size)
                     break
                     
                 obj_name = ASF_GUIDS.get(guid_bytes, f"Unknown Object ({bytes_to_guid_str(guid_bytes)})")
                 stats["total_objects"] += 1
                 
                 chunk_node = {
                     "type": obj_name,
                     "size": obj_size,
                     "offset": offset,
                     "guid": bytes_to_guid_str(guid_bytes)
                 }
                 stats["tree_nodes"].append(chunk_node)
                 
                 # --- PARSERS PROFUNDOS DOS OBJETOS ---
                 
                 # 1. FILE PROPERTIES OBJECT (A mina de ouro dos timestamps)
                 if guid_bytes == bytes.fromhex('A1DCAB8CE47B11CFB92E00A0C90348F6'):
                     payload = f.read(min(obj_size - 24, 104)) # header fields
                     if len(payload) >= 80:
                         # Offset 40 do Payload tem as Creation Dates
                         creation_time_val = struct.unpack('<Q', payload[40:48])[0]
                         stats["creation_date"] = parse_asf_filetime(creation_time_val)
                         
                         # Offset 56 tem Play Duration (100ns)
                         play_dur_val = struct.unpack('<Q', payload[56:64])[0]
                         stats["play_duration"] = int(play_dur_val / 10000000) # Segundos
                 
                 # 2. CONTENT DESCRIPTION OBJECT (Metadados Limpos)
                 elif guid_bytes == bytes.fromhex('3326B2758E66CF11A6D900AA0062CE6C'):
                     # Offset 24
                     payload = f.read(min(obj_size - 24, 500))
                     if len(payload) >= 10:
                         # Str sizes
                         title_len = struct.unpack('<H', payload[0:2])[0]
                         author_len = struct.unpack('<H', payload[2:4])[0]
                         copy_len = struct.unpack('<H', payload[4:6])[0]
                         desc_len = struct.unpack('<H', payload[6:8])[0]
                         rating_len = struct.unpack('<H', payload[8:10])[0]
                         # Extrai sequencial
                         idx = 10
                         if title_len > 0 and len(payload) >= idx+title_len:
                             val = safe_utf16_decode(payload[idx:idx+title_len])
                             if val: stats["strings_found"].append(f"Title: {val}")
                             idx += title_len
                         if author_len > 0 and len(payload) >= idx+author_len:
                             val = safe_utf16_decode(payload[idx:idx+author_len])
                             if val: stats["strings_found"].append(f"Author: {val}")
                             idx += author_len
                         if copy_len > 0 and len(payload) >= idx+copy_len:
                             val = safe_utf16_decode(payload[idx:idx+copy_len])
                             if val: stats["strings_found"].append(f"Copyright: {val}")
                             idx += copy_len

                 # 3. HEADER EXTENSION / EXTENDED CONTENT (Strings escondidas de editores)
                 elif guid_bytes in [bytes.fromhex('14E68A5CB22BCF118EE600C00C205365'), bytes.fromhex('40A4D0D207E3D21197F000A0C95EA850')]:
                      # Lemos uma amostra de até 4KB para fazer "Carving" rude de UTF-16
                      sample = f.read(min(obj_size - 24, 4000))
                      try:
                          # Muitos softwares carimbam algo como "WMFSDKVersion", "IsVBR", etc
                          decoded = sample.decode('utf-16le', errors='ignore')
                          words = [w for w in decoded.split('\x00') if len(w) > 3 and w.isprintable()]
                          for w in words:
                              if w not in ["IsVBR", "DeviceConformanceTemplate", "WM/WMADRCPeakReference", "WM/WMADRCAverageReference"]:
                                   if w.lower() not in [s.lower() for s in stats["strings_found"]]:
                                       stats["strings_found"].append(f"[Extended] {w}")
                      except Exception:
                          pass
                          
                 # 4. HEADER OBJECT (Container inicial, devemos mergulhar nele!)
                 # O Header Object contém outros objetos dentro de seu Payload.
                 if guid_bytes == bytes.fromhex('3026B2758E66CF11A6D900AA0062CE6C'):
                     # Lemos qtd de subobjetos e pulamos pra ler eles encadeados
                     f.read(4) # Number of header objects
                     f.read(1) # Reserved 1
                     f.read(1) # Reserved 2
                     offset += 30 # Os header objects iniciam diretamente abaixo daqui e não no final de obj_size
                     continue
                     
                 # Se não mergulhamos, pulamos para o próximo offset mestre
                 offset += obj_size

    except Exception as e:
         return {"Forensic Report": f"ERRO na varredura WMV/ASF: {str(e)}"}
         
    # --- MONTAGEM DO LAUDO ---
    report = ["--- RELATÓRIO ESTRUTURAL DA MICROSOFT (ASF/WMV) ---"]
    report.append(f"Arquivo analisado: {file_name}")
    report.append("O formato é baseado em Container de Objetos de 128-bits (GUIDs).\n")
    
    report.append("[ESTATÍSTICAS DA BASE DE ENVELOPES]")
    report.append(f"  - Total de Objetos Base Analisados: {stats['total_objects']}")
    
    report.append("\n" + "=" * 65)
    report.append("[🕒 ASSINATURA TEMPORAL FORENSE]")
    report.append("  O protocolo ASF armazena datas no formato FILETIME da base de registro do Windows. Isso prova a data de criação nativa independente da cópia no seu HD.")
    
    report.append(f"    - 🕓 Creation Date (UTC):  {stats['creation_date'] if stats['creation_date'] else '[NÃO DECLARADO PARSEÁVEL]'}")
    
    if stats['play_duration']:
        report.append(f"    - ⏱️ Play Duration (File): {stats['play_duration']} segundos marcados no Cabeçalho.")
        
    report.append("\n" + "-" * 65)
    report.append("[📝 DUMP DE METADADOS TEXTUAIS INTELIGENTES (UTF-16)]")
    report.append("  Varredura profunda por strings legíveis inseridas pelo gravador origial ou editor de terceiros no Extensor de Descrição:")
    
    if len(stats["strings_found"]) > 0:
        for idx, text in enumerate(stats["strings_found"]):
             report.append(f"    {idx+1}. {text}")
    else:
         report.append("    [Nenhuma string legível decodificada encontrada]")
         
    report.append("\n" + "=" * 65)
    report.append("[🌳 ÁRVORE DE OBJETOS DETECTADA]")
    for node in stats["tree_nodes"]:
         report.append(f"  > {node['type']:35} | {node['size']:10} Bytes | Offset: 0x{node['offset']:08X}")
         
    final_str = "\n".join(report)
    
    return {
         "tree": [],
         "type": "WMV/ASF", 
         "Forensic Report": final_str
    }
