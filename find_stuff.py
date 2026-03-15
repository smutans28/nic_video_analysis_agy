import sys

file_path = "e:/nic_video_analysis_ag/00_yuri_files/ers/extrator_hashes_metadados.py"
try:
    with open(file_path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            L = line.lower()
            if "drag" in L or "drop" in L or "acceptdrops" in L or "github" in L or "versão instalada" in L:
                print(f"{i+1}: {line.strip()}")
except Exception as e:
    print("Erro:", e)
