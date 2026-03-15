import subprocess
import shutil
import os
import sys

# ===== CONFIGURATION =====
VERSAO_APP = "1.0.7"
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

print("=========================================================")
print(" NIC VIDEO FORENSIC TOOL - BUILDER ")
print("=========================================================")
print("Compilacao travada no modo Pasta (Standalone).")
print("Este metodo garante portabilidade nativa da pasta bin/")
print("=========================================================")

build_mode = "standalone"

# ===== COMPILAÇÃO COM NUITKA =====
nuitka_command = [
    sys.executable, "-m", "nuitka",
    "--remove-output",
    "--windows-console-mode=disable",
    "--enable-plugin=pyside6",
    "--enable-plugin=numpy",
    "--windows-icon-from-ico=assets/icone.ico",
    # --- NOVAS FLAGS: COMPILADOR E METADADOS ANTI-FALSO POSITIVO ---
    "--windows-company-name=Forense NIC",
    "--windows-product-name=NIC Video Forensic Tool",
    "--windows-file-description=Ferramenta Forense de Analise de Video (PySide6, ExifTool, FFprobe)",
    f"--windows-product-version={VERSAO_APP}.0",
    f"--windows-file-version={VERSAO_APP}.0",
    # ---------------------------------------------------------------
    "--include-data-dir=assets=assets"
]

# MODO STANDALONE: Geramos a pasta real limpa e omitimos o 'bin' (copiaremos nativamente depois).
nuitka_command.append("--standalone")

# Arquivo principal
nuitka_command.append("main.py")

print(f"\nIniciando compilacao STANDALONE com Nuitka. Aguarde...")
try:
    subprocess.run(nuitka_command, check=True)
    print("Compilacao Nuitka concluida!")
except subprocess.CalledProcessError as e:
    print(f"\n[ERRO FATAL] Compilacao Nuitka abortou. Codigo: {e.returncode}")
    sys.exit(1)


# ===== PÓS-PROCESSAMENTO STANDALONE =====
if build_mode == "standalone":
    origem_bin = os.path.join(PROJECT_DIR, "bin")
    destino_bin = os.path.join(PROJECT_DIR, "main.dist", "bin")

    print(f"Copiando arsenal de dependencias {origem_bin} -> {destino_bin}...")
    if os.path.exists(destino_bin):
        shutil.rmtree(destino_bin)
        
    try:
        shutil.copytree(origem_bin, destino_bin)
        print("[SUCESSO] Binarios do FFprobe e ExifTool mesclados na Distribuicao!")
    except Exception as e:
        print(f"[ERRO] Falha ao copiar binarios: {e}")

    # Renomeia o executável main.exe bruto
    orig_exe = os.path.join(PROJECT_DIR, "main.dist", "main.exe")
    dest_exe = os.path.join(PROJECT_DIR, "main.dist", f"NIC_Video_Forensic_Tool_v{VERSAO_APP}.exe")

    if os.path.exists(orig_exe):
        os.rename(orig_exe, dest_exe)

# EMPACOTAMENTO FINAL (ZIP Nativo Python)
print("\nEmpacotando pasta para a primeira Release...")
exe_dir = os.path.join(PROJECT_DIR, "build_out")
os.makedirs(exe_dir, exist_ok=True)
nome_zip = os.path.join(exe_dir, f"NIC_Video_Forensic_Tool_v{VERSAO_APP}_Standalone")
pasta_dist = os.path.join(PROJECT_DIR, "main.dist")

print(f"Compactando {pasta_dist}...")
shutil.make_archive(nome_zip, 'zip', pasta_dist)

print(f"\n=======================================================")
print(f"[VITÓRIA] O Build standalone gerou o pacote:")
print(f"-> {nome_zip}.zip")
print(f"=======================================================\n")
