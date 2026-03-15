import subprocess
import os

exe = os.path.join('bin','exiftool-13.51_64','exiftool.exe')
file = 'E:/videos_mpg/M2U019388.MPG'

try:
    print(f"Executando {exe}...")
    b = subprocess.run([exe, file], capture_output=True, text=True).stdout
    f = subprocess.run([exe, '-a', '-u', '-U', '-ee', '-g1', file], capture_output=True, text=True).stdout
    print(f"BASIC LEN: {len(b)} | FULL LEN: {len(f)}")
    print("--- BASIC (primeiras 200 chars) ---")
    print(b[:200])
    print("\n--- FULL (primeiras 200 chars) ---")
    print(f[:200])
except Exception as e:
    print("ERRO:", e)
