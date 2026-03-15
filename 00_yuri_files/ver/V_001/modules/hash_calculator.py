# modules/hash_calculator.py
import hashlib
import os


def calculate_hashes(file_path, progress_callback=None):
    """
    Calcula MD5 e SHA-256 simultaneamente lendo o arquivo em blocos.
    Retorna um dicionário com os hashes.
    """
    if not os.path.exists(file_path):
        return {"error": "Arquivo não encontrado"}

    # Prepara os algoritmos
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    # Tamanho do bloco de leitura (64KB)
    CHUNK_SIZE = 65536
    file_size = os.path.getsize(file_path)
    read_bytes = 0

    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break

                # Atualiza os hashes
                md5.update(chunk)
                sha256.update(chunk)

                # Atualiza progresso (se houver callback)
                read_bytes += len(chunk)
                if progress_callback and file_size > 0:
                    progress = int((read_bytes / file_size) * 100)
                    progress_callback(progress)

        return {
            "md5": md5.hexdigest(),
            "sha256": sha256.hexdigest()
        }
    except Exception as e:
        return {"error": str(e)}
