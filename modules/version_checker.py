import urllib.request
import json
import socket
import os
from PySide6.QtCore import QThread, Signal

class VersionCheckWorker(QThread):
    """
    Sub-Rotina assíncrona que varre o GitHub em busca da última Release publicada
    ou um arquivo version.json cru, comparando com a versão local atual.
    """
    # Emite (tem_atualizacao_bool, string_versao_nova, url_download)
    finished = Signal(bool, str, str)
    
    def __init__(self, current_version):
        super().__init__()
        # A versão local limpa, ex: '1.0.7'
        self.current_version = current_version.lower().replace('v', '').strip()
        
        # Endpoint da API de Releases do GitHub
        # Repo: https://github.com/smutans28/video_analysis_agy
        self.api_url = "https://api.github.com/repos/smutans28/video_analysis_agy/releases/latest"
        
        # Como o repositório é 'private', a API pública retornará 404 Not Found a menos
        # que um Personal Access Token (PAT) seja injetado no header.
        self.github_token = os.environ.get("GITHUB_NIC_TOKEN", "")
        
    def run(self):
        # 1. Checa conexão com internet rapidamente (Timeout de 2s pra não travar o app)
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=2)
        except OSError:
            self.finished.emit(False, "", "") # Sem internet, encerra silencioso
            return
            
        # 2. Requisita a versão
        headers = {'User-Agent': 'NIC-Forensic-Updater/1.0'}
        if self.github_token:
            headers['Authorization'] = f"token {self.github_token}"
            
        req = urllib.request.Request(
            self.api_url, 
            headers=headers
        )
        
        try:
            with urllib.request.urlopen(req, timeout=3) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode('utf-8'))
                    
                    # Se for API do Github (Releases): o JSON terá 'tag_name'
                    # Se for arquivo cru version.json: terá {"version": "v1.0.8", "url": "..."}
                    online_version = data.get('tag_name', data.get('version', '0.0.0'))
                    download_url = data.get('html_url', data.get('url', ''))
                    
                    online_clean = online_version.lower().replace('v', '').strip()
                    
                    # Uma comparação burra de string. Em C++ é melhor quebrar as partes (1, 0, 7)
                    if self._is_newer(online_clean, self.current_version):
                        self.finished.emit(True, online_version, download_url)
                    else:
                        self.finished.emit(False, "", "")
                else:
                    self.finished.emit(False, "", "")
        except Exception as e:
            # Qualquer erro de rede, SSL, JSON parsing, fingiremos que estamos atualizados
            self.finished.emit(False, "", "")

    def _is_newer(self, online, local):
        """Compara duas strings de versão no formato X.Y.Z"""
        try:
            o_parts = [int(x) for x in online.split('.')]
            l_parts = [int(x) for x in local.split('.')]
            
            # Equaliza o tamanho caso sejam 1.0 vs 1.0.1
            while len(o_parts) < len(l_parts): o_parts.append(0)
            while len(l_parts) < len(o_parts): l_parts.append(0)
            
            for o, l in zip(o_parts, l_parts):
                if o > l: return True
                if o < l: return False
            return False
        except Exception:
            return False
