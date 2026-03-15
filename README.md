<div align="center">
  <img src="assets/icone.ico" alt="NIC Forensic Tool Logo" width="120" />
</div>

# NIC Video Forensic Tool 🔍🎥

**NIC Video Forensic Tool** é uma aplicação open-source desenvolvida sob medida para a **perícia criminal e análise forense audiovisual**. Ela consolida, automatiza e cruza dados de grandes motores cibernéticos (FFprobe, MediaInfo, ExifTool) em uma interface gráfica limpa, dispensando o uso exaustivo de linha de comando para tarefas de rotina na investigação de evidências em vídeo.

---

## 🎯 Objetivo

No contexto investigativo moderno, vídeos manipulados (Deepfakes), adulterações de metadados, ou até a extração forense de hardwares de origens obscuras (DVRs como `.dav`), exigem um escrutínio bit a bit. 

A aplicação foi criada para:
1. **Acelerar a Triagem:** Em vez de abrir 4 terminais diferentes, tudo é realizado em apenas uma interface.
2. **Evidenciar a Manipulação:** Realizar cruzamentos profundos nos "GOPs" (Group of Pictures) e mapeamento de Átomos (`moov`, `mdat`) para identificar incompatibilidades estruturais geradas por softwares de edição após a gravação da câmera.
3. **Analisar a Origem:** Identificar se o arquivo é providencial de uma rede social (WhatsApp/Instagram), gerado por IA Generativa, ou autêntico de câmera.

---

## 🚀 Principais Funcionalidades

### 📋 1. Metadados e Informações Gerais
A aba de informações cruza dois motores colossais:
- **MediaInfo:** Responsável pela análise fundamental do Container, Codec, bitrate e resolução.
- **ExifTool (Aviso Forense):** Extrai tags proprietárias silenciosas injetadas na raiz do arquivo, capturando Fabricante da Câmera (Apple, Canon), GPS, Softwares de codificação e Lentes físicas.

### 🏗️ 2. Estrutura do Arquivo Física
Realiza o parsing profundo em contêineres e detecta anomalias de formatação:
- **MP4 / MOV:** Analisa `ftyp`, `moov`, `mdat` procurando injeções maliciosas.
- **AVI / ASF / WMV:** Valida a integridade do cabeçalho de RIFF e pacotes de streaming legado.
- **DAV (DVRs Proprietários):** Lida com containers embarcados em DVRs de segurança frequentemente recuperados em locais públicos.

### 🤖 3. Score de Autenticidade (Heurística)
O sistema calcula um **Módulo de Probabilidade** para determinar a origem primária do vídeo:
- `Redes Sociais:` Procura ativamente por carimbos clássicos do *Facebook*, *TikTok* e *WhatsApp*.
- `IA Generativa / Deepfakes:` Identifica cadeias lógicas de sintetizadores (*Runway*, *Midjourney*).
- `Softwares de Edição:` Avisa se o arquivo do "celular" suspeito passou por exportação do *Premiere* ou *DaVinci Resolve*.

### 🎞️ 4. Análise de Frames e GOP (Group of Pictures)
Dois modos de engajamento para validar as taxas lógicas de quadros e integridade da compressão (I-Frames, P-Frames, B-Frames):
- **Análise Rápida:** Usa tabelas heurísticas de índices de átomos (STSS/STSZ).
- **Análise Profunda (Bitstream FFprobe):** Varre cada bit do arquivo evidência em background cruzando as tabelas com a realidade reproduzida. Indispensável para containers fechados de CFTV.

### 🔐 5. Cadeia de Custódia e Hashes
Cálculo atômico de blocos imutáveis (`MD5` e `SHA-256`) para assegurar o rastreio judicial e preservar a integridade digital da evidência enviada ao inquérito.

---

## 🛠️ Tecnologias Utilizadas
A ferramenta é compilada em ambiente de alto desempenho usando `Nuitka` para não depender que o usuário possua bibliotecas instaladas na própria máquina de trabalho (*standalone executable*).
- **Frontend / UI:** Python + PySide6 (Qt)
- **Extração Física:** ExifTool, FFprobe, PyMediaInfo
- **Engenharia de Threads:** QThread Workers (Asynchronous)

---

## 📋 Como Compilar (Para Desenvolvedores)
O repositório disponibiliza um script `.bat` contendo heurísticas de injeção de plugin pesadas que resolvem bibliotecas Python em um bloco de C++.
> **Requisito:** Nuitka, Python 3.10+ e bibliotecas no formato Conda/Venv.
```bash
build_nuitka_onefile.bat
```
Ao término, um arquivo `.exe` portátil será gerado, encapsulando internamente todos os motores de Exif e FFprobe.

---
> **Aviso Legal:** Esta ferramenta é destinada ao auxílio do operador de persecução penal e da computação forense. Ela não deve ser o único instrumento balizador na lavratura do laudo definitivo em casos sensíveis, devendo seus resultados técnicos serem submetidos ao rigor científico do Perito de maneira isolada.
