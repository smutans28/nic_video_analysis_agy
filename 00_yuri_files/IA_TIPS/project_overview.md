# Observações do Projeto - NIC Forensic Video Tool

## Visão Geral
O projeto é uma ferramenta de análise forense de vídeos em Python (`NIC Forensic Video Tool v1.0.5`), construída com **PySide6** para a interface gráfica e estruturada para rodar de modo portátil (compatível com compilação via Nuitka ou PyInstaller, conforme visto em `utils.py`).

O principal foco do sistema é a checagem da autenticidade e integridade de arquivos de vídeo, avaliando se os mesmos são originais de câmera (como DVRs e celulares), se passaram por manipulação em redes sociais (Mensageiros/Streaming), ou se possuem traços evidentes de edição de software (Premiere, etc.).

---

## 📂 Estrutura e Funcionalidades

### 1. Interface de Usuário (`ui/`)
- **`control_window.py`:** É o painel central da ferramenta. Ele coordena o carregamento do vídeo e a execução de múltiplos módulos de análise forense de forma concorrente em `QThreads` para não travar a UI principal. Ele oferece:
  - Carregamento do arquivo de análise e exibição de resultados em Abas (`QTabWidget`).
  - Exportação dos relatórios locais dessas análises ou do MediaInfo completo para formato `.txt`.
- **`player_window.py`:** Um visualizador de vídeo independente implementado com **OpenCV (`cv2.VideoCapture`)** para renderização frame-a-frame manual e rápida (sem depender de codecs pesados de UI) acoplado com **QMediaPlayer/QAudioOutput** para a execução com áudio sincronizado.
  - Oferece controles manuais precisos para perícia: avanço frame-a-frame manual pelas setas do teclado.
  - Exporta um frame para imagem com a estampa customizada de tempo (timestamp) e número do frame embutidos (tarja e fonte OpenCV).

### 2. Módulos Analíticos (`modules/`)
Este é o verdadeiro "motor" da aplicação. As análises variam desde mapeamento superficial de binários até a leitura profunda de GOP e metadados.

#### Cadeia de Custódia e Info Básica
- **`hash_calculator.py`:** Calcula MD5 e SHA256 em blocos (para arquivos grandes) permitindo acompanhar via barra de progresso.
- **`file_info.py`:** Um *wrapper* do `pymediainfo` que consolida os metadados do container, vídeo e áudio. Ele foca em extrair os dados mais sensíveis para perícia: tamanho, Data/Hora de Criação e Modificação intrínsecas, framerate explícito e original, e identificadores de criação (`Encoded_Library_Name`, `Producer`).

#### Análise de Estrutura de Arquivo e Autenticidade (IA / Fingerprint)
- **`file_structure.py`:** Um despachante (`Dispatcher`) que primeiro averigua a "família" do vídeo através dos _Magic Bytes_ (Assinatura do Arquivo) (`ftyp/moov` para MP4/ISOBMFF, `RIFF` para AVI, ou formato nativo de CFTV `DAHUA`). Após a checagem, direciona a análise para módulos isolados (`file_structure_isobmff`, `file_structure_riff`, `file_structure_dav`).
- **`ai_detection.py`:** Analisa as informações estruturais e os metadados do `file_info`. O "Score de IA" (Autenticidade) começa em 50 e sofre penalidades ou bonificações com base na detecção (via heurística e bibliografia científica) de:
  - Redes Sociais ou Mensageiros (ex: átomo `beam` para Android antigo, `isom` para Meta, etc.).
  - Ferramentas de Edição (`Lavf`, `Adobe`, `Sony Vegas`).
  - Marcas de câmeras de celular e CFTV.
  - Ausência/Presença de GPS ou Datas de criação zeradas.
  No final, retorna um laudo classificando de "Original (DVR/Câmera)" ou "Alta probabilidade de Edição" / "Processado por Rede Social".

#### Análise de Grupo de Imagens (Group of Pictures - GOP) e Edição
- **`frame_analysis.py` (Análise Heurística Rápida):** Tenta predizer a distribuição de quadros (I, P, B Frames) sem decodificar o vídeo. Para ISO (MP4/MOV) lê diretamente a tabela binária `stss` (Keyframes) e `stsz` (tamanhos de cada frame). Em AVI, ele analisa o chunk `idx1`.
- **`deep_frame_analysis.py` (Análise Profunda por Bitstream):** Utiliza o processo do `ffprobe.exe` (que deve estar encapsulado na pasta `/bin/` do projeto) para efetivamente ler no *bitstream* o tipo pictórico exato dos frames. 
  - Retorna uma distribuição precisa (% I, P, B), calcula o tamanho do GOP (Group Of Pictures) médio detectado.
  - **Identificação de "Drops" e Cortes:** Caso haja variações maiores do que 30% em relação ao "Moda" (Tamanho base do GOP) de forma súbita num arquivo contínuo, as classifica como *⚠️ GOP Irregular* (Anomalia), sugerindo fortemente um corte manual no frame indicado.

---

## 🎯 Conclusão sobre o Código
A aplicação tem uma estrutura modular muito engenhosa para separar a extração pesada (que exige binários externos como `MediaInfo` e `FFprobe` / ou muita CPU para ler árvores hexadecimais de forma nativa) da tela PySide6. A integração OpenCV/Qt no _Player_ também priorizou a acuracidade de frame de um perito, ao invés de buscar a simples fluidez das bibliotecas nativas de reprodução de vídeo. 

O trabalho está muito completo com embasamento científico e uma separação excelente de escopo!
