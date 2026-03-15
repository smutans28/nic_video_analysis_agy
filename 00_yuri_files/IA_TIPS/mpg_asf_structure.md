# Estrutura de Arquivos: ASF e MPEG-PS (MPG)
Este documento detalha a estrutura de baixo nível (especificações de bytes, cabeçalhos e objetos) para arquivos de vídeo `.asf` e `.mpg` (MPEG-PS), com foco na análise forense, extração de metadados e detecção de edição.

---

## 1. ASF (Advanced Systems Format) - Microsoft
O formato ASF (usado frequentemente com extensões `.asf`, `.wmv`, `.wma`) é um container proprietário focado em *streaming* e foi desenvolvido pela Microsoft. A sua estrutura é completamente baseada em **Objetos**, onde cada componente do arquivo é identificado por um **GUID (Globally Unique Identifier)** de 16 bytes (128 bits), seguido por um valor de tamanho em 64 bits (8 bytes).

### Estrutura Geral (Objetos de Alto Nível)
Um arquivo ASF válido contém **obrigatoriamente** dois objetos principais, geralmente seguidos de um terceiro (opcional):

1. **Header Object (Obrigatório):**
   - Deve ser o *primeiro* objeto do arquivo.
   - **GUID Hexadecimal:** `30 26 b2 75 8e 66 cf 11 a6 d9 00 aa 00 62 ce 6c` (Representação: `75B22630-668E-11CF-A6D9-00AA0062CE6C`).
   - É o contêiner de metadados. Ele aloja Sub-objetos importantes como:
     - **File Properties Object:** Tamanho do arquivo, tempo de criação, duração, bitrate máximo.
     - **Stream Properties Object:** Um por trilha (vídeo, áudio). Define codecs e resoluções.
     - **Content Description Object:** Informações bibliográficas (Título, Autor, Copyright). *Ótimo alvo para metadados de perícia.*
     - **Header Extension Object:** Metadados customizados ou adicionais.

2. **Data Object (Obrigatório):**
   - Fica posicionado logo após o Header Object.
   - **GUID Hexadecimal:** `36 26 b2 75 8e 66 cf 11 a6 d9 00 aa 00 62 ce 6c` (Representação: `75B22636-668E-11CF-A6D9-00AA0062CE6C`).
   - Contém o pacote de dados multimídia (O "payload"). O vídeo/áudio é dividido em pacotes de dados (*data packets*) de tamanho fixo, sendo cada um precedido por um cabeçalho.

3. **Index Object (Opcional):**
   - Fica tipicamente no fim do arquivo.
   - Usado para *seek* (navegação temporal) rápido no Data Object. O índice mapeia tempo para offsets de pacotes de dados.

### Relevância Forense (ASF)
- **Identificação e Magic Bytes:** Buscar pela assinatura `30 26 B2 75...` no byte `0` é a forma definitiva de atestar a família do container como ASF.
- **Autenticidade:** Modificações no *Content Description Object* (quebra de continuidade/inconsistência nas datas ou nomes de autores) indicam passagem por software. Softwares de terceiros tendem a gerar trilhas extras de *Header Extension* diferentes daquelas gravadas nativamente por câmeras.

---

## 2. MPEG-PS (MPEG-1/MPEG-2 Program Stream) - MPG
O MPEG-PS (extensão `.mpg` ou `.mpeg`) é a base estrutural para mídias de armazenamento confiáveis, como VCDs ou DVD-Video, em contraposição ao MPEG-TS (Transport Stream, usado em sinais de TV/cabo). A estrutura é linear, demarcada sequencialmente por **Start Codes (Códigos de Início)** de 32 bits (4 bytes).

### Estrutura Base de Códigos (Start Codes)
Todos os cabeçalhos vitais iniciam com `0x000001` seguido de um byte identificador:

1. **Pack Header (Cabeçalho do Pacote):**
   - **Assinatura Hexadecimal:** `00 00 01 BA` (`0x000001BA`).
   - Marca o início de um grupo (Pack) de Packetized Elementary Streams (PES).
   - Contém o **SCR (System Clock Reference)**: Funciona como o relógio mestre para sincronia das trilhas.

2. **System Header (Cabeçalho do Sistema):**
   - **Assinatura Hexadecimal:** `00 00 01 BB` (`0x000001BB`).
   - (Presente principalmente no primeiro ou primeiros pacotes) Lista parâmetros de taxa máxima e enumera todos os *streams* (trilhas) elementares atrelados naquele canal.

3. **PES (Packetized Elementary Stream):**
   - **Início (Prefix):** `00 00 01` (`0x000001`).
   - **Stream ID:** O byte seguinte determina o tipo da trilha. Exemplo: Áudio no range `0xC0` a `0xDF`, Vídeo no range `0xE0` a `0xEF`.
     - *Exemplo Prático:* O início do pacote de vídeo costuma ser `00 00 01 E0`.
   - Dentro dos cabeçalhos PES opcionais estarão o **PTS (Presentation Time Stamp)** e o **DTS (Decoding Time Stamp)**.

4. **Sequence Header (Dentro da trilha de vídeo):**
   - **Assinatura Hexadecimal:** `00 00 01 B3` (`0x000001B3`).
   - Extremamente forense: É aqui que o decodificador entende o tamanho do vídeo (Largura x Altura), Aspect Ratio e Frame Rate exatos do trecho decodificado. Decodificadores costumam espalhar *Sequence Headers* repetidos pelo arquivo.

### Relevância Forense (MPG / MPEG-PS)
- **Magic Bytes e Validação Estrutural:** A busca sequencial (Carving) é muito comum em arquivos MPG. Mesmo arquivos severamente corrompidos podem ter trechos de vídeo extraídos ao procurar por `00 00 01 BA` seguindo linearmente para `00 00 01 E0`.
- **Análise Temporal (Tampersing):** O estudo da coesão rítmica do **SCR** (Pacotes Mestre), juntamente com a crescente progressão relacional dos **PTS/DTS** (Apresentação e Decodificação) nos dados elementares de vídeo/áudio, são indicativos primários da linha do tempo. Quebras abruptas (saltos de tempo ou _reset_ no clock no meio de um *stream*) acusam edição/corte ou reintegração (*splice*).
- **Inconsistências de Encoder:** Assim como nos átomos MP4, metadados residuais da ferramenta codificadora diferem. A análise do recodificador pode mostrar anomalias no *pack_stuffing_length* ou injeção de *Private streams* (ID `0xBD` ou `0xBF`).
