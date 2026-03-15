# Identificação de Fonte Filmadora (Source Identification) em Arquivos MPEG-PS (.mpg)

Quando temos múltiplos arquivos de vídeo e queremos provar pericialmente que eles se originaram do mesmo equipamento físico (ou pelo menos do mesmo exato modelo e configuração de software), a análise visual da imagem é insuficiente. Precisamos olhar para a **impressão digital estrutural** gerada pelo chip codificador (encoder) da câmera durante a gravação.

Câmeras diferentes (Sony, Canon, DVRs, celulares antigos) tomam decisões matemáticas diferentes na hora de comprimir o vídeo. Ao analisar o arquivo hexadecimalmente, podemos auditar essas escolhas.

## 1. Matrizes de Quantização (Q-Tables / Quantization Matrices)
Esta é a assinatura "Padrão Ouro" em identificação de MPEG/JPEG. Para comprimir o vídeo, cada câmera divide a imagem em blocos e divide os valores das frequências de cor por uma "matriz matemática" nativa gravada no hardware/firmware dela.
- Existem matrizes separadas para **I-Frames (Intra)** e para frames preditos **(Non-Intra)**.
- Se setarmos duas câmeras iguais na mesma configuração, a matriz de 64 números (grade 8x8) que elas aplicam ao fluxo de bytes (`Sequence Header 0xB3`) será matematicamente idêntica.
- Essa tabela é literalmente uma assinatura do fabricante sobre como ele prefere sacrificar detalhes da imagem para economizar espaço de arquivo.

## 2. Padrão da Estrutura GOP (Group of Pictures)
Em vídeos comprimidos em formato MPEG, nem todas as imagens (frames) são fotos completas. O sistema utiliza um padrão **GOP**, alternando entre:
- **(I) Intra-Frames:** Fotos completas e pesadas.
- **(P) Predicted-Frames:** Guardam apenas a diferença de movimento do frame I anterior.
- **(B) Bi-Directional Frames:** Guardam o movimento olhando pro passado e pro futuro.

Câmeras adotam "compassos" diferentes na construção dos blocos matemáticos do vídeo GOP. 
- Uma câmera de segurança pode gravar no padrão `IPPPPPPPP`.
- Um encoder de DVD pode exigir distâncias fixas de `IBBPBBPBBPBBPBB`.
Decodificar os `Picture Headers` (0x00) nos dá a assinatura exata do padrão adotado e o comprimento contínuo médio desse padrão. Se os 7 arquivos adotam estritamente o mesmo padrão, a fonte de autoria é corroborada.

## 3. Rate Control e Assinaturas Básicas (Bitrate Profile)
O cabeçalho sequencial também carrega parâmetros imutáveis do momento da gravação:
- O perfil exato do codificador (`Profile @ Level`, como "Main Profile @ Main Level").
- As proporções visuais nativas (Aspect Ratio Information).
- A Taxa de Bits Alvo (Target Bitrate) estipulada no algoritmo de controle de taxa (Rate Control).

## 4. Injeção de Dados em Private Streams
Muitas fabricantes de câmeras de mão (Sony Handycams, JVCs, Panasonics) arquivam dados essenciais e telemetria (como subcódigos de tempo de gravação SMPTE original, metadados KLV, informações de GPS, temperatura da cor, ou registro de uso dos botões físicos) em fluxogramas dedicados à metadados não-padrão.
No arquivo MPEG, esses se chamam **Private Streams**.
- Fazer um *dump* de texto legível (ASCII/Hex) desses fluxos pode revelar modelos de câmeras em texto puro escrito pela fabricante no preenchimento do cabeçalho.
