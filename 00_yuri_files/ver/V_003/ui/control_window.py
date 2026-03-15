# ui/control_window.py
import os
from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QFileDialog,
    QCheckBox,
    QTabWidget,
    QTextEdit,
    QGroupBox,
    QMessageBox,
    QProgressBar,
    QLabel)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QIcon, QPixmap

import utils

# Importamos módulos (Certifique-se de que deep_frame_analysis existe em
# modules/)
from ui.player_window import VideoPlayerWindow
from modules.file_info import get_forensic_data
from modules import file_structure, frame_analysis, ai_detection, hash_calculator, deep_frame_analysis

# --- CONSTANTES DE ASSETS ---
ASSETS_DIR = "assets"
LOGO_FILENAME = "logo.png"
ICON_FILENAME = "icone.ico"


def get_asset_path(filename):
    return utils.resource_path(os.path.join(ASSETS_DIR, filename))

# --- WORKER THREADS (Para não travar a UI) ---


class GopAnalysisWorker(QThread):
    """Worker para análise rápida de GOP (Heurística/Tabelas)"""
    finished = Signal(dict)
    error = Signal(str)

    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path

    def run(self):
        try:
            result = frame_analysis.analyze_gop_structure(self.file_path)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class DeepGopWorker(QThread):
    """Worker para análise profunda de GOP (FFprobe/Bitstream)"""
    finished = Signal(dict)
    error = Signal(str)

    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path

    def run(self):
        try:
            # Chama o módulo de análise profunda (FFprobe)
            result = deep_frame_analysis.get_ffprobe_gop_analysis(
                self.file_path)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class HashWorker(QThread):
    """Worker para cálculo de Hash (MD5/SHA256)"""
    finished = Signal(dict)
    progress = Signal(int)

    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path

    def run(self):
        result = hash_calculator.calculate_hashes(
            self.file_path, self.progress.emit)
        self.finished.emit(result)


class ControlWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        # Atualizado título da janela também
        self.setWindowTitle(
            "NIC Forensic Analysis Tool v1.0.7 - Painel de Controle")
        self.resize(700, 950)

        self.player_window = None
        self.current_video_path = None
        self.workers = []

        # --- CONFIGURAÇÃO DE ÍCONE ---
        icon_path = get_asset_path(ICON_FILENAME)
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        # --- Layout Principal ---
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # 1. CABEÇALHO (Logo + Título + Sobre)
        header_layout = QVBoxLayout()
        header_layout.setSpacing(5)

        # Logo
        logo_path = get_asset_path(LOGO_FILENAME)
        if os.path.exists(logo_path):
            lbl_logo = QLabel()
            pixmap = QPixmap(logo_path)
            scaled_pixmap = pixmap.scaledToHeight(
                100, Qt.TransformationMode.SmoothTransformation)
            lbl_logo.setPixmap(scaled_pixmap)
            lbl_logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
            header_layout.addWidget(lbl_logo)

        # Título com Versão (ATUALIZADO)
        lbl_title = QLabel("NIC FORENSIC VIDEO TOOL v1.0.5")
        lbl_title.setStyleSheet(
            "font-size: 18px; font-weight: bold; color: #2c3e50; margin-top: 5px;")
        lbl_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header_layout.addWidget(lbl_title)

        # Botão Sobre
        btn_about = QPushButton("SOBRE O SISTEMA")
        btn_about.setFixedWidth(150)
        btn_about.setStyleSheet("""
            QPushButton {
                background-color: #ecf0f1; color: #2c3e50; border: 1px solid #bdc3c7;
                border-radius: 4px; padding: 4px; font-size: 11px;
            }
            QPushButton:hover { background-color: #bdc3c7; }
        """)
        btn_about.clicked.connect(self.show_about_dialog)

        about_container = QHBoxLayout()
        about_container.addStretch()
        about_container.addWidget(btn_about)
        about_container.addStretch()
        header_layout.addLayout(about_container)

        main_layout.addLayout(header_layout)

        line = QLabel()
        line.setFixedHeight(2)
        line.setStyleSheet("background-color: #bdc3c7; margin: 10px 0;")
        main_layout.addWidget(line)

        # 2. Carregamento
        btn_load = QPushButton("Carregar Arquivo de Vídeo")
        btn_load.setStyleSheet("""
            QPushButton {
                background-color: #2980b9; color: white; font-weight: bold;
                padding: 12px; font-size: 13px; border-radius: 5px;
            }
            QPushButton:hover { background-color: #3498db; }
        """)
        btn_load.clicked.connect(self.load_video_action)
        main_layout.addWidget(btn_load)

        # 3. Checklist
        self.group_analysis = QGroupBox("Módulos de Análise Forense")
        self.group_analysis.setEnabled(False)
        chk_layout = QVBoxLayout()

        self.chk_info = QCheckBox(
            "Informações Básicas (Container/Stream/CODEC)")
        self.chk_structure = QCheckBox(
            "Estrutura do Arquivo (Atoms(.mp4)/Chunks(.avi)/Offsets)")
        self.chk_gop = QCheckBox("Análise de Frames/GOP (Heurística Rápida)")
        self.chk_deep_gop = QCheckBox(
            "Análise Profunda (Bitstream/FFprobe) [+LENTO]")
        self.chk_ai = QCheckBox(
            "Score de Autenticidade/IA (Metadados + Padrões)")
        self.chk_hash = QCheckBox(
            "Gerar Hash (MD5/SHA256) - Cadeia de Custódia")

        chk_layout.addWidget(self.chk_info)
        chk_layout.addWidget(self.chk_structure)
        chk_layout.addWidget(self.chk_gop)
        chk_layout.addWidget(self.chk_deep_gop)
        chk_layout.addWidget(self.chk_ai)
        chk_layout.addWidget(self.chk_hash)

        self.btn_analyze = QPushButton("Executar Análise Selecionada")
        self.btn_analyze.clicked.connect(self.run_analysis)
        chk_layout.addWidget(self.btn_analyze)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        chk_layout.addWidget(self.progress_bar)

        self.group_analysis.setLayout(chk_layout)
        main_layout.addWidget(self.group_analysis)

        # 4. Player
        self.group_player = QGroupBox("Visualizador")
        self.group_player.setEnabled(False)
        player_layout = QHBoxLayout()

        btn_show_player = QPushButton("Abrir Player")
        btn_show_player.clicked.connect(self.show_player)
        btn_play_pause = QPushButton("Play/Pause")
        btn_play_pause.clicked.connect(self.toggle_player)

        player_layout.addWidget(btn_show_player)
        player_layout.addWidget(btn_play_pause)
        self.group_player.setLayout(player_layout)
        main_layout.addWidget(self.group_player)

        # 5. Resultados
        self.tabs_results = QTabWidget()
        main_layout.addWidget(self.tabs_results)

    # --- AÇÕES DE UI ---

    def show_about_dialog(self):
        msg = QMessageBox(self)
        msg.setWindowTitle("Sobre o NIC Forensic Video Tool")

        icon_path = get_asset_path(ICON_FILENAME)
        if os.path.exists(icon_path):
            msg.setWindowIcon(QIcon(icon_path))

        msg.setIcon(QMessageBox.Icon.Information)

        # Texto Atualizado com a versão
        text = """
        <h3>NIC FORENSIC VIDEO TOOL v1.0.5</h3>
        <p>Software desenvolvido para análise forense de autenticidade e integridade de arquivos de vídeo.</p>
        <p><b>Funcionalidades Atuais:</b></p>
        <ul>
            <li><b>Informações Técnicas:</b> Extração detalhada de metadados e dados de stream.</li>
            <li><b>Estrutura de Arquivo:</b> Análise hierárquica e detecção de anomalias (MP4, AVI, DAV).</li>
            <li><b>Análise GOP (Rápida):</b> Mapeamento via tabelas de metadados (STSS/STSZ).</li>
            <li><b>Análise GOP (Profunda):</b> Validação cruzada via leitura de bitstream (FFprobe).</li>
            <li><b>Score de Autenticidade:</b> Identificação de origem (Câmera vs. Social vs. "IA").</li>
            <li><b>Cadeia de Custódia:</b> Cálculo de Hash MD5 e SHA-256.</li>
        </ul>
        <hr>
        <p><i>Desenvolvido para auxiliar peritos na análise de arquivos de vídeos.</i></p>
        <p><i>Yuri Presto - yuri.yop@policiacientifica.sp.gov.br</i></p>
        """
        msg.setText(text)
        msg.exec()

    def load_video_action(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Selecionar Vídeo")
        if file_name:
            self.current_video_path = file_name
            self.group_analysis.setEnabled(True)
            self.group_player.setEnabled(True)
            self.tabs_results.clear()

            # Abre player
            if self.player_window is None:
                self.player_window = VideoPlayerWindow()

            self.player_window.show()
            self.player_window.activateWindow()
            self.player_window.setFocus()
            self.player_window.load_video(file_name)

    def show_player(self):
        if self.player_window is None or not self.player_window.isVisible():
            self.player_window = VideoPlayerWindow()
            self.player_window.show()

            # Usando a função auxiliar correta
            icon_path = get_asset_path(ICON_FILENAME)
            if os.path.exists(icon_path):
                self.player_window.setWindowIcon(QIcon(icon_path))

            if self.current_video_path:
                self.player_window.load_video(self.current_video_path)
            self.player_window.setFocus()
        else:
            self.player_window.activateWindow()
            self.player_window.setFocus()

    def toggle_player(self):
        if self.player_window and self.player_window.isVisible():
            self.player_window.play_pause()

    def run_analysis(self):
        self.tabs_results.clear()
        if not self.current_video_path:
            return

        # Detecta se é DAV pela extensão (rápido e seguro para decisão de UI)
        is_dav = self.current_video_path.lower().endswith('.dav')

        # 1. INFO BÁSICA (Funciona parcial para DAV via MediaInfo, mas pode ser
        # limitado)
        if self.chk_info.isChecked():
            try:
                res = get_forensic_data(self.current_video_path)
                if "Erro" not in res["simplified"]:
                    self.create_result_tab(
                        "Informações Gerais",
                        res["simplified"],
                        res["full_text"])
                else:
                    # Para DAV, MediaInfo às vezes falha. Avisamos mas não
                    # criticamos.
                    if is_dav:
                        self.create_result_tab(
                            "Info (Limitada)", {
                                "Aviso": "MediaInfo tem suporte limitado para arquivos .DAV brutos."})
                    else:
                        QMessageBox.warning(
                            self, "Erro", f"Erro Info: {res['simplified']['Erro']}")
            except Exception as e:
                QMessageBox.critical(self, "Erro", f"Falha Info: {e}")

        # 2. ESTRUTURA (Funciona - Criamos o parser específico)
        if self.chk_structure.isChecked():
            try:
                res = file_structure.analyze_atom_structure(
                    self.current_video_path)
                self.create_result_tab(
                    "Estrutura do Arquivo", {
                        "Relatório Estrutural": res["Forensic Report"]})
            except Exception as e:
                QMessageBox.critical(self, "Erro", f"Falha Estrutura: {e}")

        # 3. SCORE IA (Funciona parcial - Vai dar 'Compatível com DVR')
        if self.chk_ai.isChecked():
            try:
                res = ai_detection.calculate_authenticity_score(
                    self.current_video_path)
                self.create_result_tab(
                    "Score Autenticidade", {
                        "Relatório Estrutural": res["report"]})
            except Exception as e:
                QMessageBox.critical(self, "Erro AI", f"Falha Score IA: {e}")

        # 4. ANÁLISE GOP RÁPIDA (BLOQUEIO PARA DAV)
        if self.chk_gop.isChecked():
            if is_dav:
                # Não rodamos a heurística em DAV porque não tem tabelas de
                # átomos
                self.create_result_tab(
                    "Análise GOP (Rápida)", {
                        "Relatório Estrutural": "--- ANÁLISE CANCELADA ---\n\n"
                        "Motivo: Arquivo .DAV (Proprietário de DVR).\n"
                        "Este formato não possui tabelas de índices padrão (stsz/idx1).\n"
                        "Utilize a 'Análise Profunda (Bitstream)' para este arquivo."})
            else:
                self.start_gop_analysis()

        # 5. ANÁLISE GOP PROFUNDA (Funciona para DAV!)
        if self.chk_deep_gop.isChecked():
            self.start_deep_gop_analysis()

        # 6. HASH (Funciona sempre)
        if self.chk_hash.isChecked():
            self.start_hash_calc()

    # --- THREAD GOP RÁPIDA ---
    def start_gop_analysis(self):
        self.btn_analyze.setEnabled(False)
        self.btn_analyze.setText("Analisando Frames (Rápido)...")
        worker = GopAnalysisWorker(self.current_video_path)
        worker.finished.connect(self.on_gop_finished)
        worker.finished.connect(lambda: self.cleanup_worker(worker))
        worker.error.connect(
            lambda e: QMessageBox.critical(
                self, "Erro GOP", e))
        self.workers.append(worker)
        worker.start()

    def on_gop_finished(self, result):
        self.check_if_all_finished()
        if "report" in result:
            self.create_result_tab(
                "Análise GOP (Estrutural)", {
                    "Relatório Estrutural": result["report"]})

    # --- THREAD GOP PROFUNDA (Deep) ---
    def start_deep_gop_analysis(self):
        self.btn_analyze.setEnabled(False)
        self.btn_analyze.setText("Analisando Bitstream (FFprobe)...")
        worker = DeepGopWorker(self.current_video_path)
        worker.finished.connect(self.on_deep_gop_finished)
        worker.finished.connect(lambda: self.cleanup_worker(worker))
        worker.error.connect(
            lambda e: QMessageBox.critical(
                self,
                "Erro Deep GOP",
                f"Falha no FFprobe (verifique se está instalado):\n{e}"))
        self.workers.append(worker)
        worker.start()

    def on_deep_gop_finished(self, result):
        self.check_if_all_finished()
        if "report" in result:
            self.create_result_tab(
                "Deep GOP (FFprobe)", {
                    "Relatório Estrutural": result["report"]})
        elif "error" in result:
            QMessageBox.warning(self, "Aviso FFprobe", result["error"])

    # --- THREAD HASH ---
    def start_hash_calc(self):
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.btn_analyze.setEnabled(False)
        worker = HashWorker(self.current_video_path)
        worker.progress.connect(self.progress_bar.setValue)
        worker.finished.connect(self.on_hash_finished)
        worker.finished.connect(lambda: self.cleanup_worker(worker))
        self.workers.append(worker)
        worker.start()

    def on_hash_finished(self, result):
        self.progress_bar.setVisible(False)
        self.check_if_all_finished()
        if "error" in result:
            QMessageBox.critical(self, "Erro Hash", result["error"])
        else:
            content = "--- CADEIA DE CUSTÓDIA DIGITAL ---\n\n"
            content += f"Arquivo: {self.current_video_path}\n"
            content += "=" * 60 + "\n\n"
            content += f"MD5:    {result['md5'].upper()}\n"
            content += f"SHA256: {result['sha256'].upper()}\n"
            self.create_result_tab("Hash", {"Relatório Estrutural": content})

    # --- CONTROLE DE THREADS ---
    def cleanup_worker(self, worker):
        if worker in self.workers:
            self.workers.remove(worker)
        self.check_if_all_finished()

    def check_if_all_finished(self):
        """Reabilita o botão apenas se não houver threads rodando"""
        if not self.workers:
            self.btn_analyze.setEnabled(True)
            self.btn_analyze.setText("Executar Análise Selecionada")

    # --- UTILITÁRIOS DE ABA ---
    def create_result_tab(self, title, data_dict, full_mediainfo_text=None):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        text_area = QTextEdit()
        text_area.setReadOnly(True)
        text_area.setStyleSheet(
            "font-family: Consolas, 'Courier New', monospace; font-size: 10pt;")
        text_area.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        text_area.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)

        content = ""
        if "Relatório Estrutural" in data_dict:
            content = data_dict["Relatório Estrutural"]
        else:
            relevant_keys = [
                k for k in data_dict.keys() if not k.startswith('---')]
            max_len = (max(len(k)
                       for k in relevant_keys) + 2) if relevant_keys else 0
            for k, v in data_dict.items():
                if k.startswith('---'):
                    content += f"\n{k}\n"
                else:
                    content += f"{k:<{max_len}}: {v}\n"

        text_area.setText(content)
        layout.addWidget(text_area)

        if full_mediainfo_text:
            export_layout = QHBoxLayout()
            btn_export_full = QPushButton(
                "Exportar Relatório COMPLETO MediaInfo (TXT)")
            btn_export_full.setStyleSheet(
                "background-color: #3f6f96; color: white;")
            btn_export_full.clicked.connect(
                lambda: self.export_full_report(full_mediainfo_text))
            export_layout.addWidget(btn_export_full)
            export_layout.addStretch()
            layout.addLayout(export_layout)

        btn_export_tab = QPushButton(f"Exportar Conteúdo da Aba ({title})")
        btn_export_tab.clicked.connect(
            lambda: self.export_tab_content(
                content, title))
        layout.addWidget(btn_export_tab)
        self.tabs_results.addTab(tab, title)

    def export_full_report(self, content):
        options = QFileDialog.Options()
        
        # Gera prefixo baseado no arquivo atual
        if self.current_video_path:
            base_name = os.path.basename(self.current_video_path)
            name_no_ext, _ = os.path.splitext(base_name)
            default_name = f"{name_no_ext}_mediainfo_completo.txt"
        else:
            default_name = "MediaInfo_Completo.txt"
            
        file_name, _ = QFileDialog.getSaveFileName(
            self, "Salvar Relatório MediaInfo", default_name, "Texto (*.txt)", options=options)
            
        if file_name:
            with open(file_name, 'w', encoding='utf-8') as f:
                f.write(content)

    def export_tab_content(self, content, title):
        safe_title = title.replace(" ", "_").replace("/", "-").replace("(", "").replace(")", "").lower()
        
        # Gera prefixo baseado no arquivo atual
        if self.current_video_path:
            base_name = os.path.basename(self.current_video_path)
            name_no_ext, _ = os.path.splitext(base_name)
            default_name = f"{name_no_ext}_{safe_title}.txt"
        else:
            default_name = f"analise_{safe_title}.txt"
            
        file_name, _ = QFileDialog.getSaveFileName(
            self, "Salvar Relatório", default_name, "Texto (*.txt)")
            
        if file_name:
            with open(file_name, 'w', encoding='utf-8') as f:
                f.write(content)

    def closeEvent(self, event):
        if self.player_window:
            self.player_window.close()
        event.accept()
