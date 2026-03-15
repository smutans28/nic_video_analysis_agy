# ui/player_window.py
import cv2
import os
import numpy as np
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel,
    QPushButton,
    QHBoxLayout,
    QMessageBox,
    QFileDialog,
    QSizePolicy,
    QSlider)
from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtGui import QImage, QPixmap, QIcon
from PySide6.QtMultimedia import QMediaPlayer, QAudioOutput
import utils

ASSETS_DIR = "assets"
ICON_FILENAME = "icone.ico"


class VideoPlayerWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Visualizador de Vídeo - NIC Forensic")
        self.setObjectName("MainPlayer")

        # --- 1. CONFIGURAÇÃO DE ÍCONE DA JANELA ---
        icon_path = utils.resource_path(os.path.join("assets", "icone.ico"))
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        # Estilo Global
        self.setStyleSheet("""
            #MainPlayer { background-color: #121212; }
            QLabel { color: #eeeeee; }
            QMessageBox { background-color: #f0f0f0; color: black; }
            QMessageBox QLabel { color: black; }
            QMessageBox QPushButton {
                background-color: #2980b9; color: white;
                border-radius: 4px; padding: 6px 15px; font-weight: bold;
            }
            QMessageBox QPushButton:hover { background-color: #3498db; }
            QSlider::groove:horizontal {
                border: 1px solid #333; height: 6px; background: #2d2d2d; border-radius: 3px;
            }
            QSlider::handle:horizontal {
                background: #3498db; border: 1px solid #3498db; width: 14px;
                height: 14px; margin: -5px 0; border-radius: 7px;
            }
        """)

        # --- VARIÁVEIS DE VÍDEO (OPENCV) ---
        self.cap = None
        self.current_frame = None
        self.total_frames = 0
        self.fps = 0
        self.duration_ms = 0

        self.scale_factor = 1.0
        self.original_width = 0
        self.original_height = 0
        self.current_video_name = "video"
        self.is_seeking = False

        # --- VARIÁVEIS DE ÁUDIO (QTMULTIMEDIA) ---
        self.audio_player = QMediaPlayer()
        self.audio_output = QAudioOutput()
        self.audio_player.setAudioOutput(self.audio_output)
        self.audio_output.setVolume(1.0)  # Volume 100%

        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)

        # --- LAYOUT ---
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)

        # Área do Vídeo
        self.video_label = QLabel("Aguardando vídeo...")
        self.video_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.video_label.setStyleSheet(
            "color: #555; font-size: 20px; border: 1px solid #333;")
        self.video_label.setSizePolicy(
            QSizePolicy.Policy.Ignored,
            QSizePolicy.Policy.Ignored)
        self.layout.addWidget(
            self.video_label,
            0,
            Qt.AlignmentFlag.AlignCenter)

        # --- BARRA DE CONTROLE ---
        self.control_bar = QWidget()
        self.control_bar.setStyleSheet(
            "background-color: #2d2d2d; border-top: 1px solid #444;")
        self.control_bar.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Fixed)

        bar_layout = QVBoxLayout(self.control_bar)
        bar_layout.setContentsMargins(10, 5, 10, 5)

        # Slider
        self.slider = QSlider(Qt.Horizontal)
        self.slider.setRange(0, 0)
        self.slider.setCursor(Qt.PointingHandCursor)
        # Impede roubo de foco do teclado
        self.slider.setFocusPolicy(Qt.NoFocus)

        self.slider.sliderPressed.connect(self.on_slider_pressed)
        self.slider.sliderReleased.connect(self.on_slider_released)
        self.slider.sliderMoved.connect(self.on_slider_moved)

        bar_layout.addWidget(self.slider)

        # Botões e Status
        btns_layout = QHBoxLayout()

        self.lbl_filename = QLabel("Nenhum arquivo")
        self.lbl_filename.setStyleSheet(
            "color: #cccccc; font-family: Consolas; font-size: 12px; font-style: italic; "
            "background-color: #3a3a3a; border-radius: 4px; padding: 4px 8px;"
        )

        self.status_label = QLabel(
            "Frame: 0/0 | Tempo: 00:00 / 00:00 | Zoom: 100%")
        self.status_label.setStyleSheet(
            "color: #eeeeee; font-family: Consolas; font-size: 12px; font-weight: bold; margin: 0 10px;")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        btn_export = QPushButton("📷 Exportar Frame")
        btn_export.setStyleSheet(
            "background-color: #2980b9; color: white; border-radius: 4px; padding: 6px 12px; font-weight: bold;")
        btn_export.clicked.connect(self.export_current_frame)

        btns_layout.addWidget(self.lbl_filename)
        btns_layout.addStretch()
        btns_layout.addWidget(self.status_label)
        btns_layout.addStretch()
        btns_layout.addWidget(btn_export)

        bar_layout.addLayout(btns_layout)
        self.layout.addWidget(self.control_bar)

        # Timer para atualização visual
        self.timer = QTimer()
        self.timer.timeout.connect(self.next_frame)

    # --- CONTROLE DO SLIDER ---
    def on_slider_pressed(self):
        self.is_seeking = True
        self.timer.stop()
        self.audio_player.pause()  # Pausa áudio ao arrastar

    def on_slider_moved(self, position):
        # Visualiza rápido, sem sync áudio pesado
        self.seek_frame(position, sync_audio=False)

    def on_slider_released(self):
        position = self.slider.value()
        # Sincroniza áudio ao soltar
        self.seek_frame(position, sync_audio=True)
        self.is_seeking = False
        self.setFocus()  # Devolve foco para atalhos

    def seek_frame(self, frame_no, sync_audio=True):
        if self.cap and self.cap.isOpened():
            frame_no = max(0, min(frame_no, self.total_frames - 1))
            self.cap.set(cv2.CAP_PROP_POS_FRAMES, frame_no)
            ret, frame = self.cap.read()
            if ret:
                self.display_frame(frame)
                self.update_status()

            # Sincronia de Áudio
            if sync_audio and self.fps > 0:
                time_ms = int((frame_no / self.fps) * 1000)
                self.audio_player.setPosition(time_ms)

    # --- FORMAT E HELPERS ---
    def format_time(self, ms):
        s = int(ms / 1000)
        msec = int(ms % 1000)
        m, s = divmod(s, 60)
        h, m = divmod(m, 60)
        return f"{h:02d}:{m:02d}:{s:02d}.{msec:03d}"

    def update_view_geometry(self):
        if self.original_width > 0:
            new_w = int(self.original_width * self.scale_factor)
            new_h = int(self.original_height * self.scale_factor)
            self.video_label.setFixedSize(new_w, new_h)
            self.adjustSize()

    def show_controls_info(self):
        msg = QMessageBox(self)
        msg.setWindowTitle("Controles")
        icon_path = utils.resource_path(os.path.join("assets", "icone.ico"))
        if os.path.exists(icon_path):
            msg.setWindowIcon(QIcon(icon_path))
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setText("""
        <h3 style='color:black;'>Guia de Controles</h3>
        <ul style='color:black;'>
            <li><b>ESPAÇO:</b> Play / Pause (Com Áudio).</li>
            <li><b>SLIDER:</b> Navegação Rápida.</li>
            <li><b>SETAS:</b> Frame a frame (Mudo).</li>
            <li><b>SHIFT + SETAS:</b> Pula 10 frames.</li>
            <li><b>ZOOM:</b> Teclas (+) e (-).</li>
        </ul>
        """)
        msg.addButton("Entendi", QMessageBox.ButtonRole.AcceptRole)
        msg.exec()

    # --- LÓGICA DO PLAYER ---
    def load_video(self, path):
        # Limpeza anterior
        if self.cap:
            self.cap.release()
        self.audio_player.stop()
        self.audio_player.setSource(QUrl())  # Limpa source

        self.cap = cv2.VideoCapture(path)
        if self.cap.isOpened():
            # Configura Vídeo
            self.total_frames = int(self.cap.get(cv2.CAP_PROP_FRAME_COUNT))
            self.fps = self.cap.get(cv2.CAP_PROP_FPS)
            if self.fps == 0:
                self.fps = 30

            self.slider.setRange(0, self.total_frames - 1)
            self.original_width = int(self.cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            self.original_height = int(self.cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            self.scale_factor = 1.0
            self.duration_ms = (self.total_frames / self.fps) * 1000

            # Configura Áudio (Carrega o mesmo arquivo)
            self.audio_player.setSource(QUrl.fromLocalFile(path))

            # UI Updates
            fname = os.path.basename(path)
            self.lbl_filename.setText(
                (fname[:30] + '..') if len(fname) > 30 else fname)
            self.current_video_name = os.path.splitext(fname)[0]

            self.timer.setInterval(int(1000 / self.fps))
            self.update_view_geometry()

            # Estado Inicial
            self.cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
            self.next_frame()  # Mostra frame 0

            self.activateWindow()
            self.setFocus()
            self.show_controls_info()
            return True
        return False

    def play_pause(self):
        if self.timer.isActive():
            # PAUSE
            self.timer.stop()
            self.audio_player.pause()
        else:
            # PLAY
            # Se chegou no fim, reinicia
            if self.cap and self.cap.get(
                    cv2.CAP_PROP_POS_FRAMES) >= self.total_frames - 1:
                self.cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
                self.audio_player.setPosition(0)

            # Sincronia fina antes de soltar o play
            current_frame = self.cap.get(cv2.CAP_PROP_POS_FRAMES)
            start_ms = int((current_frame / self.fps) * 1000)
            self.audio_player.setPosition(start_ms)

            self.audio_player.play()
            self.timer.start()

    def next_frame(self):
        if self.cap and self.cap.isOpened():
            ret, frame = self.cap.read()
            if ret:
                self.display_frame(frame)
                if not self.is_seeking:
                    pos = int(self.cap.get(cv2.CAP_PROP_POS_FRAMES))
                    self.slider.blockSignals(True)
                    self.slider.setValue(pos)
                    self.slider.blockSignals(False)
            else:
                # Fim do vídeo
                self.timer.stop()
                self.audio_player.stop()

    def display_frame(self, frame):
        self.current_frame = frame
        frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        h, w, ch = frame_rgb.shape
        bytes_per_line = ch * w
        qt_img = QImage(
            frame_rgb.data,
            w,
            h,
            bytes_per_line,
            QImage.Format.Format_RGB888)

        target_w = int(self.original_width * self.scale_factor)
        target_h = int(self.original_height * self.scale_factor)
        pixmap = QPixmap.fromImage(qt_img).scaled(
            target_w,
            target_h,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation)
        self.video_label.setPixmap(pixmap)
        self.update_status()

    def update_status(self):
        if self.cap and self.cap.isOpened():
            if self.is_seeking:
                pos = self.slider.value()
            else:
                pos = int(self.cap.get(cv2.CAP_PROP_POS_FRAMES))

            ms = self.cap.get(cv2.CAP_PROP_POS_MSEC)
            zoom_pct = int(self.scale_factor * 100)
            self.status_label.setText(
                f"Frame: {pos}/{self.total_frames} | "
                f"Tempo: {self.format_time(ms)} / {self.format_time(self.duration_ms)} | Zoom: {zoom_pct}%"
            )

    # def export_current_frame(self):
    #     if self.current_frame is not None:
    #         pos = int(self.cap.get(cv2.CAP_PROP_POS_FRAMES))
    #         ms = self.cap.get(cv2.CAP_PROP_POS_MSEC)
    #         h, w, c = self.current_frame.shape
    #
    #         font = cv2.FONT_HERSHEY_COMPLEX_SMALL
    #         font_scale = max(0.5, w / 1500.0)
    #         padding = 10
    #         (text_w, text_h), _ = cv2.getTextSize("TEST", font, font_scale, 1)
    #         footer_h = text_h + (padding * 2)
    #
    #         img = np.zeros((h + footer_h, w, c), dtype=np.uint8)
    #         img[0:h, 0:w] = self.current_frame
    #
    #         cv2.putText(img, f"TIME: {self.format_time(ms)}", (10, h + footer_h - padding), font, font_scale,
    #                     (0, 255, 0), 1, cv2.LINE_AA)
    #         f_str = f"Frame: {pos}"
    #         (fw, _), _ = cv2.getTextSize(f_str, font, font_scale, 1)
    #         cv2.putText(img, f_str, (w - fw - 10, h + footer_h - padding), font, font_scale, (0, 255, 0), 1,
    #                     cv2.LINE_AA)
    #
    #         options = QFileDialog.Options()
    #         name = f"{self.current_video_name}_frame_{pos}.png"
    #         fname, _ = QFileDialog.getSaveFileName(self, "Exportar", name, "PNG (*.png);;JPG (*.jpg)", options=options)
    #
    #         if fname:
    #             cv2.imwrite(fname, img)
    #             msg = QMessageBox(self)
    #             icon_path = utils.resource_path(os.path.join("assets", "icone.ico"))
    #             if os.path.exists(icon_path): msg.setWindowIcon(QIcon(icon_path))
    #             msg.setIcon(QMessageBox.Icon.Information);
    #             msg.setWindowTitle("Sucesso")
    #             msg.setText(f"Frame exportado:\n{fname}");
    #             msg.exec()
    #     else:
    #         QMessageBox.warning(self, "Aviso", "Nenhum frame.")

    def export_current_frame(self):
        if self.current_frame is not None:
            # 1. Dados do Frame Atual
            pos = int(self.cap.get(cv2.CAP_PROP_POS_FRAMES))
            ms = self.cap.get(cv2.CAP_PROP_POS_MSEC)
            h, w, c = self.current_frame.shape

            # 2. Configuração da Fonte (Mais robusta e legível)
            font = cv2.FONT_HERSHEY_DUPLEX  # Fonte mais "cheia" que a anterior
            # Escala dinâmica baseada na largura da imagem (evita texto
            # minúsculo em 4K)
            font_scale = max(0.4, w / 1200.0)
            print(font_scale)
            thickness = max(1, int(font_scale * 2))  # Espessura proporcional

            # 3. Cálculo do Tamanho da Tarja
            # Mede a altura que o texto vai ocupar
            (text_w, text_h), baseline = cv2.getTextSize(
                "TESTE 123", font, font_scale, thickness)
            padding_vertical = 7  # Espaço acima e abaixo do texto
            footer_height = text_h + (padding_vertical * 2) + baseline

            # 4. Criação da Imagem Final (Canvas)
            # Cria uma nova imagem preta com a altura original + a altura do
            # rodapé
            final_img = np.zeros((h + footer_height, w, c), dtype=np.uint8)

            # Copia o frame original para a parte superior
            final_img[0:h, 0:w] = self.current_frame

            # 5. Desenhando o Texto na Tarja Preta (Rodapé)
            # A tarja preta já é o fundo natural do np.zeros na parte inferior

            # Texto da Esquerda (Tempo)
            time_str = f"Time: {self.format_time(ms)}"
            # Posição Y: Fim da imagem original + padding + altura do texto
            text_y = h + padding_vertical + text_h
            cv2.putText(final_img, time_str, (5, text_y), font,
                        font_scale, (0, 255, 0), thickness, cv2.LINE_AA)

            # Texto da Direita (Frame)
            frame_str = f"Frame: {pos}"
            (fw, fh), _ = cv2.getTextSize(frame_str, font, font_scale, thickness)
            # Posição X: Largura total - largura do texto - margem
            text_x_right = w - fw - 5
            cv2.putText(final_img, frame_str, (text_x_right, text_y),
                        font, font_scale, (0, 255, 0), thickness, cv2.LINE_AA)

            # 6. Diálogo de Salvar
            options = QFileDialog.Options()
            # Sugere nome com padrão forense
            default_name = f"{self.current_video_name}_Frame_{pos:06d}.png"
            fname, _ = QFileDialog.getSaveFileName(
                self, "Salvar Frame", default_name, "Imagem PNG (*.png);;Imagem JPG (*.jpg)", options=options)

            if fname:
                # Salva em alta qualidade
                if fname.lower().endswith('.jpg'):
                    cv2.imwrite(
                        fname, final_img, [
                            cv2.IMWRITE_JPEG_QUALITY, 100])
                else:
                    # PNG já é lossless por padrão
                    cv2.imwrite(fname, final_img)

                # Confirmação
                msg = QMessageBox(self)
                icon_path = utils.resource_path(
                    os.path.join("assets", "icone.ico"))
                if os.path.exists(icon_path):
                    msg.setWindowIcon(QIcon(icon_path))
                msg.setIcon(QMessageBox.Icon.Information)
                msg.setWindowTitle("Exportação Concluída")
                msg.setText(
                    f"Frame salvo com sucesso:\n\n{os.path.basename(fname)}")
                msg.exec()
        else:
            QMessageBox.warning(
                self, "Aviso", "Não há frame carregado para exportar.")

    def keyPressEvent(self, event):
        key = event.key()
        mods = event.modifiers()

        # Se for tecla de navegação, pausa para precisão
        if key in [Qt.Key.Key_Right, Qt.Key.Key_Left]:
            if self.timer.isActive():
                self.timer.stop()
                self.audio_player.pause()

        if key in [Qt.Key.Key_Plus, Qt.Key.Key_Equal]:
            self.scale_factor += 0.2
            self.update_view_geometry()
            if self.current_frame is not None:
                self.display_frame(self.current_frame)
        elif key == Qt.Key.Key_Minus:
            if self.scale_factor > 0.2:
                self.scale_factor -= 0.2
                self.update_view_geometry()
                if self.current_frame is not None:
                    self.display_frame(self.current_frame)

        elif key == Qt.Key.Key_Right:
            step = 10 if (mods & Qt.ShiftModifier) else 1
            current = int(self.cap.get(cv2.CAP_PROP_POS_FRAMES))
            if step == 1:
                self.next_frame_single()
            else:
                self.seek_frame(current + step, sync_audio=True)
                self.slider.setValue(current + step)

        elif key == Qt.Key.Key_Left:
            step = 10 if (mods & Qt.ShiftModifier) else 1
            current = int(self.cap.get(cv2.CAP_PROP_POS_FRAMES))
            target = max(0, current - step)
            if step == 1:
                self.prev_frame()
                self.slider.setValue(
                    int(self.cap.get(cv2.CAP_PROP_POS_FRAMES)))
            else:
                self.seek_frame(target, sync_audio=True)
                self.slider.setValue(target)

        elif key == Qt.Key.Key_Space:
            self.play_pause()

        else:
            super().keyPressEvent(event)

    def next_frame_single(self):
        # Avança um frame sem áudio (modo edição)
        self.next_frame()
        pos = int(self.cap.get(cv2.CAP_PROP_POS_FRAMES))
        self.slider.blockSignals(True)
        self.slider.setValue(pos)
        self.slider.blockSignals(False)

    def prev_frame(self):
        if self.cap and self.cap.isOpened():
            current = int(self.cap.get(cv2.CAP_PROP_POS_FRAMES))
            # Retrocede visualmente
            self.seek_frame(current - 2, sync_audio=False)

    def closeEvent(self, event):
        self.timer.stop()
        self.audio_player.stop()  # Para o áudio ao fechar
        if self.cap:
            self.cap.release()
        event.accept()
