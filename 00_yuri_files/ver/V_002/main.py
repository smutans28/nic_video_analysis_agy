# main.py
import sys
from PySide6.QtWidgets import QApplication
from ui.control_window import ControlWindow

if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Estilo Fusion (funciona bem em Windows/Mac/Linux)
    app.setStyle("Fusion")

    window = ControlWindow()
    window.show()

    sys.exit(app.exec())
