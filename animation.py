import sys
from PySide6.QtCore import (Qt, QPropertyAnimation, QEasingCurve, QTimer, Property)
from PySide6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QHBoxLayout)
from PySide6.QtGui import (QPainter, QFont, QColor, QPen)

class CryptexCylinder(QWidget):
    def __init__(self, letter, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._angle = 0
        self._current_letter = letter
        self._target_letter = letter
        self.setMinimumSize(60, 120)
        self.font = QFont("Consolas", 36, QFont.Bold)

    def setAngle(self, angle):
        self._angle = angle
        self.update()

    def getAngle(self):
        return self._angle

    angle = Property(int, getAngle, setAngle)

    def setLetter(self, letter):
        self._current_letter = letter
        self.update()

    def getLetter(self):
        return self._current_letter

    def animate_to_letter(self, target_letter, duration=600):
        self._target_letter = target_letter
        self.anim = QPropertyAnimation(self, b"angle")
        self.anim.setStartValue(0)
        self.anim.setEndValue(360)
        self.anim.setDuration(duration)
        self.anim.setEasingCurve(QEasingCurve.OutBounce)
        self.anim.valueChanged.connect(self._on_anim_value)
        self.anim.finished.connect(lambda: self.setLetter(target_letter))
        self.anim.start()

    def _on_anim_value(self, angle):
        # During animation, show a random letter
        import random, string
        if angle < 350:
            self.setLetter(random.choice(string.ascii_letters + string.digits + "+"))
        else:
            self.setLetter(self._target_letter)
        self.setAngle(angle)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHints(QPainter.Antialiasing)
        painter.setPen(Qt.NoPen)
        # Cylinder background
        grad_color = QColor(60, 60, 65)
        painter.setBrush(grad_color)
        painter.drawEllipse(5, 20, 50, 80)
        # Cylinder rim
        painter.setBrush(QColor(80, 80, 140))
        painter.drawEllipse(0, 15, 60, 90)
        # Letter display
        painter.setFont(self.font)
        pen = QPen(QColor(240, 240, 240))
        painter.setPen(pen)
        painter.drawText(self.rect(), Qt.AlignCenter, self._current_letter)

class CryptexPasswordWidget(QWidget):
    def __init__(self, password, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.password = password
        self.cylinders = []
        self.init_ui()

    def init_ui(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #181828;
            }
            QLabel {
                color: #eee;
                font-size: 28px;
                font-family: 'Consolas';
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #444466, stop:1 #181828);
                color: #fff;
                border: 1px solid #444;
                border-radius: 12px;
                padding: 12px 24px;
                font-size: 18px;
            }
            QPushButton:hover {
                background: #6666aa;
            }
        """)
        main_layout = QVBoxLayout(self)
        main_layout.setAlignment(Qt.AlignCenter)
        title = QLabel("Cryptex Password Reveal")
        main_layout.addWidget(title)

        self.cylinder_layout = QHBoxLayout()
        self.cylinder_layout.setAlignment(Qt.AlignCenter)
        for c in self.password:
            cylinder = CryptexCylinder("?")
            self.cylinders.append(cylinder)
            self.cylinder_layout.addWidget(cylinder)
        main_layout.addLayout(self.cylinder_layout)

        self.reveal_btn = QPushButton("Reveal Password")
        self.reveal_btn.clicked.connect(self.start_animation)
        main_layout.addWidget(self.reveal_btn)

        self.final_label = QLabel("")
        main_layout.addWidget(self.final_label)

    def start_animation(self):
        self.reveal_btn.setEnabled(False)
        self.final_label.setText("")
        self._current_index = 0
        self.animate_next()

    def animate_next(self):
        if self._current_index < len(self.password):
            cylinder = self.cylinders[self._current_index]
            target_letter = self.password[self._current_index]
            cylinder.animate_to_letter(target_letter, duration=600)
            QTimer.singleShot(650, self.animate_next)
            self._current_index += 1
        else:
            QTimer.singleShot(650, self.show_password)

    def show_password(self):
        self.final_label.setText(f"Password: <b>{self.password}</b>")
        self.reveal_btn.setEnabled(True)

def main():
    app = QApplication(sys.argv)
    password = "KILLnow1TRUMP+"
    window = CryptexPasswordWidget(password)
    window.setWindowTitle("Cryptex Password Animator")
    window.resize(950, 350)
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
