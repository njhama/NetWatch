from PyQt5.QtWidgets import QMainWindow, QTextEdit, QPushButton, QVBoxLayout, QWidget, QApplication
from multiprocessing import Process, Queue
from sniffer.sniffer import run_sniffer
from PyQt5.QtCore import QTimer
from .stylesheet import DARK_THEME_STYLESHEET

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.setStyleSheet(DARK_THEME_STYLESHEET)

    def initUI(self):
        self.setWindowTitle('Net Watch')
        self.setGeometry(100, 100, 800, 600)
        layout = QVBoxLayout()
        self.textEdit = QTextEdit()
        self.textEdit.setReadOnly(True)
        layout.addWidget(self.textEdit)
        self.btnStart = QPushButton('Start Sniffing', self)
        self.btnStart.clicked.connect(self.start_sniffing)
        layout.addWidget(self.btnStart)
        self.btnStop = QPushButton('Stop Sniffing', self)
        self.btnStop.clicked.connect(self.stop_sniffing)
        self.btnStop.setEnabled(False)
        layout.addWidget(self.btnStop)
        centralWidget = QWidget()
        centralWidget.setLayout(layout)
        self.setCentralWidget(centralWidget)
        self.sniffer_process = None
        self.update_timer = None

    def start_sniffing(self):
        self.btnStart.setEnabled(False)
        self.btnStop.setEnabled(True)
        self.queue = Queue()
        self.sniffer_process = Process(target=run_sniffer, args=(self.queue,))
        self.sniffer_process.start()
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_text)
        self.update_timer.start(1000)  
    
    def stop_sniffing(self):
        if self.sniffer_process and self.sniffer_process.is_alive():
            self.sniffer_process.terminate()
        if self.update_timer:
            self.update_timer.stop()
        self.btnStart.setEnabled(True)
        self.btnStop.setEnabled(False)

    def update_text(self):
        while not self.queue.empty():
            text = self.queue.get()
            self.textEdit.append(text)
