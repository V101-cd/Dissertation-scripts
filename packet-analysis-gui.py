import sys

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QRadioButton,
    QButtonGroup,
    QStackedLayout,
    QVBoxLayout,
    QWidget,
    QTableWidget,
    QTableWidgetItem,
)

class FrameWindow(QWidget):
    """
    This "window" is a QWidget. If it has no parent, it
    will appear as a free-floating window as we want.
    """
    def __init__(self, packet_name, binary_frame, processed_frame):
        super().__init__()
        self.packet_name = packet_name
        self.binary_frame = binary_frame
        self.processed_frame = processed_frame

        self.setWindowTitle(self.packet_name)
        
        self.layout = QVBoxLayout()
        
        self.layout.addWidget(QLabel("Binary"))
        self.layout.addWidget(self.binary_frame)
        self.layout.addWidget(QLabel("Processed data"))
        self.layout.addWidget(self.processed_frame)
        self.setLayout(self.layout)
        

class draw_frame():
    def __init__(self, num_cols, num_rows, headers=[]):
        super().__init__()
        self.num_cols = num_cols
        self.num_rows = num_rows
        self.headers = headers
        
        self.frame =  QTableWidget(self.num_rows, self.num_cols)
        self.frame.setWordWrap(True)
        self.frame.setHorizontalHeaderLabels(self.headers)
        self.frame.setVerticalHeaderLabels([""])
            

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("TCPDump Analysis and Visualisation Tool")

        pagelayout = QVBoxLayout()
        button_layout = QHBoxLayout()
        self.stacklayout = QStackedLayout()

        pagelayout.addLayout(button_layout)
        pagelayout.addLayout(self.stacklayout)

        # btn = QPushButton("red")
        # btn.pressed.connect(self.activate_tab_1)
        # button_layout.addWidget(btn)
        # label_red = QLabel()
        # label_red.setStyleSheet('QLabel{background-color:red}')
        # self.stacklayout.addWidget(label_red)
        
        packet_info = ['de:ad:be:ef:00:01', 'ff:ff:ff:ff:ff:ff', 2048]
        
        btn = QPushButton("Ethernet")
        # btn.pressed.connect(self.activate_tab_1)
        btn.pressed.connect(lambda: self.show_ethernet_frame("Test packet - Ethernet frame", packet_info))
        button_layout.addWidget(btn)
        label_ethernet = QLabel()
        label_ethernet.setStyleSheet('QLabel{background-color:none}')
        self.stacklayout.addWidget(label_ethernet)

        btn = QPushButton("green")
        btn.pressed.connect(self.activate_tab_2)
        button_layout.addWidget(btn)
        label_green = QLabel()
        label_green.setStyleSheet('QLabel{background-color:green}')
        self.stacklayout.addWidget(label_green)

        btn = QPushButton("blue")
        btn.pressed.connect(self.activate_tab_3)
        button_layout.addWidget(btn)
        label_blue = QLabel()
        label_blue.setStyleSheet('QLabel{background-color:blue}')
        self.stacklayout.addWidget(label_blue)

        widget = QWidget()
        widget.setLayout(pagelayout)
        self.setCentralWidget(widget)

    def activate_tab_1(self):
        self.stacklayout.setCurrentIndex(0)

    def activate_tab_2(self):
        self.stacklayout.setCurrentIndex(1)

    def activate_tab_3(self):
        self.stacklayout.setCurrentIndex(2)
        
    def show_ethernet_frame(self, packet_name, packet_info):
             
        binary_frame = draw_frame(5,1,["Destination\naddress", "Source\naddress", "Type", "Data", "CRC"]).frame
        for i in range(2):
            binary_frame.setItem(0,i,QTableWidgetItem(str(packet_info[i])))
        binary_frame.setItem(0,2,QTableWidgetItem(hex(packet_info[2])))
        binary_frame.setItem(0,3,QTableWidgetItem(str("data")))
        binary_frame.setItem(0,4,QTableWidgetItem(str("CRC missing")))

        processed_frame = draw_frame(5,1,["Destination\naddress", "Source\naddress", "Type", "Data", "CRC"]).frame
        for i in range(2):
            processed_frame.setItem(0,i,QTableWidgetItem(str(packet_info[i])))
        processed_frame.setItem(0,2,QTableWidgetItem(str("IPv4")))
        processed_frame.setItem(0,3,QTableWidgetItem(str("data")))
        processed_frame.setItem(0,4,QTableWidgetItem(str("CRC missing")))
       
        # self.w = FrameWindow(packet_name, headers_grid, processed_headers_grid)
        self.w = FrameWindow(packet_name, binary_frame, processed_frame)
        self.w.resize(550,150)
        self.w.show()


app = QApplication(sys.argv)

window = MainWindow()
window.resize(1000,500)
window.show()

app.exec()
