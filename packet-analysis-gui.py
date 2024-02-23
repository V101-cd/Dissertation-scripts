import sys
import copy
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
    def __init__(self, num_cols, num_rows, headers=[], bits=True):
        super().__init__()
        self.num_cols = num_cols
        self.num_rows = num_rows+1
        self.headers = headers
        self.bits = bits
        if self.bits == True:
            self.datatype = "Bits"
        else:
            self.datatype = "Bytes"
        
        self.frame = QTableWidget(self.num_rows, self.num_cols)
        self.frame.setWordWrap(True)
        self.frame.setHorizontalHeaderLabels(self.headers)
        self.frame.setVerticalHeaderLabels([self.datatype, ""])
        
        ##TODO: make the cells uneditable; make the cell sizes dynamic based on size of window etc.
        # self.frame.wordWrap()
        # self.frame.resizeColumnsToContents()
        # self.frame.resizeRowsToContents()
    def __deepcopy__(self, memodict={}):
        new_frame = draw_frame(self.num_cols, self.num_rows, self.headers, self.bits)
        new_frame.__dict__.update(self.__dict__)
        new_frame.num_cols = copy.deepcopy(self.num_cols, memodict)
        new_frame.num_rows = copy.deepcopy(self.num_rows, memodict)
        new_frame.headers = copy.deepcopy(self.headers, memodict)
        new_frame.bits = copy.deepcopy(self.bits, memodict)
        new_frame.datatype = copy.deepcopy(self.datatype, memodict)
        new_frame.frame = QTableWidget(new_frame.num_rows, new_frame.num_cols)
        new_frame.frame.setWordWrap(True)
        new_frame.frame.setHorizontalHeaderLabels(new_frame.headers)
        new_frame.frame.setVerticalHeaderLabels([new_frame.datatype, ""])
        return new_frame
     

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
        
        # packet_info = ['de:ad:be:ef:00:01', 'ff:ff:ff:ff:ff:ff', 2048]
        packet_info = ['fc:44:82:39:bc:1e', 'dc:a6:32:66:cd:5a', '0x800', b'E\x00\x009\xe4\x1b@\x00\x80\x11\xa4\xe5\xc0\xa8\x04\x05\xd8:\xd4\xca\xc2&\x01\xbb\x00%\xfe@@\xe9h\xef\xf7\xd3\xe4~>\xd9F\xf3\xa7v\x97U\xf0^E\x1e\xc1\x8f\xc7\x96\xd0\xe3\x08\x82\xe9'] ##dpkt identifies this length as 57 bytes (well, 57 something)
        udp_packet_info = [56375, 443, 42, 61632, b"]\xfac\xc5\ns\xbb\xee-\x18\xea\x07\xab\xec\xc8\xdb\xaf\xea\x8bv\xd55?\xec\x1f\x13\x99\xa6Q'\xd0\xe7\xe9\xf9"]
        # packet_info = "<bound method Ethernet.__bytes__ of Ethernet(dst=b'\xfcD\x829\xbc\x1e', src=b'\xdc\xa62f\xcdZ', data=IP(tos=128, len=53, df=1, ttl=57, p=17, sum=14722, src=b'\x8e\xfa\xb4\x0e', dst=b'\xc0\xa8\x04\x05', opts=b'', data=UDP(sport=443, dport=51865, ulen=33, sum=47964, data=b'ZU\x1e\xa5\x9b\xfa\x84m\xcb\xb41]\xf8\xde\xdd\xdb\xd2\x8f\xda(`\r\x0fN\xe7')))>"
        btn = QPushButton("Ethernet")
        # btn.pressed.connect(self.activate_tab_1)
        btn.pressed.connect(lambda: self.show_ethernet_frame("Test packet - Ethernet frame", packet_info))
        button_layout.addWidget(btn)
        label_ethernet = QLabel()
        label_ethernet.setStyleSheet('QLabel{background-color:none}')
        self.stacklayout.addWidget(label_ethernet)

        # btn = QPushButton("green")
        # btn.pressed.connect(self.activate_tab_2)
        # button_layout.addWidget(btn)
        # label_green = QLabel()
        # label_green.setStyleSheet('QLabel{background-color:green}')
        # self.stacklayout.addWidget(label_green)
        
        btn = QPushButton("UDP")
        btn.pressed.connect(lambda: self.show_udp_frame("Test packet - UDP frame", udp_packet_info))
        button_layout.addWidget(btn)
        label_udp = QLabel()
        label_udp.setStyleSheet('QLabel{background-color:none}')
        self.stacklayout.addWidget(label_udp)

        btn = QPushButton("blue")
        btn.pressed.connect(self.activate_tab_3)
        button_layout.addWidget(btn)
        label_blue = QLabel()
        label_blue.setStyleSheet('QLabel{background-color:blue}')
        self.stacklayout.addWidget(label_blue)

        widget = QWidget()
        widget.setLayout(pagelayout)
        self.setCentralWidget(widget)
        
    def get_Ethernet_headers(self, packet_info):
        print(packet_info.split('('))

    def activate_tab_1(self):
        self.stacklayout.setCurrentIndex(0)

    def activate_tab_2(self):
        self.stacklayout.setCurrentIndex(1)

    def activate_tab_3(self):
        self.stacklayout.setCurrentIndex(2)
        
    def show_ethernet_frame(self, packet_name, packet_info):
        
        cols = 5
        rows = 1
        # self.get_Ethernet_headers(packet_info)
        ethernet_frame = draw_frame(cols,rows,["Destination\naddress", "Source\naddress", "Type", "Data", "CRC"], bits=False)    
        bits = [6,6,2,len(packet_info[3]),4]
        
        binary_frame = copy.deepcopy(ethernet_frame)
        # print("bin ", id(binary_frame.frame))
        
        for i in range(cols):
            binary_frame.frame.setItem(0,i,QTableWidgetItem(str(bits[i])))
        for i in range(rows+(cols-2)):
            binary_frame.frame.setItem(1,i,QTableWidgetItem(str(packet_info[i])))
        # binary_frame.frame.setItem(1,2,QTableWidgetItem(packet_info[2]))
        # binary_frame.frame.setItem(1,3,QTableWidgetItem(str(packet_info[3])))
        # binary_frame.frame.setItem(1,4,QTableWidgetItem(str("CRC missing")))

        processed_frame = copy.deepcopy(ethernet_frame)
        # print("proc ", id(processed_frame.frame))
        for i in range(cols):
            processed_frame.frame.setItem(0,i,QTableWidgetItem(str(bits[i])))
        for i in range(rows+(cols-2)):
            processed_frame.frame.setItem(1,i,QTableWidgetItem(str(packet_info[i])))
        # processed_frame.frame.setItem(1,2,QTableWidgetItem(str("IPv4")))
        # processed_frame.frame.setItem(1,3,QTableWidgetItem(str(packet_info[3])))
        # processed_frame.frame.setItem(1,4,QTableWidgetItem(str("CRC missing")))
       
        self.w = FrameWindow(packet_name, binary_frame.frame, processed_frame.frame)
        self.w.resize(565,280)
        self.w.show()

    def show_udp_frame(self, packet_name, packet_info):
             
        cols = 5
        rows = 1
        # self.get_Ethernet_headers(packet_info)
        udp_frame = draw_frame(cols,rows,["Source\nport", "Destination\nport", "UDP\nlength", "Checksum", "Data"], bits=True)    
        bits = [16,16,16,16,len(packet_info[4])]
        
        binary_frame = copy.deepcopy(udp_frame)
        # print("bin ", id(binary_frame.frame))
        
        for i in range(cols):
            binary_frame.frame.setItem(0,i,QTableWidgetItem(str(bits[i])))
        for i in range(rows+(cols-1)):
            binary_frame.frame.setItem(1,i,QTableWidgetItem(str(packet_info[i])))
        # binary_frame.frame.setItem(1,2,QTableWidgetItem(packet_info[2]))
        # binary_frame.frame.setItem(1,3,QTableWidgetItem(str(packet_info[3])))
        # binary_frame.frame.setItem(1,4,QTableWidgetItem(str("")))

        processed_frame = copy.deepcopy(udp_frame)
        # print("proc ", id(processed_frame.frame))
        for i in range(cols):
            processed_frame.frame.setItem(0,i,QTableWidgetItem(str(bits[i])))
        for i in range(rows+(cols-1)):
            processed_frame.frame.setItem(1,i,QTableWidgetItem(str(packet_info[i])))
        # processed_frame.frame.setItem(1,2,QTableWidgetItem(str("IPv4")))
        # processed_frame.frame.setItem(1,3,QTableWidgetItem(str(packet_info[3])))
        # processed_frame.frame.setItem(1,4,QTableWidgetItem(str("CRC missing")))
       
        self.w = FrameWindow(packet_name, binary_frame.frame, processed_frame.frame)
        self.w.resize(565,280)
        self.w.show()

app = QApplication(sys.argv)

window = MainWindow()
window.resize(1000,500)
window.show()

app.exec()
