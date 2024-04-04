import sys
import copy
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QFileDialog,
    QRadioButton,
    QButtonGroup,
    QListWidget,
    QListWidgetItem,
    QScrollArea,
    QStackedLayout,
    QToolButton,
    QVBoxLayout,
    QWidget,
    QTableWidget,
    QTableWidgetItem,
)
import pylibpcap_follow_streams as parser
# import pylibpcap_follow_streams as parser

class FrameWindow(QWidget):
    """
    This "window" is a QWidget. If it has no parent, it
    will appear as a free-floating window as we want.
    """
    def __init__(self, packet_name, binary_frame):
        super().__init__()
        self.packet_name = packet_name
        self.binary_frame = binary_frame

        self.setWindowTitle(self.packet_name)
        
        self.layout = QVBoxLayout()
        
        self.layout.addWidget(QLabel("Binary"))
        self.layout.addWidget(self.binary_frame)
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
        pcap_loader_layout = QHBoxLayout()
        packet_layer_button_layout = QHBoxLayout()
        pcap_loading_status_layout = QHBoxLayout()
        # self.stacklayout = QStackedLayout()

        pagelayout.addLayout(pcap_loader_layout)
        pagelayout.addLayout(packet_layer_button_layout)
        # pagelayout.addLayout(self.stacklayout)

        pcap_ldr_btn = QPushButton("Import PCAP files")
        pcap_loader_layout.addWidget(pcap_ldr_btn)
        pcap_ldr_btn.pressed.connect(lambda: self.pcap_loader())

        pagelayout.addLayout(pcap_loading_status_layout)
        self.pcap_loading_status = QLabel()
        pcap_loading_status_layout.addWidget(self.pcap_loading_status)

        self.scroll_area = QScrollArea()
        self.scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.scroll_area.setWidgetResizable(True)
        pagelayout.addWidget(self.scroll_area)
        
        packet_info = ['fc:44:82:39:bc:1e', 'dc:a6:32:66:cd:5a', '0x800', b'E\x00\x009\xe4\x1b@\x00\x80\x11\xa4\xe5\xc0\xa8\x04\x05\xd8:\xd4\xca\xc2&\x01\xbb\x00%\xfe@@\xe9h\xef\xf7\xd3\xe4~>\xd9F\xf3\xa7v\x97U\xf0^E\x1e\xc1\x8f\xc7\x96\xd0\xe3\x08\x82\xe9'] ##dpkt identifies this length as 57 bytes (well, 57 something)
        udp_packet_info = [56375, 443, 42, 61632, b"]\xfac\xc5\ns\xbb\xee-\x18\xea\x07\xab\xec\xc8\xdb\xaf\xea\x8bv\xd55?\xec\x1f\x13\x99\xa6Q'\xd0\xe7\xe9\xf9"]
        # packet_info = "<bound method Ethernet.__bytes__ of Ethernet(dst=b'\xfcD\x829\xbc\x1e', src=b'\xdc\xa62f\xcdZ', data=IP(tos=128, len=53, df=1, ttl=57, p=17, sum=14722, src=b'\x8e\xfa\xb4\x0e', dst=b'\xc0\xa8\x04\x05', opts=b'', data=UDP(sport=443, dport=51865, ulen=33, sum=47964, data=b'ZU\x1e\xa5\x9b\xfa\x84m\xcb\xb41]\xf8\xde\xdd\xdb\xd2\x8f\xda(`\r\x0fN\xe7')))>"
        self.eth_btn = QPushButton("Ethernet")
        self.eth_btn.hide()
        self.eth_btn.pressed.connect(lambda: self.show_ethernet_frame("Test packet - Ethernet frame", packet_info))
        packet_layer_button_layout.addWidget(self.eth_btn)
        # label_ethernet = QLabel()
        # label_ethernet.setStyleSheet('QLabel{background-color:purple}')
        # self.stacklayout.addWidget(label_ethernet)
        
        self.udp_btn = QPushButton("UDP")
        self.udp_btn.hide()
        self.udp_btn.pressed.connect(lambda: self.show_udp_frame("Test packet - UDP frame", udp_packet_info))
        packet_layer_button_layout.addWidget(self.udp_btn)

        # if packet_button in self.pcap_row_buttons .connect(lambda: self.packet_btn_clicked(i, pcap_list[i]))

        # label_udp = QLabel()
        # label_udp.setStyleSheet('QLabel{background-color:none}')
        # self.stacklayout.addWidget(label_udp)

        # btn = QPushButton("blue")
        # btn.pressed.connect(self.activate_tab_3)
        # packet_layer_button_layout.addWidget(btn)
        # label_blue = QLabel()
        # label_blue.setStyleSheet('QLabel{background-color:blue}')
        # self.stacklayout.addWidget(label_blue)

        widget = QWidget()
        widget.setLayout(pagelayout)
        self.setCentralWidget(widget)
    
    def pcap_loader(self):
        self.pcap_loading_status.setText("Loading pcap...")
        QApplication.processEvents()
        dialog = QFileDialog()
        dialog.setNameFilter("All PCAP files (*.pcap)") ## only open PCAP files
        dialog.setFileMode(QFileDialog.FileMode.ExistingFile) ## only let the user open files already created; only lets the user import one file at a time
        dialogSuccess = dialog.exec() ## has the user clicked 'Open'? returns 1 (True) if successful, 0 (False) if not (inc. if closed)
        if dialogSuccess:
            self.clear_layout_view()
            self.pcap_loading_status.setText("Parsing PCAP...")
            QApplication.processEvents()
            selected_files = dialog.selectedFiles()
            self.pcap_dicts = parser.pcap(selected_files[0]).get_packet_headers()
            self.pcap_loading_status.setText("Displaying packets...")
            QApplication.processEvents()
            pcap_packets_widget = self.display_pcap_list()
            print("packets_widget received in calling function")
            self.scroll_area.setWidget(pcap_packets_widget)
            self.scroll_area.show()
            self.pcap_loading_status.setText("PCAP successfully loaded!")
            QApplication.processEvents()

    
    def display_pcap_list(self):
        pcap_rows_widget = QWidget()
        pcap_rows = QVBoxLayout()
        pcap_len = len(self.pcap_dicts)
        # self.pcap_row_buttons = []
        for i in range(pcap_len):
            packet_btn = QPushButton("Packet " + str(i+1))
            # self.pcap_row_buttons.append(QPushButton("Packet " + str(i+1)))
            pcap_rows.addWidget(packet_btn)
            packet_btn.clicked.connect(lambda: self.packet_btn_clicked())
            print(i)
        print("Label generation completed")
        pcap_rows_widget.setLayout(pcap_rows)
        print("Setting scroll_area")
        return pcap_rows_widget
        # pcap_rows_widget = QWidget()
        # pcap_rows = QVBoxLayout()
        # pcap_len = len(pcap_list)
        # for i in range(pcap_len):
        #     packet_btn = QPushButton("Packet " + str(i+1))
        #     self.packet_button_dict[packet_btn] = (i+1, pcap_list[i+1])
        #     pcap_rows.addWidget(packet_btn)
        #     packet_btn.clicked.connect(lambda: self.packet_btn_clicked(self.packet_button_dict[packet_btn.text()]))
        #     print(i)
        # print("Label generation completed")
        # pcap_rows_widget.setLayout(pcap_rows)
        # print("Setting scroll_area")
        # return pcap_rows_widget

    def clear_layout_view(self):
        # self.pcap_rows_widget.setParent(None) ##should delete all rows in it too
        # for child in self.scroll_area.children():
        #     child.deleteLater()
        self.scroll_area.setWidget(QWidget())
        
    def packet_btn_clicked(self):
        # packet_num = packet_dictionary_tuple[0]
        # packet_headers = packet_dictionary_tuple[1]
        sender = self.sender()
        self.eth_btn.show()
        self.udp_btn.show()
        packet_num = sender.text().split()[-1]
        packet_headers = self.pcap_dicts[int(packet_num)]
        packet_header_attributes = {}
        for key in packet_headers:
            packet_header_attributes[key] = vars(packet_headers[key])
        print(packet_num, packet_header_attributes)
        
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
        ethernet_frame = draw_frame(cols,rows,["Destination\naddress", "Source\naddress", "Type", "Data", "CRC"], bits=False)    
        bits = [6,6,2,len(packet_info[3]),4]
        
        binary_frame = copy.deepcopy(ethernet_frame)
        
        for i in range(cols):
            binary_frame.frame.setItem(0,i,QTableWidgetItem(str(bits[i])))
        for i in range(rows+(cols-2)):
            binary_frame.frame.setItem(1,i,QTableWidgetItem(str(packet_info[i])))
       
        self.w = FrameWindow(packet_name, binary_frame.frame)
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
       
        self.w = FrameWindow(packet_name, binary_frame.frame)
        self.w.resize(565,280)
        self.w.show()

app = QApplication(sys.argv)

window = MainWindow()
window.resize(1000,500)
window.show()

app.exec()
