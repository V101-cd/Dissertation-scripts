import sys
import copy
from PyQt6.QtCore import Qt, QPoint
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
    QSizePolicy,
    QStackedLayout,
    QToolButton,
    QVBoxLayout,
    QWidget,
    QTableWidget,
    QTableWidgetItem,
)
from PyQt6.QtGui import QPainter, QPixmap, QResizeEvent
import pylibpcap_follow_streams as parser
# import pylibpcap_follow_streams as parser

class FrameWindow(QScrollArea):

    def __init__(self, packet_name):
        # super(FrameWindow,self).__init__()
        super().__init__()
        self.packet_name = packet_name
        self.setWindowTitle(self.packet_name)
        self.widget = QWidget()
        self.layout = QVBoxLayout(self.widget)
        self.setWidget(self.widget)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setFixedSize(810,400)
        self.setWidgetResizable(True)

    
    def add_frame(self, frame, frame_name):
        self.layout.addWidget(QLabel(frame_name))
        self.layout.addWidget(frame)
    
    def add_verbose(self, message, verbose_type):
        self.layout.addWidget(QLabel(verbose_type + ": " + message))

    def add_diagram_label(self, diagram_label, header_name):
        self.layout.addWidget(QLabel(header_name))
        # self.layout.addWidget(diagram_label)
        self.layout.addLayout(diagram_label)

    def add_verbose_label(self, message):
        self.layout.addWidget(QLabel(message))

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
        # self.frame.setWordWrap(True)
        self.frame.setHorizontalHeaderLabels(self.headers)
        self.frame.setVerticalHeaderLabels([self.datatype, ""])
        self.frame.adjustSize()
        
        ##TODO: make the cells uneditable; make the cell sizes dynamic based on size of window etc.
        # self.frame.wordWrap()
        # self.frame.resizeColumnsToContents()
        # self.frame.resizeRowsToContents()

class header_diagram():
    def __init__(self, diagram_location, header_type, field_values, extension_header_diagram = None):
        super().__init__()
        self.layout = QVBoxLayout()
        self.field_values = field_values
        self.diagram = QPixmap(diagram_location)
        self.diagram_label = QLabel()
        self.diagram_label.setScaledContents(True)
        self.diagram_label.setPixmap(self.diagram)
        self.layout.addWidget(self.diagram_label)
        
        if header_type == "ethernet":
            self.diagram_label.setFixedSize(775,275)
            self.dst_addr_label = QLabel(str(self.field_values["dstaddr"]))
            self.dst_addr_label.setParent(self.diagram_label)
            self.dst_addr_label.move(QPoint(225,100))

            self.src_addr_label = QLabel(str(self.field_values["srcaddr"]))
            self.src_addr_label.setParent(self.diagram_label)
            self.src_addr_label.move(QPoint(540,145))

            self.ethtype_label = QLabel(str(self.field_values["ethtype"]))
            self.ethtype_label.setParent(self.diagram_label)
            self.ethtype_label.move(QPoint(165,220))
        
        if header_type == "arp":
            self.diagram_label.setFixedSize(775,350)
            self.hardware_type_label = QLabel(str(self.field_values["hw_type"]))
            self.hardware_type_label.setParent(self.diagram_label)
            self.hardware_type_label.move(QPoint(190,68))

            self.protocol_type_label = QLabel(str(self.field_values["proto_type"]))
            self.protocol_type_label.setParent(self.diagram_label)
            self.protocol_type_label.move(QPoint(525,68))

            self.hardware_size_label = QLabel(str(self.field_values["hw_size"]))
            self.hardware_size_label.setParent(self.diagram_label)
            self.hardware_size_label.move(QPoint(190,107))

            self.protocol_size_label = QLabel(str(self.field_values["proto_size"]))
            self.protocol_size_label.setParent(self.diagram_label)
            self.protocol_size_label.move(QPoint(355,107))

            self.opcode_label = QLabel(str(self.field_values["opcode"]))
            self.opcode_label.setParent(self.diagram_label)
            self.opcode_label.move(QPoint(525,107))

            self.src_mac_label = QLabel(str(self.field_values["srcmac"]))
            self.src_mac_label.setParent(self.diagram_label)
            self.src_mac_label.move(QPoint(235,148))

            self.src_ip_label = QLabel(str(self.field_values["proto_src_addrb"]))
            self.src_ip_label.setParent(self.diagram_label)
            self.src_ip_label.move(QPoint(545,185))

            self.dst_mac_label = QLabel(str(self.field_values["dstmac"]))
            self.dst_mac_label.setParent(self.diagram_label)
            self.dst_mac_label.move(QPoint(586,231))

            self.dst_ip_label = QLabel(str(self.field_values["proto_dst_addrb"]))
            self.dst_ip_label.setParent(self.diagram_label)
            self.dst_ip_label.move(QPoint(235,294))
        
        if header_type == "ip4":
            self.diagram_label.setFixedSize(775,350)
            self.version_label = QLabel("4")
            self.version_label.setParent(self.diagram_label)
            self.version_label.move(QPoint(106,80))

            self.header_length_label = QLabel(str(self.field_values["iphdrlen"]))
            self.header_length_label.setParent(self.diagram_label)
            self.header_length_label.move(QPoint(190,80))

            self.diff_serv_label = QLabel(str(self.field_values["dsfield"]))
            self.diff_serv_label.setParent(self.diagram_label)
            self.diff_serv_label.move(QPoint(315,80))

            self.length_label = QLabel(str(self.field_values["length"]))
            self.length_label.setParent(self.diagram_label)
            self.length_label.move(QPoint(514,69))

            self.ident_label = QLabel(str(self.field_values["ident"]))
            self.ident_label.setParent(self.diagram_label)
            self.ident_label.move(QPoint(178,108))

            self.reserved_label = QLabel(str(self.field_values["reserved"]))
            self.reserved_label.setParent(self.diagram_label)
            self.reserved_label.move(QPoint(408,120))

            self.df_label = QLabel(str(self.field_values["df"]))
            self.df_label.setParent(self.diagram_label)
            self.df_label.move(QPoint(429,120))

            self.mf_label = QLabel(str(self.field_values["mf"]))
            self.mf_label.setParent(self.diagram_label)
            self.mf_label.move(QPoint(449,120))

            self.frag_offset_label = QLabel(str(self.field_values["fragoffset"]))
            self.frag_offset_label.setParent(self.diagram_label)
            self.frag_offset_label.move(QPoint(590,108))

            self.ttl_label = QLabel(str(self.field_values["ttl"]))
            self.ttl_label.setParent(self.diagram_label)
            self.ttl_label.move(QPoint(178,147))

            self.protocol_label = QLabel(str(self.field_values["proto"]))
            self.protocol_label.setParent(self.diagram_label)
            self.protocol_label.move(QPoint(318,147))

            self.checksum_label = QLabel(str(self.field_values["chksum"]))
            self.checksum_label.setParent(self.diagram_label)
            self.checksum_label.move(QPoint(505,147))
            
            self.src_ip_label = QLabel(str(self.field_values["srcaddrb"]))
            self.src_ip_label.setParent(self.diagram_label)
            self.src_ip_label.move(QPoint(231,186))

            self.dst_ip_label = QLabel(str(self.field_values["dstaddrb"]))
            self.dst_ip_label.setParent(self.diagram_label)
            self.dst_ip_label.move(QPoint(231,226))

        if header_type == "ip6":
            self.diagram_label.setFixedSize(775,350)
            if extension_header_diagram != None:
                for i in range(len(self.field_values["extheaders"])):
                    self.ext_diagram = QPixmap(extension_header_diagram)
                    self.ext_diagram_label = QLabel()
                    self.ext_diagram_label.setScaledContents(True)
                    self.ext_diagram_label.setPixmap(self.ext_diagram)
                    self.ext_diagram_label.setFixedSize(765,46)
                    
                    self.extension_next_header_label = QLabel(str(self.field_values["extheaders"][i][0]))
                    self.extension_next_header_label.setParent(self.ext_diagram_label)
                    self.extension_next_header_label.move(QPoint(180,17))
                    self.layout.addWidget(self.ext_diagram_label)

    def get_diagram_label(self):
        # return self.diagram_label
        return self.layout
    
    def get_verbose_label(self):
        if self.field_values["verbose"] != None:
            return self.field_values["verbose"]
        return None
    
    # def resizeEvent(self, event):
    #     scaled_diagram = self.diagram.scaled(self.width(), self.height(), Qt.KeepAspectRatio, Qt.SmoothTransformation)
    #     self.diagram_label.setPixmap(scaled_diagram)
    #     self.update()

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
        
        # packet_info = ['fc:44:82:39:bc:1e', 'dc:a6:32:66:cd:5a', '0x800', b'E\x00\x009\xe4\x1b@\x00\x80\x11\xa4\xe5\xc0\xa8\x04\x05\xd8:\xd4\xca\xc2&\x01\xbb\x00%\xfe@@\xe9h\xef\xf7\xd3\xe4~>\xd9F\xf3\xa7v\x97U\xf0^E\x1e\xc1\x8f\xc7\x96\xd0\xe3\x08\x82\xe9'] ##dpkt identifies this length as 57 bytes (well, 57 something)
        # udp_packet_info = [56375, 443, 42, 61632, b"]\xfac\xc5\ns\xbb\xee-\x18\xea\x07\xab\xec\xc8\xdb\xaf\xea\x8bv\xd55?\xec\x1f\x13\x99\xa6Q'\xd0\xe7\xe9\xf9"]
        # packet_info = "<bound method Ethernet.__bytes__ of Ethernet(dst=b'\xfcD\x829\xbc\x1e', src=b'\xdc\xa62f\xcdZ', data=IP(tos=128, len=53, df=1, ttl=57, p=17, sum=14722, src=b'\x8e\xfa\xb4\x0e', dst=b'\xc0\xa8\x04\x05', opts=b'', data=UDP(sport=443, dport=51865, ulen=33, sum=47964, data=b'ZU\x1e\xa5\x9b\xfa\x84m\xcb\xb41]\xf8\xde\xdd\xdb\xd2\x8f\xda(`\r\x0fN\xe7')))>"
        # self.eth_btn = QPushButton("Ethernet")
        # self.eth_btn.hide()
        # self.eth_btn.pressed.connect(lambda: self.show_ethernet_frame("Test packet - Ethernet frame", packet_info))
        # packet_layer_button_layout.addWidget(self.eth_btn)
        # label_ethernet = QLabel()
        # label_ethernet.setStyleSheet('QLabel{background-color:purple}')
        # self.stacklayout.addWidget(label_ethernet)
        
        # self.udp_btn = QPushButton("UDP")
        # self.udp_btn.hide()
        # self.udp_btn.pressed.connect(lambda: self.show_udp_frame("Test packet - UDP frame", udp_packet_info))
        # packet_layer_button_layout.addWidget(self.udp_btn)

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
        # self.eth_btn.show()
        # self.udp_btn.show()
        packet_num = sender.text().split()[-1]
        packet_headers = self.pcap_dicts[int(packet_num)]
        print(packet_headers)
        packet_header_attributes = {}
        self.header_window = FrameWindow("Packet " + str(packet_num))
        for key in packet_headers:
            print(key)
            packet_header_attributes[key] = vars(packet_headers[key])
            if key == "ethernet":
                # self.visualise_header(packet_header_attributes[key], "Ethernet", [6,6,2], False, packet_header_attributes[key].keys())
                self.view_header_diagram(key, packet_header_attributes[key])
                print("visualised eth")
            if key == "arp":
                self.view_header_diagram(key, packet_header_attributes[key])
                # self.visualise_header(packet_header_attributes[key], "ARP", [2,2,6,4,6,4,0], False, packet_header_attributes[key].keys())
                print("visualised arp")
            if key == "ip4":
                self.view_header_diagram(key, packet_header_attributes[key])
                # self.visualise_header(packet_header_attributes[key], "IPv4", [4,8,16,16,3,13,8,8,16,32,32], True, packet_header_attributes[key].keys())
                print("visualised ipv4")
            if key == "ip6":
                self.view_header_diagram(key, packet_header_attributes[key])
                # self.visualise_header(packet_header_attributes[key], "IPv6", [4,8,20,16,8,8,128,128], True, packet_header_attributes[key].keys())
                print("visualised ipv6")
            if key == "tcp":
                self.visualise_header(packet_header_attributes[key], "TCP", [16,16,32,32,4,4,1,1,1,1,1,1,1,1,16,16,16], True, packet_header_attributes[key].keys())
                print("visualised tcp")
            if key == "udp":
                self.visualise_header(packet_header_attributes[key], "UDP", [16,16,16,16], True, packet_header_attributes[key].keys())
                print("visualised udp")
            if key == "icmp4":
                self.visualise_header(packet_header_attributes[key], "ICMPv4", [8,8,16,32], True, packet_header_attributes[key].keys())
                print("visualised icmpv4")
            if key == "icmp6":
                self.visualise_header(packet_header_attributes[key], "ICMPv6", [8,8,16], True, packet_header_attributes[key].keys())
                print("visualised icmpv6")

        self.header_window.show()
        print(packet_num, packet_header_attributes)
        
    def get_Ethernet_headers(self, packet_info):
        print(packet_info.split('('))

    def activate_tab_1(self):
        self.stacklayout.setCurrentIndex(0)

    def activate_tab_2(self):
        self.stacklayout.setCurrentIndex(1)

    def activate_tab_3(self):
        self.stacklayout.setCurrentIndex(2)

    def view_header_diagram(self, header_type, field_values):
        if header_type == "ethernet":
            diagram = header_diagram("./eth-frame-header.png", header_type, field_values)
            self.header_window.add_diagram_label(diagram.get_diagram_label(), "Ethernet")
            verbose_label = diagram.get_verbose_label()
            if verbose_label != None:
                self.header_window.add_verbose_label(verbose_label)
        if header_type == "arp":
            diagram = header_diagram("./arp-frame-header.png", header_type, field_values)
            self.header_window.add_diagram_label(diagram.get_diagram_label(), "ARP")
            verbose_label = diagram.get_verbose_label()
            if verbose_label != None:
                self.header_window.add_verbose_label(verbose_label)
        if header_type == "ip4":
            diagram = header_diagram("./ipv4-packet-header.png", header_type, field_values)
            self.header_window.add_diagram_label(diagram.get_diagram_label(), "IPv4")
            verbose_label = diagram.get_verbose_label()
            if verbose_label != None:
                self.header_window.add_verbose_label(verbose_label)
        if header_type == "ip6":
            if field_values["extheaders"] != []:
                diagram = header_diagram("./ipv6-base-packet-header.png", header_type, field_values, "./ipv6-packet-extension-header.png")
                # extension = True
            else:
                diagram = header_diagram("./ipv6-packet-header-without-extensions.png", header_type, field_values)
                # extension = None
            self.header_window.add_diagram_label(diagram.get_diagram_label(), "IPv6")
            # if extension != None:
            #     for _ in range(len(field_values["extheaders"])):
            #         self.header_window.add_diagram_label(extension.get_diagram_label(), "")
            verbose_label = diagram.get_verbose_label()
            if verbose_label != None:
                self.header_window.add_verbose_label(verbose_label)

    def visualise_header(self, packet_info : dict, header_type, field_sizes, bits_true, row_headers = [], verbose_list = []):
        if row_headers == []:
            row_headers = packet_info.keys()
        row_headers = list(row_headers)
        print
        if "verbose" in packet_info.keys():
            verbose_list.append(packet_info["verbose"])
            print("verbose in keys")
            cols = len(packet_info.keys()) - 1
        else:
            cols = len(packet_info.keys())
        rows = 1
        frame = draw_frame(cols, rows, row_headers, bits=bits_true)
        
        for i in range(cols):
            frame.frame.setItem(0,i,QTableWidgetItem(str(field_sizes[i])))
            frame.frame.setItem(1,i,QTableWidgetItem(str(packet_info[list(packet_info.keys())[i]])))
        self.header_window.add_frame(frame.frame, header_type)
        if verbose_list != []:
            for message in verbose_list:
                self.header_window.add_verbose(message, header_type + " Verbose")
                verbose_list.remove(message)
        self.header_window.resize(565,280)

app = QApplication(sys.argv)

window = MainWindow()
window.resize(1000,500)
window.show()

app.exec()
