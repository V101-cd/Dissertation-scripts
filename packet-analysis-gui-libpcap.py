import sys
import copy
# from PyQt6 import uic
# import pyqtgraph as pg
import matplotlib
matplotlib.use('QtAgg')
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg
from matplotlib.figure import Figure
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
import packet_headers as headers

class FrameWindow(QScrollArea):

    def __init__(self, packet_name):
        super().__init__()
        self.packet_name = packet_name
        self.setWindowTitle(self.packet_name)
        self.widget = QWidget()
        self.layout = QVBoxLayout(self.widget)
        self.setWidget(self.widget)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setFixedSize(810,400)
        self.setWidgetResizable(True)

    def add_diagram_label(self, diagram_label, header_name):
        self.layout.addWidget(QLabel(header_name))
        self.layout.addLayout(diagram_label)

    def add_verbose_label(self, message):
        verbose_label = QLabel(message)
        verbose_label.setWordWrap(True)
        self.layout.addWidget(verbose_label)

class MatplotlibCanvas(FigureCanvasQTAgg):

    def __init__(self, parent=None, width=5, height=4, dpi=100):
        fig = Figure(figsize=(width, height), dpi=dpi)
        self.axes = fig.add_subplot(111)
        super(MatplotlibCanvas, self).__init__(fig)

class StreamsWindow(QScrollArea):

    def __init__(self, pcap_name):
        super().__init__()
        self.setWindowTitle("Streams in " + pcap_name)
        self.widget = QWidget()
        self.layout = QVBoxLayout(self.widget)
        self.setWidget(self.widget)
        # self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setFixedSize(810,400)
        self.setWidgetResizable(True)

    # def add_stream_graph(self, stream_name, connection_data):
    #     for key in connection_data:
    #         stream_graph, packets = self.generate_graph(key, connection_data[key])  ##change to [connection[key][i][0] for i in range(len(connection[key]))]
    #         stream_name_label = QLabel(stream_name + " : " + str(key))
    #         stream_name_label.setWordWrap(True)
    #         self.layout.addWidget(stream_name_label)
    #         self.layout.addWidget(stream_graph)
    #         packet_list = "Packets in connection " + stream_name + " : " + str(key) + " :\n"
    #         for packet in packets:
    #             packet_list += str(packet) + ", "
    #         packet_list_label = QLabel(packet_list[0:-2])
    #         packet_list_label.setWordWrap(True)
    #         self.layout.addWidget(packet_list_label)

    # def generate_graph(self, key, keyed_connection_data):
    #     self.plot_graph = MatplotlibCanvas(self)
    #     x = [keyed_connection_data[i][0] for i in range(len(keyed_connection_data))]
    #     y = [i+1 for i in range(len(keyed_connection_data))]
    #     self.plot_graph.axes.set_ybound(0, max(y))
    #     self.plot_graph.axes.set_xbound(0, max(x))
    #     self.plot_graph.axes.plot(x, y, marker='.', label=key)
    #     self.plot_graph.axes.legend()
    #     return (self.plot_graph, x)

    def add_stream_graph(self, stream_name, connection_data):
        stream_graph, legend, packet_list = self.generate_graph(connection_data)  ##change to [connection[key][i][0] for i in range(len(connection[key]))]
        stream_name_label = QLabel(stream_name + " :")
        stream_name_label.setWordWrap(True)
        self.layout.addWidget(stream_name_label)
        self.layout.addWidget(stream_graph)
        legend_label = QLabel(legend)
        legend_label.setWordWrap(True)
        self.layout.addWidget(legend_label)
        packet_list_label = QLabel(packet_list)
        packet_list_label.setWordWrap(True)
        self.layout.addWidget(packet_list_label)

    def generate_graph(self, connection_data):
        self.plot_graph = MatplotlibCanvas(self)
        packet_list = ""
        for key in connection_data:
            x = [connection_data[key][i][0] for i in range(len(connection_data[key]))]
            y = [i+1 for i in range(len(connection_data[key]))]
            self.plot_graph.axes.set_ybound(0, max(y))
            self.plot_graph.axes.set_xbound(0, max(x))
            self.plot_graph.axes.plot(x, y, marker='.', label=key)
            packet_list += "Packets in connection " + str(key) + " :\n"
            for packet in x:
                packet_list += str(packet) + ", "
            packet_list = packet_list[:-2] + "\n"
        self.plot_graph.axes.set_xlabel("Packet number")
        self.plot_graph.axes.set_ylabel("Number of packets in the stream")
        return (self.plot_graph, self.plot_graph.axes.legend(), packet_list)


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
            # self.diagram_label.setFixedSize(775,341)
            self.diagram_label.setFixedSize(775,500)

            self.version_label = QLabel("6")
            self.version_label.setParent(self.diagram_label)
            self.version_label.move(QPoint(106,90))

            self.traffic_class_label = QLabel(str(self.field_values["trafficclassfield"]))
            self.traffic_class_label.setParent(self.diagram_label)
            self.traffic_class_label.move(QPoint(230,90))

            self.flow_label = QLabel(str(self.field_values["flowlabel"]))
            self.flow_label.setParent(self.diagram_label)
            self.flow_label.move(QPoint(440,81))

            self.payload_len_label = QLabel(str(self.field_values["length"]))
            self.payload_len_label.setParent(self.diagram_label)
            self.payload_len_label.move(QPoint(210,122))

            self.next_header_label = QLabel(str(self.field_values["nextheader"]))
            self.next_header_label.setParent(self.diagram_label)
            self.next_header_label.move(QPoint(513,122))

            self.hop_limit_label = QLabel(str(self.field_values["hoplimit"]))
            self.hop_limit_label.setParent(self.diagram_label)
            self.hop_limit_label.move(QPoint(670,122))

            self.src_ip_label = QLabel(str(self.field_values["srcaddrb"]))
            self.src_ip_label.setParent(self.diagram_label)
            self.src_ip_label.move(QPoint(231,220))

            self.dst_ip_label = QLabel(str(self.field_values["dstaddrb"]))
            self.dst_ip_label.setParent(self.diagram_label)
            self.dst_ip_label.move(QPoint(231,400))

            if extension_header_diagram != None:
                for i in range(len(self.field_values["extheaders"])):
                    self.ext_diagram = QPixmap(extension_header_diagram)
                    self.ext_diagram_label = QLabel()
                    self.ext_diagram_label.setScaledContents(True)
                    self.ext_diagram_label.setPixmap(self.ext_diagram)
                    self.ext_diagram_label.setFixedSize(765,50)
                    
                    self.extension_next_header_label = QLabel(str(self.field_values["extheaders"][i][0]))
                    self.extension_next_header_label.setParent(self.ext_diagram_label)
                    self.extension_next_header_label.move(QPoint(180,17))
                    self.layout.addWidget(self.ext_diagram_label)

        if header_type == "udp":
            self.diagram_label.setFixedSize(775,150)
            self.source_port_label = QLabel(str(self.field_values["srcport"]))
            self.source_port_label.setParent(self.diagram_label)
            self.source_port_label.move(QPoint(189,69))

            self.dest_port_label = QLabel(str(self.field_values["dstport"]))
            self.dest_port_label.setParent(self.diagram_label)
            self.dest_port_label.move(QPoint(545,69))

            self.length_label = QLabel(str(self.field_values["length"]))
            self.length_label.setParent(self.diagram_label)
            self.length_label.move(QPoint(189,105))

            self.checksum_label = QLabel(str(self.field_values["chksum"]))
            self.checksum_label.setParent(self.diagram_label)
            self.checksum_label.move(QPoint(545,105))

        if header_type == "tcp":
            self.diagram_label.setFixedSize(775,290)
            self.source_port_label = QLabel(str(self.field_values["srcport"]))
            self.source_port_label.setParent(self.diagram_label)
            self.source_port_label.move(QPoint(189,71))

            self.dest_port_label = QLabel(str(self.field_values["dstport"]))
            self.dest_port_label.setParent(self.diagram_label)
            self.dest_port_label.move(QPoint(545,71))

            self.seq_num_label = QLabel(str(self.field_values["absseqnum"]))
            self.seq_num_label.setParent(self.diagram_label)
            self.seq_num_label.move(QPoint(252,118))

            self.acknowledgement_label = QLabel(str(self.field_values["absacknum"]))
            self.acknowledgement_label.setParent(self.diagram_label)
            self.acknowledgement_label.move(QPoint(252,159))

            self.header_length_label = QLabel(str(self.field_values["tcphdrlen"]))
            self.header_length_label.setParent(self.diagram_label)
            self.header_length_label.move(QPoint(106,210))

            self.reserved_label = QLabel(str(self.field_values["reserved"]))
            self.reserved_label.setParent(self.diagram_label)
            self.reserved_label.move(QPoint(187,210))

            self.cwr_label = QLabel(str(self.field_values["cwr"]))
            self.cwr_label.setParent(self.diagram_label)
            self.cwr_label.move(QPoint(241,210))

            self.ece_label = QLabel(str(self.field_values["ece"]))
            self.ece_label.setParent(self.diagram_label)
            self.ece_label.move(QPoint(262,210))

            self.urg_label = QLabel(str(self.field_values["urg"]))
            self.urg_label.setParent(self.diagram_label)
            self.urg_label.move(QPoint(283,210))

            self.ack_label = QLabel(str(self.field_values["ack"]))
            self.ack_label.setParent(self.diagram_label)
            self.ack_label.move(QPoint(304,210))

            self.psh_label = QLabel(str(self.field_values["psh"]))
            self.psh_label.setParent(self.diagram_label)
            self.psh_label.move(QPoint(325,210))

            self.rst_label = QLabel(str(self.field_values["rst"]))
            self.rst_label.setParent(self.diagram_label)
            self.rst_label.move(QPoint(346,210))

            self.syn_label = QLabel(str(self.field_values["syn"]))
            self.syn_label.setParent(self.diagram_label)
            self.syn_label.move(QPoint(367,210))

            self.fin_label = QLabel(str(self.field_values["fin"]))
            self.fin_label.setParent(self.diagram_label)
            self.fin_label.move(QPoint(388,210))

            self.advertised_window_label = QLabel(str(self.field_values["winsize"]))
            self.advertised_window_label.setParent(self.diagram_label)
            self.advertised_window_label.move(QPoint(587,199))

            self.checksum_label = QLabel(str(self.field_values["chksum"]))
            self.checksum_label.setParent(self.diagram_label)
            self.checksum_label.move(QPoint(210,241))

            self.urgent_pointer_label = QLabel(str(self.field_values["urgent"]))
            self.urgent_pointer_label.setParent(self.diagram_label)
            self.urgent_pointer_label.move(QPoint(545,241))

        if (header_type == "icmp4"):
            self.diagram_label.setFixedSize(775,150)
            self.type_label = QLabel(str(self.field_values["type"]))
            self.type_label.setParent(self.diagram_label)
            self.type_label.move(QPoint(147,69))

            self.code_label = QLabel(str(self.field_values["code"]))
            self.code_label.setParent(self.diagram_label)
            self.code_label.move(QPoint(315,69))

            self.checksum_label = QLabel(str(self.field_values["checksum"]))
            self.checksum_label.setParent(self.diagram_label)
            self.checksum_label.move(QPoint(514,69))

        if (header_type == "icmp6"):
            self.diagram_label.setFixedSize(775,150)
            self.type_label = QLabel(str(self.field_values["type"]))
            self.type_label.setParent(self.diagram_label)
            self.type_label.move(QPoint(147,69))

            self.code_label = QLabel(str(self.field_values["code"]))
            self.code_label.setParent(self.diagram_label)
            self.code_label.move(QPoint(315,69))

            self.checksum_label = QLabel(str(self.field_values["checksum"]))
            self.checksum_label.setParent(self.diagram_label)
            self.checksum_label.move(QPoint(514,69))


    def get_diagram_label(self):
        return self.layout
    
    def get_verbose_label(self):
        if self.field_values["verbose"] != None:
            return self.field_values["verbose"]
        return None

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("TCPDump Analysis and Visualisation Tool")

        pagelayout = QVBoxLayout()
        pcap_loader_layout = QHBoxLayout()
        # packet_layer_button_layout = QHBoxLayout()
        pcap_loading_status_layout = QHBoxLayout()

        pagelayout.addLayout(pcap_loader_layout)
        # pagelayout.addLayout(packet_layer_button_layout)

        pcap_ldr_btn = QPushButton("Import PCAP files")
        pcap_loader_layout.addWidget(pcap_ldr_btn)
        pcap_ldr_btn.pressed.connect(lambda: self.pcap_loader())

        pagelayout.addLayout(pcap_loading_status_layout)
        self.pcap_loading_status = QLabel()
        pcap_loading_status_layout.addWidget(self.pcap_loading_status)

        self.packet_visualisation_area = QHBoxLayout()
        self.scroll_area = QScrollArea()
        self.scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.scroll_area.setWidgetResizable(True)
        self.packet_visualisation_area.addWidget(self.scroll_area)
        pagelayout.addLayout(self.packet_visualisation_area)
        # pagelayout.addWidget(self.scroll_area)
        copyright = QLabel("© Vedika Parulkar, April 2024")
        pagelayout.addWidget(copyright, alignment=Qt.AlignmentFlag.AlignRight)

        self.streams_btn = QPushButton("View Streams")
        self.streams_btn.hide()
        self.streams_btn.pressed.connect(lambda: self.view_streams())
        self.packet_visualisation_area.addWidget(self.streams_btn)
        
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
            self.streams_btn.show()
            QApplication.processEvents()
            selected_files = dialog.selectedFiles()
            self.pcap_name = selected_files[0]
            self.pcap_dicts = parser.pcap(self.pcap_name).get_packet_headers()
            self.pcap_connections = parser.pcap(self.pcap_name).get_connections()
            self.pcap_ip4_datagrambytes = parser.pcap(self.pcap_name).get_ip4_datagrambytes()
            self.inv_ip4_datagrambytes = {value:key for key,value in self.pcap_ip4_datagrambytes.items()}
            self.pcap_loading_status.setText("Displaying packets...")
            QApplication.processEvents()
            pcap_packets_widget = self.display_pcap_list()
            self.stream_window = StreamsWindow(self.pcap_name)
            for name, connection in self.pcap_connections:
                self.stream_window.add_stream_graph(name, connection)
            print("packets_widget received in calling function")
            self.scroll_area.setWidget(pcap_packets_widget)
            self.scroll_area.show()
            self.pcap_loading_status.setText("PCAP successfully loaded!")
            QApplication.processEvents()

    
    def display_pcap_list(self):
        pcap_rows_widget = QWidget()
        pcap_rows = QVBoxLayout()
        pcap_len = len(self.pcap_dicts)
        for i in range(pcap_len):
            packet_btn = QPushButton("Packet " + str(i+1))
            pcap_rows.addWidget(packet_btn)
            packet_btn.clicked.connect(lambda: self.packet_btn_clicked())
        print("Label generation completed")
        pcap_rows_widget.setLayout(pcap_rows)
        print("Setting scroll_area")
        return pcap_rows_widget

    def clear_layout_view(self):
        self.scroll_area.setWidget(QWidget())

    def view_streams(self):
        self.stream_window.show()
        
    def packet_btn_clicked(self):
        sender = self.sender()
        packet_num = sender.text().split()[-1]
        packet_headers = self.pcap_dicts[int(packet_num)]
        print(packet_headers)
        packet_header_attributes = {}
        self.header_window = FrameWindow("Packet " + str(packet_num))
        for key in packet_headers:
            print(key)
            packet_header_attributes[key] = vars(packet_headers[key])
            if key == "ethernet":
                self.view_header_diagram(key, packet_header_attributes[key])
                print("visualised eth")
            if key == "arp":
                self.view_header_diagram(key, packet_header_attributes[key])
                print("visualised arp")
            if key == "ip4":
                self.view_header_diagram(key, packet_header_attributes[key])
                print("visualised ipv4")
            if key == "ip6":
                self.view_header_diagram(key, packet_header_attributes[key])
                print("visualised ipv6")
            if key == "tcp":
                self.view_header_diagram(key, packet_header_attributes[key])
                print("visualised tcp")
            if key == "udp":
                self.view_header_diagram(key, packet_header_attributes[key])
                print("visualised udp")
            if key == "icmp4":
                self.view_header_diagram(key, packet_header_attributes[key])
                print("visualised icmpv4")
            if key == "icmp6":
                self.view_header_diagram(key, packet_header_attributes[key])
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
            else:
                diagram = header_diagram("./ipv6-packet-header-without-extensions.png", header_type, field_values)
            self.header_window.add_diagram_label(diagram.get_diagram_label(), "IPv6")
            verbose_label = diagram.get_verbose_label()
            if verbose_label != None:
                self.header_window.add_verbose_label(verbose_label)
        if header_type == "udp":
            diagram = header_diagram("./udp-header.png", header_type, field_values)
            self.header_window.add_diagram_label(diagram.get_diagram_label(), "UDP")
            verbose_label = diagram.get_verbose_label()
            if verbose_label != None:
                self.header_window.add_verbose_label(verbose_label)
        if header_type == "tcp":
            diagram = header_diagram("./tcp-header.png", header_type, field_values)
            self.header_window.add_diagram_label(diagram.get_diagram_label(), "TCP")
            verbose_label = diagram.get_verbose_label()
            if verbose_label != None:
                self.header_window.add_verbose_label(verbose_label)
        if header_type == "icmp4":
            diagram = header_diagram("./icmp-header.png", header_type, field_values)
            self.header_window.add_diagram_label(diagram.get_diagram_label(), "ICMPv4")
            verbose_label = diagram.get_verbose_label()
            if verbose_label != None:
                self.header_window.add_verbose_label(verbose_label)
            if "ip4header" in field_values.keys():
                icmp_verbose = ""
                icmp_ip4header = field_values["ip4header"]
                if icmp_ip4header:
                    icmp_ip4header_parsed = parser.packet(0,0,0,icmp_ip4header).get_header(icmp_ip4header,0,headers.ip4header)
                    if "datagrambytes" in field_values.keys():
                        icmp_datagrambytes = field_values["datagrambytes"]
                        if icmp_datagrambytes:
                            icmp_datagrambytes_hex = (icmp_datagrambytes).hex()
                            icmp_verbose += f"ICMP error thrown from IPv4 packet with datagram [first 64 bits]: {icmp_datagrambytes_hex}\n"
                            if (icmp_ip4header_parsed.srcaddrb, icmp_ip4header_parsed.dstaddrb, icmp_datagrambytes_hex) in self.inv_ip4_datagrambytes:
                                try:
                                    icmp_verbose = f"ICMP error thrown from packet {self.inv_ip4_datagrambytes[(icmp_ip4header_parsed.srcaddrb, icmp_ip4header_parsed.dstaddrb, icmp_datagrambytes_hex)]}\n"
                                except:
                                    icmp_verbose = f"ICMP error thrown from unknown IPv4 packet (may not be in this PCAP) with:\n\tsource IP: {icmp_ip4header_parsed.srcaddrb}\n\tdestination IP: {icmp_ip4header_parsed.dstaddrb}\n\tdatagram [first 64 bits]: {icmp_datagrambytes_hex}\n"         
                            else:
                                icmp_verbose = f"ICMP error thrown from unknown IPv4 packet (may not be in this PCAP) with:\n\tsource IP: {icmp_ip4header_parsed.srcaddrb}\n\tdestination IP: {icmp_ip4header_parsed.dstaddrb}\n\tdatagram [first 64 bits]: {icmp_datagrambytes_hex}\n"       
                        else:
                            icmp_verbose = f"ICMP error thrown from unknown IPv4 packet (may not be in this PCAP) with:\n\tsource IP: {icmp_ip4header_parsed.srcaddrb}\n\tdestination IP: {icmp_ip4header_parsed.dstaddrb}\n"
                    else:
                        icmp_verbose = f"ICMP error thrown from unknown IPv4 packet (may not be in this PCAP) with:\n\tsource IP: {icmp_ip4header_parsed.srcaddrb}\n\tdestination IP: {icmp_ip4header_parsed.dstaddrb}\n"
                else:
                    icmp_verbose = f"ICMP error thrown from an unidentifiable IPv4 packet\n"
            else:
                icmp_verbose = f"ICMP error thrown from an unidentifiable IPv4 packet\n"
            self.header_window.add_verbose_label(icmp_verbose)            

        if header_type == "icmp6":
            diagram = header_diagram("./icmp-header.png", header_type, field_values)
            self.header_window.add_diagram_label(diagram.get_diagram_label(), "ICMPv6")
            verbose_label = diagram.get_verbose_label()
            if verbose_label != None:
                self.header_window.add_verbose_label(verbose_label)

app = QApplication(sys.argv)

window = MainWindow()
window.resize(1000,500)
window.show()

app.exec()
