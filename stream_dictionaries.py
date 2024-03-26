class connections():
    def __init__(self):
        self.TLS_CONNECTIONDICT = {} ##maybe not possible
        self.TCP_CONNECTIONDICT = {} #done
        self.UDP_CONNECTIONDICT = {} #done
        self.QUIC_CONNECTIONDICT = {} ##maybe not possible
        self.DNS_CONNECTIONDICT = {} #maybe not possible
        self.IPV4_CONNECTIONDICT = {} #done
        self.ICMP_V4_CONNECTIONDICT = {} #done
        self.IPV6_CONNECTIONDICT = {} #done
        self.ICMP_V6_CONNECTIONDICT = {} #done
        self.ARP_CONNECTIONDICT = {} #done
        self.ETHERNET_CONNECTIONDICT = {} #done
    
    def get_connections(self):
        return [("TCP", self.TCP_CONNECTIONDICT),
                ("UDP", self.UDP_CONNECTIONDICT),
                ("IP4", self.IPV4_CONNECTIONDICT),
                ("ICMP4", self.ICMP_V4_CONNECTIONDICT),
                ("IP6", self.IPV6_CONNECTIONDICT),
                ("ICMP6", self.ICMP_V6_CONNECTIONDICT),
                ("ARP", self.ARP_CONNECTIONDICT),
                ("ETHERNET", self.ETHERNET_CONNECTIONDICT)]