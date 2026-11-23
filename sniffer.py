import sys
from scapy.all import sniff, IP, TCP, conf
from modules.ids import Detector

detector = Detector()


def process(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        flags = int(packet[TCP].flags)
        is_syn = (flags & 0x02) != 0 and (flags & 0x10) == 0
        detector.handle_packet(packet[IP].src, packet[TCP].dport, is_syn)


if __name__ == "__main__":
    iface = None
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg.isdigit():
            iface = conf.ifaces.dev_from_index(int(arg))
        else:
            iface = arg
    print("IDS sniffer started on:", iface if iface else "default adapter")
    print("Press Ctrl+C to stop.")
    sniff(iface=iface, prn=process, store=False)