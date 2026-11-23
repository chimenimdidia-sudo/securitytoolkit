import time
from modules.db import init_db, add_alert

PORT_SCAN_LIMIT = 15
SCAN_WINDOW = 10
SYN_FLOOD_LIMIT = 100
FLOOD_WINDOW = 5
ALERT_COOLDOWN = 30


class Detector:
    def __init__(self):
        self.ports_seen = {}
        self.syn_seen = {}
        self.last_alert = {}

    def handle_packet(self, src_ip, dst_port, is_syn, now=None):
        if now is None:
            now = time.time()
        if is_syn:
            self.check_port_scan(src_ip, dst_port, now)
            self.check_syn_flood(src_ip, now)

    def check_port_scan(self, src_ip, dst_port, now):
        entries = self.ports_seen.setdefault(src_ip, [])
        entries.append((now, dst_port))
        entries[:] = [(t, p) for (t, p) in entries if now - t <= SCAN_WINDOW]
        distinct_ports = {p for (t, p) in entries}
        if len(distinct_ports) >= PORT_SCAN_LIMIT:
            message = (src_ip + " contacted " + str(len(distinct_ports)) +
                       " different ports within " + str(SCAN_WINDOW) +
                       " seconds (possible port scan)")
            self.raise_alert(src_ip, "port scan", "high", message, now)

    def check_syn_flood(self, src_ip, now):
        times = self.syn_seen.setdefault(src_ip, [])
        times.append(now)
        times[:] = [t for t in times if now - t <= FLOOD_WINDOW]
        if len(times) >= SYN_FLOOD_LIMIT:
            message = (src_ip + " sent " + str(len(times)) +
                       " connection requests within " + str(FLOOD_WINDOW) +
                       " seconds (possible SYN flood)")
            self.raise_alert(src_ip, "syn flood", "high", message, now)

    def raise_alert(self, src_ip, kind, severity, message, now):
        last = self.last_alert.get((src_ip, kind), 0)
        if now - last < ALERT_COOLDOWN:
            return
        self.last_alert[(src_ip, kind)] = now
        add_alert("IDS", severity, message)


def simulate():
    init_db()
    detector = Detector()
    start = time.time()

    for i in range(30):
        detector.handle_packet("10.0.0.5", 20 + i, True, now=start + i * 0.1)

    for i in range(300):
        detector.handle_packet("10.0.0.9", 80, True, now=start + 5 + i * 0.007)


if __name__ == "__main__":
    simulate()
    print("Simulated attacks sent. Open 127.0.0.1:5000/alerts to see them.")