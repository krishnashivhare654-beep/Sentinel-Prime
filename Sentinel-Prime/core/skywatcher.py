from scapy.all import sniff, IP, TCP, UDP
import datetime

def packet_callback(packet):
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "Other"
        
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')
        
        # Displaying on Terminal for now
        print(f"[{timestamp}] {proto} | {ip_src} --> {ip_dst}")

def start_sniffing(interface=None):
    print(f"[*] SkyWatcher Engine Active... Monitoring Traffic.")
    # sniff() will capture packets and send them to packet_callback
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    # Note: Running this might require Admin/Sudo privileges
    start_sniffing()