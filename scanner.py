from scapy.all import ARP, Ether, srp

def scan_network(ip_range):
    # Create an ARP request packet
    arp_request = ARP(pdst=ip_range)
    # Create an Ethernet frame to encapsulate the ARP request
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    # Combine the Ethernet frame and ARP request
    packet = ether_frame / arp_request

    # Send the packet and capture the response
    result = srp(packet, timeout=3, verbose=0)[0]

    # Process the response to extract IP and MAC addresses
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

if __name__ == "__main__":
    ip_range = "192.168.1.1/24"  # Define the IP range to scan
    scanned_devices = scan_network(ip_range)
    print("Available devices in the network:")
    for device in scanned_devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")
