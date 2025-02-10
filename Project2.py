import socket
import struct

def ethernet_frame(data):
    """Unpacks Ethernet frame."""
    dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(eth_proto), data[14:]

def get_mac_addr(bytes_addr):
    """Converts MAC address to readable format."""
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()

def ipv4_packet(data):
    """Unpacks IPv4 packet."""
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    """Converts IPv4 address to readable format."""
    return '.'.join(map(str, addr))

def tcp_segment(data):
    """Unpacks TCP segment."""
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = {
        'URG': (offset_reserved_flags & 32) >> 5,
        'ACK': (offset_reserved_flags & 16) >> 4,
        'PSH': (offset_reserved_flags & 8) >> 3,
        'RST': (offset_reserved_flags & 4) >> 2,
        'SYN': (offset_reserved_flags & 2) >> 1,
        'FIN': offset_reserved_flags & 1,
    }
    return src_port, dest_port, sequence, acknowledgment, flags, data[offset:]

def udp_segment(data):
    """Unpacks UDP segment."""
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def main():
    # Create raw socket for capturing packets
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    while True:
        raw_data, _ = conn.recvfrom(65535)
        
        # Parse Ethernet frame
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(f'  Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')
        
        # Check if IPv4 packet
        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            print('  IPv4 Packet:')
            print(f'    Version: {version}, Header Length: {header_length}, TTL: {ttl}')
            print(f'    Protocol: {proto}, Source: {src}, Target: {target}')
            
            # Check for TCP
            if proto == 6:
                src_port, dest_port, sequence, acknowledgment, flags, data = tcp_segment(data)
                print('    TCP Segment:')
                print(f'      Source Port: {src_port}, Destination Port: {dest_port}')
                print(f'      Sequence: {sequence}, Acknowledgment: {acknowledgment}')
                print(f'      Flags: {flags}')
            
            # Check for UDP
            elif proto == 17:
                src_port, dest_port, size, data = udp_segment(data)
                print('    UDP Segment:')
                print(f'      Source Port: {src_port}, Destination Port: {dest_port}, Length: {size}')
            
            # Other protocols
            else:
                print(f'    Other Protocol: {proto}')

if __name__ == "__main__":
    main()

