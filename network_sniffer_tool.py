import socket
import struct
import textwrap

def ipv4(addr):
    return '.'.join(map(str, addr))

def format_multi_line(prefix, string, size=16):
    return '\n'.join([prefix + ' '.join(f'\\x{byte:02x}' for byte in string[i:i+size]) for i in range(0, len(string), size)])

def main():
    # Windows: raw socket on local IP (change if needed)
    host = socket.gethostbyname(socket.gethostname())
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    conn.bind((host, 0))
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    while True:
        raw_data, addr = conn.recvfrom(65535)

        # Unpack IP header
        version_header_length = raw_data[0]
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
        src_ip = socket.inet_ntoa(src)
        dest_ip = socket.inet_ntoa(target)

        print("\nIPv4 Packet:")
        print(f"  - Version: 4, Header Length: {header_length}, TTL: {ttl}")
        print(f"  - Protocol: {proto}, Source: {src_ip}, Target: {dest_ip}")

        if proto == 6:  # TCP
            tcp_header = raw_data[header_length:header_length+20]
            src_port, dest_port, seq, ack, offset_reserved_flags = struct.unpack('!HHLLH', tcp_header[:14])
            offset = (offset_reserved_flags >> 12) * 4
            flags = {
                'URG': (offset_reserved_flags & 32) >> 5,
                'ACK': (offset_reserved_flags & 16) >> 4,
                'PSH': (offset_reserved_flags & 8) >> 3,
                'RST': (offset_reserved_flags & 4) >> 2,
                'SYN': (offset_reserved_flags & 2) >> 1,
                'FIN': offset_reserved_flags & 1,
            }

            print("  - TCP Segment:")
            print(f"    - Source Port: {src_port}, Destination Port: {dest_port}")
            print(f"    - Sequence: {seq}, Acknowledgment: {ack}")
            print("    - Flags:")
            for k, v in flags.items():
                print(f"      {k}: {v}")

            payload = raw_data[header_length+offset:]
            print("  - Data:")
            print(format_multi_line("    ", payload))

main()
