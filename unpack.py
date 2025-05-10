import struct
import socket


# Unpack Ethernet Frame
def ethernet_frame(data):
    # The ethernet frame takes the first 14 bytes of the packet.
    destnation_mac, source_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addresses(destnation_mac), get_mac_addresses(source_mac), socket.htons(protocol), data[14:]

# Unpack the IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4 # Bitwise Operation
    header_length = (version_header_length & 15) * 4 # Bitwise Operation
    ttl, protocol, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, protocol, get_ipv4_addresses(src), get_ipv4_addresses(target), data[header_length:]

def unpack_TCP_segment(data):
# Unpacks TCP segment
    (source_port, destnation_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])

    # Bitwise Operations.
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return source_port, destnation_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def unpack_UDP_segment(data):
    src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, length, data[8:]

def unpack_icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Returns properly formatted MAC addressesess (ie AA:BB:CC:DD:EE:FF)
def get_mac_addresses(bytes_addresses):
    bytes_str = map('{:02x}'.format, bytes_addresses)
    return ':'.join(bytes_str).upper()


# Returns properly formatted IPv4 addressesess
def get_ipv4_addresses(addresses):
    return '.'.join(map(str, addresses))