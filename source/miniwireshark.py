from socket import *
from struct import *


def ether(data):
    dest_mac, src_mac, proto = unpack('! 6s 6s 2s', data[:14])
    dest_mac = dest_mac.hex()
    src_mac = src_mac.hex()
    return[dest_mac,src_mac, proto.hex(), data[14:]]


def ip(data):
  maindata = data
  data=unpack('! B s H 2s 2s B B 2s 4s 4s', data[:20])
  return[data[0]>>4, #version
  (data[0]&(0x0F) )*4, #header length
   data[1].hex(), #Diffserv
   data[2], #total length
   data[3].hex(), #ID
   "Ox"+data[4].hex(), #flags
   data[5], #ttl
   data[6], #protocol
   data[7].hex(), #check sum
   inet_ntoa(data[8]), #source ip
   inet_ntoa(data[9]), #destination ip
   maindata[(data[0]&(0x0F))*4:]
          ] #ip payload


def tcp(data):
    tcp_hdr = unpack("! H H I I H H 2s 2s", data[:20])
    src_port = tcp_hdr[0]
    dst_port = tcp_hdr[1]
    seq_num = tcp_hdr[2]
    ack_num = tcp_hdr[3]
    data_offset = tcp_hdr[4] >> 12
    flags = tcp_hdr[4] & 0xfff
    window = tcp_hdr[5]
    checksum = tcp_hdr[6].hex()
    urg_ptr = tcp_hdr[7].hex()

    return [
        tcp_hdr,
        src_port,
        dst_port,
        seq_num,
        ack_num,
        data_offset,
        flags,
        window,
        checksum,
        urg_ptr,
    ]


conn = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003))

while True:
    raw_data, add = conn.recvfrom(65535)

    ether_shark = ether(raw_data)
    #if(ether_shark[2] == 0x800):
    ip_shark=ip(ether_shark[3])
    if(ip_shark[7] == 6):
        tcp_shark = tcp(ip_shark[11])
        if(tcp_shark[6] & 0b0010010 == 0b0010010):
            print(str(tcp_shark[1]) + " is open on " + str(ip_shark[9]))


