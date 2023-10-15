from socket import *
from pkt_sender import pkt_sender
fd = open('info.txt', 'r')
Lines = fd.readlines()
def header_checksum(header, size):
    cksum = 0
    pointer = 0

    # The main loop adds up each set of 2 bytes. They are first converted to strings and then concatenated
    # together, converted to integers, and then added to the sum.
    while size > 1:
        cksum += int((str("%02x" % (header[pointer],)) +
                      str("%02x" % (header[pointer + 1],))), 16)
        size -= 2
        pointer += 2
    if size:  # This accounts for a situation where the header is odd
        cksum += header[pointer]

    cksum = (cksum >> 16) + (cksum & 0xffff)
    cksum += (cksum >> 16)

    return (~cksum) & 0xFFFF

def cs(data):
    data = data.split()
    data = [int(item,16) for item in data]
    return  "%04x" % (header_checksum(data, len(data)),)


dest_mac = Lines[6][:17] #destination mac
src_mac = Lines[5][:17] #source mac
proto3 = "0800" #layer 3 protocol number
ver = "45" #version, header length
diff = "00" #diffserv
t_len = "0028" #total length ("00 28" for 40 bytes,"00 3c" for 60 bytes)
id = "07c3" #id
flags = "4000" #flags
ttl = "40" #ttl
proto4 = "06" #layer 4 protocol number
cs3 ="0000" #io check sum
src_ip = inet_aton(Lines[2]).hex() #source ip
dest_ip = inet_aton(Lines[0]).hex() #dest io
src_port = "%04x" %int(Lines[3]) #src port
dest_port ="%04x" %int(Lines[1]) #dest port
seq_num ="174930d1" #seq number
ack ="00000000" #ack number
h_len = "5002" #tcp header length and flags ("a0 02" for 40 bytes, "50 02" for 20 bytes)
W_size ="7210" #window size
cs4 = "0000"#tcp check sum
up = "0000"  #urgent pointer
interface0 = Lines[4].strip()

pseudo_header = src_ip + dest_ip + '00' + proto4 + '0014'
tcp_cs = (pseudo_header + src_port + dest_port + seq_num + ack + h_len + W_size + "00 00" + up).replace(' ', '')
tcp_cs = ' '.join(tcp_cs[i:i+2] for i in range(0, len(tcp_cs), 2))
checksum3 = cs(tcp_cs)
tcp_segment = src_port + dest_port + seq_num + ack + h_len + W_size + checksum3 + up

ip_cs = (ver + diff + t_len + id + flags + ttl + proto4 + "00 00" + str(src_ip) + str(dest_ip)).replace(' ', '')
ip_cs = ' '.join(ip_cs[i:i+2] for i in range(0, len(ip_cs), 2))
checksum4 = cs(ip_cs)
ip_datagram = ver + diff + t_len + id + flags + ttl + proto4 + checksum4 + str(src_ip) + str(dest_ip) + tcp_segment
print(len(tcp_segment))

eth_frame = (dest_mac + src_mac + proto3 + ip_datagram).replace(' ', '')

print(pkt_sender(eth_frame, interface0))