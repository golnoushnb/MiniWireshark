from socket import *
from binascii import unhexlify

def pkt_sender(message, interface):
  s = socket(AF_PACKET, SOCK_RAW)
  s.bind((interface, 0))
  pkt = unhexlify((message))
  byteNum = s.send(pkt)
  return ("sent " + str(byteNum) + "-bytes packets on " + interface)

if __name__ == "__main__":
    message = input("what is your packet content?")
    interface = input("which interface do you want to use?")
    print(pkt_sender(message, interface))