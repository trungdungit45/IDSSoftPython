import struct

class frameHeader:
    def __init__(self):
        self.ipsourc  = str()
        self.ipdesti = str()
        self.time = str()
        self.count = int()
