import datetime
from Struct.frameheader import frameHeader

# create an array of structs with _n members
def searchforframe(_frameHeader, ipsource, ipdesti):
    for i in range(0,len(_frameHeader)):
        if(_frameHeader[i].ipsourc ==ipsource and _frameHeader[i].ipdesti ==ipdesti):
            return i
    return -1

def AddtoFrame(_frameHeader, ipsource, ipdesti, count):
    #print(searchforframe(_frameHeader, ipsource, ipdesti), len(_frameHeader))
    if (searchforframe(_frameHeader, ipsource, ipdesti ) == -1):
        #print("Them moi vao")
        Frame = frameHeader()
        Frame.ipsourc = ipsource
        Frame.ipdesti = ipdesti
        Frame.time = datetime.datetime.now().strftime("%H%M%S")
        Frame.count = count
        _frameHeader.append(Frame)
    else:
        #print("Chinh sua moi vao")
        _frameHeader[searchforframe(_frameHeader, ipsource, ipdesti)].count += 1
        #print(searchforframe(_frameHeader,"192.168.10.2","192.168.10.2"))
def main():

    _listFrameEth = []
    AddtoFrame(_listFrameEth,"192.168.10.1", "192.168.10.1", 1)
    AddtoFrame(_listFrameEth,"192.168.10.1", "192.168.10.1", 1)
    AddtoFrame(_listFrameEth,"192.168.10.1", "192.168.10.2", 1)
    AddtoFrame(_listFrameEth,"192.168.10.1", "192.168.10.3", 1)
    for i in range(0, len(_listFrameEth)):
        print(_listFrameEth[i].ipsourc,_listFrameEth[i].ipdesti, _listFrameEth[i].count,_listFrameEth[i].time)

main()