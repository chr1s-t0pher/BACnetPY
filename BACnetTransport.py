#MIT License
#
#Copyright (c) 2020 chr1s-t0pher
#
#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.


from BACnetBase import *
import asyncio
import logging, sys
import socket
from events import Events
from netifaces import interfaces, ifaddresses, AF_INET


logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)

class UDPIPProtocol:

    def __init__(self, local_endpoint : str = "192.168.0.44", port : int = 47808):
        self.port = port
        self.loop = asyncio.get_event_loop()
        self.type = None
        self.headerlength :int = BVLC.BVLC_HEADER_LENGTH
        self.maxbufferlength = None
        self.maxadpulength : BacnetMaxAdpu = BacnetMaxAdpu(BacnetMaxAdpu.MAX_APDU1024)
        self.MaxInfoFrames = None
        self._m_exclusive_port = True
        self._m_dont_fragment = False
        self._m_local_endpoint = local_endpoint
        self.events = Events()
        self.transport = None

    def connection_made(self, transport):
        print('started')
        self.transport = transport
        sock = transport.get_extra_info("socket")
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        #self.broadcast()

    def datagram_received(self, data, addr):
        logging.info('data received:'+str(data) + str(addr))
        asyncio.ensure_future(self.OnReceiveData(data, addr))

    async def OnReceiveData(self, datagram, address):
        rx = 0
        rx = len(datagram)
        BVLC.BVLC_HEADER_LENGTH


        if rx < BVLC.BVLC_HEADER_LENGTH or rx == 0:
            print("garbage")
        else:
            (HEADER_LENGTH, function, msg_length) = BVLC.Decode(datagram, 0)
            if HEADER_LENGTH != -1:
                if function == BacnetBvlcFunctions.BVLC_RESULT:
                    print("Receive Register as Foreign Device Response")
                if function == BacnetBvlcFunctions.BVLC_FORWARDED_NPDU:
                    print("BVLC_FORWARDED_NPDU do something!!")
                if function == BacnetBvlcFunctions.BVLC_ORIGINAL_UNICAST_NPDU or function == BacnetBvlcFunctions.BVLC_ORIGINAL_BROADCAST_NPDU or function == BacnetBvlcFunctions.BVLC_FORWARDED_NPDU:

                    self.events.on_MessageRecieved(self, datagram, HEADER_LENGTH, rx - HEADER_LENGTH, address)



    def send(self, buffer, offset, data_length, address : BACnetAddress, wait_for_transmission, timeout):
        full_length = data_length + self.headerlength

        function = BacnetBvlcFunctions.BVLC_ORIGINAL_UNICAST_NPDU

        if address.network_number == 0xFFFF:
            function = BacnetBvlcFunctions.BVLC_ORIGINAL_BROADCAST_NPDU


        buffer =  BVLC.encode(offset - BVLC.BVLC_HEADER_LENGTH, function , full_length) + buffer

        self.transport.sendto(buffer, (address.IP_and_port()))



    def getbroadcastaddress(self) -> BACnetAddress:
        broadcast = "255.255.255.255"
        for ifaceName in interfaces():
            addrs = ifaddresses(ifaceName).get(2)
            if(addrs != None):
                ip_address = addrs[0].get('addr')
                if ip_address == self._m_local_endpoint:
                    broadcast = addrs[0].get('broadcast')

        return BACnetAddress(net_type=BACnetNetworkType.IPV4, network_number=0xFFFF, address=broadcast + ":" + str(self.port))


    def WaitForAllTransmits(self, timeout):
        pass

    def start(self):
        coro = self.loop.create_datagram_endpoint(lambda: self, local_addr=(self._m_local_endpoint, self.port))
        self.loop.run_until_complete(coro)
        self.loop.run_forever()
        self.loop.close()
