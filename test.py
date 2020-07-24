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

from BACnetClient import *
from BACnetTransport import UDPIPProtocol

def recieved_WHOIS(sender : BacnetClient, adr : BACnetAddress, rq : WhoIs_Request):
    test_deviceid = 1001
    if (rq.deviceInstanceRangeLowLimit != None and rq.deviceInstanceRangeHighLimit != None and test_deviceid >= rq.deviceInstanceRangeLowLimit  and test_deviceid <= rq.deviceInstanceRangeHighLimit) or (rq.deviceInstanceRangeLowLimit == None and rq.deviceInstanceRangeHighLimit == None):
        sender.UnconfirmedIam(IAm_Request(BACnetObjectIdentifier(BACnetObjectType.Device, test_deviceid), 20, BACnetSegmentation.NO_SEGMENTATION, 250))


def recieved_IAM(sender : BacnetClient, adr : BACnetAddress, rq : IAm_Request):
    print("recieved IAM")
    sender.ReadPropertyRequest(
        BACnetAddress(address="1.0.0.0:0", net_type=BACnetNetworkType.IPV4, network_number=20),
        ReadProperty_Request(BACnetObjectIdentifier(BACnetObjectType.Analog_Input, 0),
                             BACnetPropertyIdentifier.PRESENT_VALUE))


def recieved_WhoHas(sender : BacnetClient, adr : BACnetAddress, rq : WhoHas_Request):
    print("recieved_WhoHas")

def recieved_COVNotification(sender : BacnetClient, adr : BACnetAddress, rq : COVNotification_Request, confirmed : bool):
    if confirmed == True:
        print("Confirmed COVNotification")
    else:
        print("Confirmed COVNotification")

def recieved_OnTimeSynchronize(sender : BacnetClient, adr : BACnetAddress, rq : TimeSynchronization_Request):
    print("recieved_OnTimeSynchronize")

def recieved_OnEventNotify(sender : BacnetClient, adr : BACnetAddress, rq : EventNotification_Request, confirmed : bool):
    if confirmed == True:
        print("Confirmed EventNotification")
    else:
        print("Confirmed EventNotification")

def recieved_IHave(sender : BacnetClient, adr : BACnetAddress, rq : IHave_Request):
    print("recieved_IHave")

def recieved_OnTextMessage(sender : BacnetClient, adr : BACnetAddress, rq : TextMessage_Request):
    print("recieved_OnTextMessage")

def recieved_OnReadProperty(sender : BacnetClient, adr : BACnetAddress, rq : ReadProperty_Request):
    print("recieved_OnReadProperty")

def recieved_OnWriteProperty(sender : BacnetClient, adr : BACnetAddress, rq : WriteProperty_Request):
    print("recieved_OnWriteProperty")

def recieved_OnReadPropertyMultiple(sender : BacnetClient, adr : BACnetAddress, rq : ReadPropertyMultiple_Request):
    print("recieved_OnReadPropertyMultiple")

def recieved_OnWritePropertyMultiple(sender : BacnetClient, adr : BACnetAddress, rq : WritePropertyMultiple_Request):
    print("recieved_OnWritePropertyMultiple")

def recieved_OnAtomicReadFile(sender : BacnetClient, adr : BACnetAddress, rq : AtomicReadFile_Request):
    print("recieved_OnAtomicReadFile")
    if type(rq.accessmethod) == AtomicReadFile_Request.recordaccess:
        print("recordaccess")
    elif type(rq.accessmethod) == AtomicReadFile_Request.streamaccess:
        print("streamaccess")

def recieved_OnAtomicWriteFile(sender : BacnetClient, adr : BACnetAddress, rq : AtomicReadFile_Request):
    print("recieved_OnAtomicWriteFile")
    if type(rq.accessmethod) == AtomicWriteFile_Request.recordaccess:
        print("recordaccess")
    elif type(rq.accessmethod) == AtomicWriteFile_Request.streamaccess:
        print("streamaccess")

def recieved_OnSubscribeCOV(sender : BacnetClient, adr : BACnetAddress, rq : SubscribeCOV_Request):
    print("recieved_OnSubscribeCOV")

def recieved_OnSubscribeCOVProperty(sender : BacnetClient, adr : BACnetAddress, rq : SubscribeCOVProperty_Request):
    print("recieved_OnSubscribeCOVProperty")

def recieved_OnCreateObject(sender : BacnetClient, adr : BACnetAddress, rq : CreateObject_Request):
    print("recieved_OnCreateObject")

def recieved_OnDeleteObject(sender : BacnetClient, adr : BACnetAddress, rq : DeleteObject_Request):
    print("recieved_OnDeleteObject")

def recieved_OnReadRange(sender : BacnetClient, adr : BACnetAddress, rq : ReadRange_Request):
    print("recieved_OnReadRange")

def recieved_OnDeviceCommunicationControl(sender : BacnetClient, adr : BACnetAddress, rq : DeviceCommunicationControl_Request):
    print("recieved_OnDeviceCommunicationControl")

def recieved_OnReinitializeDevice(sender : BacnetClient, adr : BACnetAddress, rq : ReinitializeDevice_Request):
    print("recieved_OnReinitializeDevice")

def recieved_OnAddListElement(sender : BacnetClient, adr : BACnetAddress, rq : AddListElement_Request):
    print("recieved_OnAddListElement")

bc = BacnetClient(UDPIPProtocol("192.168.0.46", 47808), 1000, 3)
bc.events.OnWhoIs += recieved_WHOIS
bc.events.OnIam += recieved_IAM
bc.events.OnWhoHas += recieved_WhoHas
bc.events.OnCOVNotification += recieved_COVNotification
bc.events.OnTimeSynchronize += recieved_OnTimeSynchronize
bc.events.OnEventNotify += recieved_OnEventNotify
bc.events.OnIHave += recieved_IHave
bc.events.OnTextMessage += recieved_OnTextMessage
bc.events.OnReadProperty += recieved_OnReadProperty
bc.events.OnWriteProperty += recieved_OnWriteProperty
bc.events.OnReadPropertyMultiple += recieved_OnReadPropertyMultiple
bc.events.OnWritePropertyMultiple += recieved_OnWritePropertyMultiple
bc.events.OnAtomicReadFile += recieved_OnAtomicReadFile
bc.events.OnAtomicWriteFile += recieved_OnAtomicWriteFile
bc.events.OnSubscribeCOV += recieved_OnSubscribeCOV
bc.events.OnSubscribeCOVProperty += recieved_OnSubscribeCOVProperty
bc.events.OnCreateObject += recieved_OnCreateObject
bc.events.OnDeleteObject += recieved_OnDeleteObject
bc.events.OnReadRange += recieved_OnReadRange
bc.events.OnDeviceCommunicationControl += recieved_OnDeviceCommunicationControl
bc.events.OnReinitializeDevice += recieved_OnReinitializeDevice
bc.events.OnAddListElement += recieved_OnAddListElement
bc.start()
