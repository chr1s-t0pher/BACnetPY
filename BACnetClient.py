# MIT License
#
# Copyright (c) 2020 chr1s-t0pher
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import asyncio

from BACnetBase import *
from BACnetRequest import *
import logging, sys
from events import Events
from BACnetTransport import UDPIPProtocol


# todo needs to be fixed, experimental!
logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)



class BacnetClient:
    def __init__(self, transport : UDPIPProtocol = None, timeout = 1000, retries = 3):
        self.transport = transport
        self.timeout = timeout
        self.transmit_timeout = 3000
        self.retries = retries
        self._m_invoke_id = 0
        self.max_segments = BacnetMaxSegments(BacnetMaxSegments.MAX_SEG0)
        self._m_last_sequence_number = 0
        self.proposed_window_size = 10
        self.default_segmentation_handling = True
        #self LatSegmentACK
        self.force_window_size = False
        self.writepriority = 0
        self.raw_buffer = None
        self.raw_offset = None
        self.raw_length = None
        self.loop = None
        self.events = Events()


    def OnRecieve(self, sender, buffer, offset, msg_length, remote_address):
        leng = 0
        if msg_length > 0:
            npdu = NPDU()
            leng += npdu.decode(buffer, offset+leng)

            if npdu.control.network_layer_message:
                print("Network Layer message received")
                return


            if leng > 0:
                if msg_length > 0:
                    self.ProcessApdu(remote_address, buffer, offset+leng, msg_length-leng)

    def ProcessConfirmedServiceRequest(self, adr, apdu, max_segments, max_apdu, invoke_id, buffer, offset,
                                       length):

        if apdu.service_choice == BACnetConfirmedServiceChoice.READ_PROPERTY and self.events.OnReadProperty:
            rq = ReadProperty_Request()
            leng = ReadProperty_Request.ASN1decode(rq, buffer, offset, length)
            if leng >= 0:
                logging.info(
                    "\n--------------------------- BACnetConfirmedServiceChoice.READ_PROPERTY ---------------------------")
                logging.info(rq)
                logging.info(
                    "\n-------------------------------------------------------------------------------------------")
                self.events.OnReadProperty(self, adr, rq)
            else:
                logging.debug("Couldn't decode BACnetConfirmedServiceChoice.READ_PROPERTY")
        elif apdu.service_choice == BACnetConfirmedServiceChoice.WRITE_PROPERTY and self.events.OnWriteProperty:
            rq = WriteProperty_Request()
            leng = WriteProperty_Request.ASN1decode(rq, buffer, offset, length)
            if leng >= 0:
                logging.info(
                    "\n--------------------------- BACnetConfirmedServiceChoice.WRITE_PROPERTY ---------------------------")
                logging.info(rq)
                logging.info(
                    "\n-------------------------------------------------------------------------------------------")
                self.events.OnWriteProperty(self, adr, rq)
            else:
                logging.debug("Couldn't decode BACnetConfirmedServiceChoice.WRITE_PROPERTY")
        elif apdu.service_choice == BACnetConfirmedServiceChoice.READ_PROPERTY_MULTIPLE and self.events.OnReadPropertyMultiple:
            rq = ReadPropertyMultiple_Request()
            leng = ReadPropertyMultiple_Request.ASN1decode(rq, buffer, offset, length)
            if leng >= 0:
                logging.info(
                    "\n--------------------------- BACnetConfirmedServiceChoice.READ_PROPERTY_MULTIPLE ---------------------------")
                logging.info(rq)
                logging.info(
                    "\n-------------------------------------------------------------------------------------------")
                self.events.OnReadPropertyMultiple(self, adr, rq)
            else:
                logging.debug("Couldn't decode BACnetConfirmedServiceChoice.READ_PROPERTY_MULTIPLE")
        elif apdu.service_choice == BACnetConfirmedServiceChoice.WRITE_PROPERTY_MULTIPLE and self.events.OnWritePropertyMultiple:
            rq = WritePropertyMultiple_Request()
            leng = WritePropertyMultiple_Request.ASN1decode(rq, buffer, offset, length)
            if leng >= 0:
                logging.info(
                    "\n--------------------------- BACnetConfirmedServiceChoice.WRITE_PROPERTY_MULTIPLE "
                    "---------------------------")
                logging.info(rq)
                logging.info(
                    "\n-------------------------------------------------------------------------------------------")
                self.events.OnWritePropertyMultiple(self, adr, rq)
            else:
                logging.debug("Couldn't decode BACnetConfirmedServiceChoice.WRITE_PROPERTY_MULTIPLE")
        elif apdu.service_choice == BACnetConfirmedServiceChoice.CONFIRMED_COV_NOTIFICATION and self.events.OnCOVNotification:
            rq = COVNotification_Request()
            leng = COVNotification_Request.ASN1decode(rq, buffer, offset, length)
            if leng >= 0:
                logging.info(
                    "\n--------------------------- BACnetConfirmedServiceChoice.CONFIRMED_COV_NOTIFICATION "
                    "---------------------------")
                logging.info(rq)
                logging.info(
                    "\n"
                    "-----------------------------------------------------------------------------------------------------------")
                self.events.OnCOVNotification(self, adr, rq, True)
            else:
                logging.debug("Couldn't decode BACnetConfirmedServiceChoice.CONFIRMED_COV_NOTIFICATION")
        elif apdu.service_choice == BACnetConfirmedServiceChoice.ATOMIC_WRITE_FILE and self.events.OnAtomicWriteFile:
            rq = AtomicWriteFile_Request()
            leng = AtomicWriteFile_Request.ASN1decode(rq, buffer, offset, length)
            if leng >= 0:
                logging.info(
                    "\n--------------------------- BACnetConfirmedServiceChoice.ATOMIC_WRITE_FILE "
                    "---------------------------")
                logging.info(rq)
                logging.info(
                    "\n-----------------------------------------------------------------------------------------------------------")
                self.events.OnAtomicWriteFile(self, adr, rq)
            else:
                logging.debug("Couldn't decode BACnetConfirmedServiceChoice.ATOMIC_WRITE_FILE")
        elif apdu.service_choice == BACnetConfirmedServiceChoice.ATOMIC_READ_FILE and self.events.OnAtomicReadFile:
            rq = AtomicReadFile_Request()
            leng = AtomicReadFile_Request.ASN1decode(rq, buffer, offset, length)
            if leng >= 0:
                logging.info(
                    "\n--------------------------- BACnetConfirmedServiceChoice.ATOMIC_READ_FILE ---------------------------")
                logging.info(rq)
                logging.info(
                    "\n-----------------------------------------------------------------------------------------------------------")
                self.events.OnAtomicReadFile(self, adr, rq)
            else:
                logging.debug("Couldn't decode BACnetConfirmedServiceChoice.ATOMIC_READ_FILE")
        elif apdu.service_choice == BACnetConfirmedServiceChoice.SUBSCRIBE_COV and self.events.OnSubscribeCOV:
            rq = SubscribeCOV_Request()
            leng = SubscribeCOV_Request.ASN1decode(rq, buffer, offset, length)
            if leng >= 0:
                logging.info(
                    "\n--------------------------- BACnetConfirmedServiceChoice.SUBSCRIBE_COV ---------------------------")
                logging.info(rq)
                logging.info(
                    "\n-----------------------------------------------------------------------------------------------------------")
                self.events.OnSubscribeCOV(self, adr, rq)
            else:
                logging.debug("Couldn't decode BACnetConfirmedServiceChoice.SUBSCRIBE_COV")
        elif apdu.service_choice == BACnetConfirmedServiceChoice.SUBSCRIBE_COV_PROPERTY and self.events.OnSubscribeCOVProperty:
            rq = SubscribeCOVProperty_Request()
            leng = SubscribeCOVProperty_Request.ASN1decode(rq, buffer, offset, length)
            if leng >= 0:
                logging.info(
                    "\n--------------------------- BACnetConfirmedServiceChoice.SUBSCRIBE_COV_PROPERTY ---------------------------")
                logging.info(rq)
                logging.info(
                    "\n-----------------------------------------------------------------------------------------------------------")
                self.events.OnSubscribeCOVProperty(self, adr, rq)
            else:
                logging.debug("Couldn't decode BACnetConfirmedServiceChoice.SUBSCRIBE_COV_PROPERTY")
        elif apdu.service_choice == BACnetConfirmedServiceChoice.DEVICE_COMMUNICATION_CONTROL and self.events.OnDeviceCommunicationControl:
            rq = DeviceCommunicationControl_Request()
            leng = DeviceCommunicationControl_Request.ASN1decode(rq, buffer, offset, length)
            if leng >= 0:
                logging.info(
                    "\n--------------------------- BACnetConfirmedServiceChoice.REINITIALIZE_DEVICE ---------------------------")
                logging.info(rq)
                logging.info(
                    "\n-----------------------------------------------------------------------------------------------------------")
                self.events.OnDeviceCommunicationControl(self, adr, rq)
            else:
                logging.debug("Couldn't decode BACnetConfirmedServiceChoice.REINITIALIZE_DEVICE")
        elif apdu.service_choice == BACnetConfirmedServiceChoice.REINITIALIZE_DEVICE and self.events.OnReinitializeDevice:
            rq = ReinitializeDevice_Request()
            leng = ReinitializeDevice_Request.ASN1decode(rq, buffer, offset, length)
            if leng >= 0:
                logging.info(
                    "\n--------------------------- BACnetConfirmedServiceChoice.REINITIALIZE_DEVICE ---------------------------")
                logging.info(rq)
                logging.info(
                    "\n-----------------------------------------------------------------------------------------------------------")
                self.events.OnReinitializeDevice(self, adr, rq)
            else:
                logging.debug("Couldn't decode BACnetConfirmedServiceChoice.REINITIALIZE_DEVICE")
        elif apdu.service_choice == BACnetConfirmedServiceChoice.CONFIRMED_EVENT_NOTIFICATION:
            rq = EventNotification_Request()
            leng = EventNotification_Request.ASN1decode(rq, buffer, offset, length)
            if leng >= 0:
                logging.info(
                    "\n--------------------------- BACnetConfirmedServiceChoice.CONFIRMED_EVENT_NOTIFICATION ---------------------------")
                logging.info(rq)
                logging.info(
                    "\n---------------------------------------------------------------------------------------------------------------------")
                self.events.OnEventNotify(self, adr, rq, True)
            else:
                logging.debug("Couldn't decode BACnetConfirmedServiceChoice.CONFIRMED_EVENT_NOTIFICATION")
        elif apdu.service_choice == BACnetConfirmedServiceChoice.READ_RANGE and self.events.OnReadRange:
            rq = ReadRange_Request()
            leng = ReadRange_Request.ASN1decode(rq, buffer, offset, length)
            if leng >= 0:
                logging.info(
                    "\n--------------------------- BACnetConfirmedServiceChoice.READ_RANGE ---------------------------")
                logging.info(rq)
                logging.info(
                    "\n---------------------------------------------------------------------------------------------------------------------")
                self.events.OnReadRange(self, adr, rq)
            else:
                logging.debug("Couldn't decode BACnetConfirmedServiceChoice.READ_RANGE")
        elif apdu.service_choice == BACnetConfirmedServiceChoice.CREATE_OBJECT and self.events.OnCreateObject:
            rq = CreateObject_Request()
            leng = CreateObject_Request.ASN1decode(rq, buffer, offset, length)
            if leng >= 0:
                logging.info(
                    "\n--------------------------- BACnetConfirmedServiceChoice.CREATE_OBJECT ---------------------------")
                logging.info(rq)
                logging.info(
                    "\n---------------------------------------------------------------------------------------------------------------------")
                self.events.OnCreateObject(self, adr, rq)
            else:
                logging.debug("Couldn't decode BACnetConfirmedServiceChoice.CREATE_OBJECT")
        elif apdu.service_choice == BACnetConfirmedServiceChoice.DELETE_OBJECT and self.events.OnDeleteObject:
            rq = DeleteObject_Request()
            leng = DeleteObject_Request.ASN1decode(rq, buffer, offset, length)
            if leng >= 0:
                logging.info(
                    "\n--------------------------- BACnetConfirmedServiceChoice.DELETE_OBJECT ---------------------------")
                logging.info(rq)
                logging.info(
                    "\n---------------------------------------------------------------------------------------------------------------------")
                self.events.OnDeleteObject(self, adr, rq)
            else:
                logging.debug("Couldn't decode BACnetConfirmedServiceChoice.DELETE_OBJECT")
        elif apdu.service_choice == BACnetConfirmedServiceChoice.ADD_LIST_ELEMENT and self.events.OnAddListElement:
            rq = AddListElement_Request()
            leng = AddListElement_Request.ASN1decode(rq, buffer, offset, length)
            if leng >= 0:
                logging.info(
                    "\n--------------------------- BACnetConfirmedServiceChoice.ADD_LIST_ELEMENT ---------------------------")
                logging.info(rq)
                logging.info(
                    "\n---------------------------------------------------------------------------------------------------------------------")
                self.events.OnAddListElement(self, adr, rq)
            else:
                logging.debug("Couldn't decode BACnetConfirmedServiceChoice.ADD_LIST_ELEMENT")
        elif apdu.service_choice == BACnetConfirmedServiceChoice.REMOVE_LIST_ELEMENT and self.events.OnRemoveListElement:
            rq = RemoveListElement_Request()
            leng = RemoveListElement_Request.ASN1decode(rq, buffer, offset, length)
            if leng >= 0:
                logging.info(
                    "\n--------------------------- BACnetConfirmedServiceChoice.REMOVE_LIST_ELEMENT ---------------------------")
                logging.info(rq)
                logging.info(
                    "\n---------------------------------------------------------------------------------------------------------------------")
                self.events.OnRemoveListElement(self, adr, rq)
            else:
                logging.debug("Couldn't decode BACnetConfirmedServiceChoice.REMOVE_LIST_ELEMENT")
        elif apdu.service_choice == BACnetConfirmedServiceChoice.GET_EVENT_INFORMATION:
            logging.info("GET_EVENT_INFORMATION needs to be added!")
        elif apdu.service_choice == BACnetConfirmedServiceChoice.GET_ALARM_SUMMARY:
            logging.info("GET_ALARM_SUMMARY needs to be added!")
        elif apdu.service_choice == BACnetConfirmedServiceChoice.GET_ENROLLMENT_SUMMARY:
            logging.info("GET_ENROLLMENT_SUMMARY needs to be added!")
        elif apdu.service_choice == BACnetConfirmedServiceChoice.LIFE_SAFETY_OPERATION:
            logging.info("LIFE_SAFETY_OPERATION needs to be added!")
        else:
            logging.info("Confirmed service not handled: ", apdu.service_choice)

    def ProcessUnconfirmedServiceRequest(self, adr, apdu, buffer, offset, length):
        if apdu.service_choice == BACnetUnconfirmedServiceChoice.I_AM and self.events.OnIam:
            rq = IAm_Request()
            leng = IAm_Request.ASN1decode(rq, buffer, offset, length)
            if leng >= 0:
                logging.info(
                    "\n--------------------------- BACnetUnconfirmedServiceChoice.I_AM ---------------------------")
                logging.info(rq)
                logging.info(
                    "\n-------------------------------------------------------------------------------------------")
                self.events.OnIam(self, adr, rq)
            else:
                logging.debug("Couldn't decode BACnetUnconfirmedServiceChoice.I_AM")
        elif apdu.service_choice == BACnetUnconfirmedServiceChoice.WHO_IS and self.events.OnWhoIs:
            rq = WhoIs_Request()
            leng = WhoIs_Request.ASN1decode(rq, buffer, offset, length)
            if leng >= 0:
                logging.info(
                    "\n--------------------------- BACnetUnconfirmedServiceChoice.WHO_IS ---------------------------")
                logging.info(rq)
                logging.info(
                    "\n---------------------------------------------------------------------------------------------")
                self.events.OnWhoIs(self, adr, rq)
            else:
                logging.debug("Couldn't decode BACnetUnconfirmedServiceChoice.WHO_IS")


        elif apdu.service_choice == BACnetUnconfirmedServiceChoice.UNCONFIRMED_COV_NOTIFICATION and self.events.OnCOVNotification:
            rq = COVNotification_Request()
            leng = COVNotification_Request.ASN1decode(rq, buffer, offset, length)
            if leng >= 0:
                logging.info(
                    "\n--------------------------- BACnetUnconfirmedServiceChoice.UNCONFIRMED_COV_NOTIFICATION ---------------------------")
                logging.info(rq)
                logging.info(
                    "\n-----------------------------------------------------------------------------------------------------------")
                self.events.OnCOVNotification(self, adr, rq, False)
            else:
                logging.debug("Couldn't decode BACnetUnconfirmedServiceChoice.UNCONFIRMED_COV_NOTIFICATION")
        elif apdu.service_choice == BACnetUnconfirmedServiceChoice.TIME_SYNCHRONIZATION and self.events.OnTimeSynchronize:

            rq = TimeSynchronization_Request()
            leng = TimeSynchronization_Request.ASN1decode(rq, buffer, offset, length)
            if leng >= 0:
                logging.info(
                    "\n--------------------------- BACnetUnconfirmedServiceChoice.TIME_SYNCHRONIZATION ---------------------------")
                logging.info(rq)
                logging.info(
                    "\n-----------------------------------------------------------------------------------------------------------")
                self.events.OnTimeSynchronize(self, adr, rq)
            else:
                logging.debug("Couldn't decode BACnetUnconfirmedServiceChoice.TIME_SYNCHRONIZATION")
        elif apdu.service_choice == BACnetUnconfirmedServiceChoice.UTC_TIME_SYNCHRONIZATION and self.events.OnTimeSynchronize:
            rq = TimeSynchronization_Request()
            leng = TimeSynchronization_Request.ASN1decode(rq, buffer, offset, length)

            if leng >= 0:
                logging.info(
                    "\n--------------------------- BACnetUnconfirmedServiceChoice.UTC_TIME_SYNCHRONIZATION ---------------------------")
                logging.info(rq)
                logging.info(
                    "\n---------------------------------------------------------------------------------------------------------------")
                self.events.OnTimeSynchronize(self, adr, rq)
            else:
                logging.debug("Couldn't decode BACnetUnconfirmedServiceChoice.UTC_TIME_SYNCHRONIZATION")
        elif apdu.service_choice == BACnetUnconfirmedServiceChoice.UNCONFIRMED_EVENT_NOTIFICATION and self.events.OnEventNotify:

            rq = EventNotification_Request()
            leng = EventNotification_Request.ASN1decode(rq, buffer, offset, length)
            if leng >= 0:
                logging.info(
                    "\n--------------------------- BACnetUnconfirmedServiceChoice.UNCONFIRMED_EVENT_NOTIFICATION ---------------------------")
                logging.info(rq)
                logging.info(
                    "\n---------------------------------------------------------------------------------------------------------------------")
                self.events.OnEventNotify(self, adr, rq, False)
            else:
                logging.debug("Couldn't decode BACnetUnconfirmedServiceChoice.UNCONFIRMED_EVENT_NOTIFICATION")

        elif apdu.service_choice == BACnetUnconfirmedServiceChoice.UNCONFIRMED_TEXT_MESSAGE and self.events.OnTextMessage:

            rq = TextMessage_Request()
            leng = TextMessage_Request.ASN1decode(rq, buffer, offset, length)

            if leng >= 0:
                logging.info(
                    "\n--------------------------- BACnetUnconfirmedServiceChoice.UNCONFIRMED_TEXT_MESSAGE ---------------------------")
                logging.info(rq)
                logging.info(
                    "\n---------------------------------------------------------------------------------------------------------------")
                self.events.OnTextMessage(self, adr, rq)
            else:
                logging.debug("Couldn't decode BACnetUnconfirmedServiceChoice.UNCONFIRMED_TEXT_MESSAGE")
        elif apdu.service_choice == BACnetUnconfirmedServiceChoice.WHO_HAS and self.events.OnWhoHas:

            rq = WhoHas_Request()
            leng = WhoHas_Request.ASN1decode(rq, buffer, offset, length)
            if leng >= 0:
                logging.info(
                    "\n--------------------------- BACnetUnconfirmedServiceChoice.WHO_HAS ---------------------------")
                logging.info(rq)
                logging.info(
                    "\n----------------------------------------------------------------------------------------------")
                self.events.OnWhoHas(self, adr, rq)
            else:
                logging.debug("Couldn't decode BACnetUnconfirmedServiceChoice.WHO_HAS")
        elif apdu.service_choice == BACnetUnconfirmedServiceChoice.I_HAVE and self.events.OnIHave:
            rq = IHave_Request()
            leng = IHave_Request.ASN1decode(rq, buffer, offset, length)
            if leng >= 0:
                logging.info(
                    "\n--------------------------- BACnetUnconfirmedServiceChoice.I_HAVE ---------------------------")
                logging.info(rq)
                logging.info(
                    "\n---------------------------------------------------------------------------------------------")
                self.events.OnIHave(self, adr, rq)
            else:
                logging.debug("Couldn't decode BACnetUnconfirmedServiceChoice.I_HAVE")
        elif apdu.service_choice == BACnetUnconfirmedServiceChoice.WHO_AM_I and self.events.OnWhoAmI:
            rq = WhoAmI_Request()
            leng = WhoAmI_Request.ASN1decode(rq, buffer, offset, length)
            if leng >= 0:
                logging.info(
                    "\n--------------------------- BACnetUnconfirmedServiceChoice.WHO_AM_I ---------------------------")
                logging.info(rq)
                logging.info(
                    "\n---------------------------------------------------------------------------------------------")
                self.events.OnWhoAmI(self, adr, rq)
            else:
                logging.debug("Couldn't decode BACnetUnconfirmedServiceChoice.WHO_AM_I")
        elif apdu.service_choice == BACnetUnconfirmedServiceChoice.YOU_ARE and self.events.OnYouAre:
            rq = YouAre_Request()
            leng = YouAre_Request.ASN1decode(rq, buffer, offset, length)
            if leng >= 0:
                logging.info(
                    "\n--------------------------- BACnetUnconfirmedServiceChoice.YOU_ARE ---------------------------")
                logging.info(rq)
                logging.info(
                    "\n---------------------------------------------------------------------------------------------")
                self.events.OnYouAre(self, adr, rq)
            else:
                logging.debug("Couldn't decode BACnetUnconfirmedServiceChoice.YOU_ARE")
        else:
            print("Unconfirmed service not handled:",apdu.service_choice)

    def ProcessSimpleAck(adr, apdu, buffer, offset, length):  # (BACnetAddress adr, BacnetPduTypes type, BacnetConfirmedServices service, byte invoke_id, byte[] buffer, int offset, int length)
        logging.info(
            "\n--------------------------- SimpleAck ---------------------------")
        logging.info("\n\tservice:"+str(apdu.service_choice)+ "\n\tinvoke ID:"+str(apdu.invoke_id))
        logging.info(
            "\n-----------------------------------------------------------------")


    def ProcessComplexAck(self, adr, type, service, invoke_id, buffer, offset, length):
        if self.events.OnComplexAck:
            self.events.OnComplexAck(self, adr, type, service, invoke_id, buffer, offset, length)

    def ProcessError(adr, Pdu_type, service, invoke_id, buffer, offset, length):
        be = BACnetError()
        leng = be.ASN1decode(buffer, offset, length)
        logging.info("Error: "+str(be))

    def ProcessApdu(self, adr, buffer, offset, length):
        apdu = APDU()
        apdu_header_len = apdu.decode(buffer, offset)

        if apdu.pdu_type == BacnetPduTypes.PDU_TYPE_UNCONFIRMED_SERVICE_REQUEST:
            offset += apdu_header_len
            length -= apdu_header_len
            self.ProcessUnconfirmedServiceRequest(adr, apdu, buffer, offset, length)
        elif apdu.pdu_type == BacnetPduTypes.PDU_TYPE_SIMPLE_ACK:
            offset += apdu_header_len
            length -= apdu_header_len
            BacnetClient.ProcessSimpleAck(adr, apdu, buffer, offset, length)
        elif apdu.pdu_type == BacnetPduTypes.PDU_TYPE_COMPLEX_ACK:

            offset += apdu_header_len

            length -= apdu_header_len

            if not apdu.segmented_message:

                #(self, adr, type, service, invoke_id, buffer, offset, length):
                self.ProcessComplexAck(adr, apdu.pdu_type, apdu.service_choice, apdu.invoke_id, buffer, offset, length)
            else:
                pass  # segements!!!!
        elif apdu.pdu_type == BacnetPduTypes.PDU_TYPE_SEGMENT_ACK:
            print("BacnetPduTypes.PDU_TYPE_SEGMENT_ACK")
        elif apdu.pdu_type == BacnetPduTypes.PDU_TYPE_ERROR:
            print("BacnetPduTypes.PDU_TYPE_ERROR")
            offset += apdu_header_len
            length -= apdu_header_len
            BacnetClient.ProcessError(adr, apdu.pdu_type, apdu.service_choice, apdu.invoke_id, buffer, offset, length)


        elif apdu.pdu_type == BacnetPduTypes.PDU_TYPE_REJECT:
            print("BacnetPduTypes.PDU_TYPE_REJECT")
        elif apdu.pdu_type == BacnetPduTypes.PDU_TYPE_ABORT:
            print("BacnetPduTypes.PDU_TYPE_ABORT")
        elif apdu.pdu_type == BacnetPduTypes.PDU_TYPE_CONFIRMED_SERVICE_REQUEST:

            (apdu_header_len, TYPE, service, max_segments, max_apdu, invoke_id, sequence_number,
             proposed_window_number) = APDU.DecodeConfirmedServiceRequest(buffer, offset)

            offset += apdu_header_len

            length -= apdu_header_len

            if (apdu.pdu_type & BacnetPduTypes.SEGMENTED_MESSAGE) == 0:

                self.ProcessConfirmedServiceRequest(adr, apdu, max_segments, max_apdu, invoke_id,
                                                            buffer, offset, length)
            else:
                print("ProcessSegment")

        else:
            print("Something else arrived: ")


    def start(self):
        self.transport.events.on_MessageRecieved += self.OnRecieve
        self.transport.start()

    def UnconfirmedIam(self, rq : IAm_Request):
        logging.info("Sending UnconfirmedIam ...")
        broadcast = self.transport.getbroadcastaddress()

        npdu = NPDU(destination=broadcast)
        npdu.control.network_priority.Normal_Message = True
        apdu = APDU(pdu_type=BacnetPduTypes.PDU_TYPE_UNCONFIRMED_SERVICE_REQUEST,
                        service_choice=BACnetUnconfirmedServiceChoice.I_AM)

        buffer = npdu.encode() + apdu.encode() + rq.ASN1encode()

        self.transport.send(buffer, self.transport.headerlength, len(buffer), broadcast, False , 0)

    def UnconfirmedWhoIs(self, rq : WhoIs_Request):
        logging.info("Sending UnconfirmedWhoIs ...")
        broadcast = self.transport.getbroadcastaddress()
        npdu = NPDU(destination=broadcast)
        npdu.control.network_priority.Normal_Message = True
        apdu = APDU(pdu_type=BacnetPduTypes.PDU_TYPE_UNCONFIRMED_SERVICE_REQUEST,
                        service_choice=BACnetUnconfirmedServiceChoice.WHO_IS)

        buffer = npdu.encode() + apdu.encode() + rq.ASN1encode()

        self.transport.send(buffer, self.transport.headerlength, len(buffer), broadcast, False, 0)

    def UnconfirmedWhoAmI(self, rq : WhoAmI_Request):
        logging.info("Sending UnconfirmedWhoAmI ...")
        broadcast = self.transport.getbroadcastaddress()
        npdu = NPDU(destination=broadcast)
        npdu.control.network_priority.Normal_Message = True
        apdu = APDU(pdu_type=BacnetPduTypes.PDU_TYPE_UNCONFIRMED_SERVICE_REQUEST,
                        service_choice=BACnetUnconfirmedServiceChoice.WHO_AM_I)

        buffer = npdu.encode() + apdu.encode() + rq.ASN1encode()

        self.transport.send(buffer, self.transport.headerlength, len(buffer), broadcast, False, 0)

    def UnconfirmedYouAre(self, rq : YouAre_Request):
        logging.info("Sending UnconfirmedYouAre ...")
        broadcast = self.transport.getbroadcastaddress()
        npdu = NPDU(destination=broadcast)
        npdu.control.network_priority.Normal_Message = True
        apdu = APDU(pdu_type=BacnetPduTypes.PDU_TYPE_UNCONFIRMED_SERVICE_REQUEST,
                        service_choice=BACnetUnconfirmedServiceChoice.YOU_ARE)

        buffer = npdu.encode() + apdu.encode() + rq.ASN1encode()

        self.transport.send(buffer, self.transport.headerlength, len(buffer), broadcast, False, 0)

    def UnconfirmedIHave(self, rq: IHave_Request):
        logging.info("Sending UnconfirmedIHave ...")
        broadcast = self.transport.getbroadcastaddress()
        npdu = NPDU(destination=broadcast)
        npdu.control.network_priority.Normal_Message = True
        apdu = APDU(pdu_type=BacnetPduTypes.PDU_TYPE_UNCONFIRMED_SERVICE_REQUEST,
                        service_choice=BACnetUnconfirmedServiceChoice.I_HAVE)

        buffer = npdu.encode() + apdu.encode() + rq.ASN1encode()

        self.transport.send(buffer, self.transport.headerlength, len(buffer), broadcast, False, 0)

    def UnconfirmedWhoHas(self, rq: WhoHas_Request):
        logging.info("Sending UnconfirmedWhoHas ...")

        broadcast = self.transport.getbroadcastaddress()
        npdu = NPDU(destination=broadcast)
        npdu.control.network_priority.Normal_Message = True
        apdu = APDU(pdu_type=BacnetPduTypes.PDU_TYPE_UNCONFIRMED_SERVICE_REQUEST,
                        service_choice=BACnetUnconfirmedServiceChoice.WHO_HAS)

        buffer = npdu.encode() + apdu.encode() + rq.ASN1encode()

        self.transport.send(buffer, self.transport.headerlength, len(buffer), broadcast, False, 0)

    def UnconfirmedTimeSynchronize(self, rq : TimeSynchronization_Request):
        logging.info("Sending UnconfirmedTimeSynchronize ...")

        broadcast = self.transport.getbroadcastaddress()
        npdu = NPDU(destination=broadcast)
        npdu.control.network_priority.Normal_Message = True
        apdu = APDU(pdu_type=BacnetPduTypes.PDU_TYPE_UNCONFIRMED_SERVICE_REQUEST,
                        service_choice=BACnetUnconfirmedServiceChoice.TIME_SYNCHRONIZATION)

        buffer = npdu.encode() + apdu.encode() + rq.ASN1encode()

        self.transport.send(buffer, self.transport.headerlength, len(buffer), broadcast, False, 0)

    def UnconfirmedTextMessage(self, rq : TextMessage_Request):
        logging.info("Sending UnconfirmedTextMessage ...")

        broadcast = self.transport.getbroadcastaddress()
        npdu = NPDU(destination=broadcast)
        npdu.control.network_priority.Normal_Message = True
        apdu = APDU(pdu_type=BacnetPduTypes.PDU_TYPE_UNCONFIRMED_SERVICE_REQUEST,
                        service_choice=BACnetUnconfirmedServiceChoice.UNCONFIRMED_TEXT_MESSAGE)

        buffer = npdu.encode() + apdu.encode() + rq.ASN1encode()

        self.transport.send(buffer, self.transport.headerlength, len(buffer), broadcast, False, 0)

    def UnconfirmedEventNotification(self, rq : EventNotification_Request):
        logging.info("Sending UnconfirmedEventNotification ...")

        broadcast = self.transport.getbroadcastaddress()
        npdu = NPDU(destination=broadcast)
        npdu.control.network_priority.Normal_Message = True
        apdu = APDU(pdu_type=BacnetPduTypes.PDU_TYPE_UNCONFIRMED_SERVICE_REQUEST,
                        service_choice=BACnetUnconfirmedServiceChoice.UNCONFIRMED_EVENT_NOTIFICATION)

        buffer = npdu.encode() + apdu.encode() + rq.ASN1encode()

        self.transport.send(buffer, self.transport.headerlength, len(buffer), broadcast, False, 0)

    def ReadPropertyRequest(self,device_identifier:BACnetObjectIdentifier = None, adr:BACnetAddress = None, rq: ReadProperty_Request = None):
        #fixme as async and retries and await answer, not correct yet!!!
        task = asyncio.ensure_future(self.BeginReadPropertyRequest(device_identifier, adr, rq))
        return task

    async def BeginReadPropertyRequest(self,device_identifier:BACnetObjectIdentifier = None, adr:BACnetAddress = None, rq: ReadProperty_Request = None):

        logging.info("Sending ReadPropertyRequest")
        npdu = NPDU(destination=BACnetAddress(net_type=BACnetNetworkType.IPV4, address=device_identifier,
                                              network_number=adr.network_number))
        npdu.control.data_expecting_reply = True
        npdu.control.network_priority.Normal_Message = True

        apdu = APDU(pdu_type=BacnetPduTypes.PDU_TYPE_CONFIRMED_SERVICE_REQUEST,
                    service_choice=BACnetConfirmedServiceChoice.READ_PROPERTY,
                    segmented_response_accepted=False,
                    max_segments_accepted=BACnetSegmentation.NO_SEGMENTATION,
                    max_apdu_length_accepted=BacnetMaxAdpu.MAX_APDU1476,
                    invoke_id=self._m_invoke_id
                    )

        buffer = npdu.encode() + apdu.encode() + rq.ASN1encode()
        result = BACnetResult(self, adr, self._m_invoke_id, buffer, len(buffer), False, 0)
        self._m_invoke_id += 1
        if self._m_invoke_id > 255:
            self._m_invoke_id = 0

        result.send()
        await result.Done()
        print(result.result)
        return result.result


class BACnetResult:
    def __init__(self, client:BacnetClient, adr:BACnetAddress, invoke_id:int, buffer:bytes, transmit_length:int, wait_for_transmit:bool = None, transmit_timeout:int = None):
        self.client = client
        self.adr = adr
        self.wait_invoke_id = invoke_id
        self.buffer = buffer
        self.transmit_length = transmit_length
        self.wait_for_transmit = wait_for_transmit
        self.transmit_timeout = transmit_timeout
        self.client.events.OnComplexAck += self.ComplexAckHandler
        self.result = None

    async def Done(self):
        while self.result == None:
            await asyncio.sleep(1)
        return True

    def send(self):
        self.client.transport.send(self.buffer, self.client.transport.headerlength, len(self.buffer), self.adr, self.wait_for_transmit, self.transmit_timeout)

    def ComplexAckHandler(self, sender, adr, type, service, invoke_id, buffer, offset, length):
        if self.wait_invoke_id == invoke_id:
            if service == BACnetConfirmedServiceChoice.READ_PROPERTY:
                #logging.info("-------------------------- ReadProperty-ACK --------------------------")
                rq = ReadProperty_ACK()
                leng = rq.ASN1decode(buffer, offset, length)
                #logging.info(rq)
                #logging.info("----------------------------------------------------------------------")
                self.result = rq
            elif service == BACnetConfirmedServiceChoice.CREATE_OBJECT:
                pass
            elif service == BACnetConfirmedServiceChoice.READ_PROPERTY_MULTIPLE:
                pass
            else:
                logging.debug("ComplexAck not finished")
            self.client.events.OnComplexAck -= self.ComplexAckHandler