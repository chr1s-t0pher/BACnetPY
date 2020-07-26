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

from BACnetEnum import *
from BACnetBase import *
import logging, sys
import enum

logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)


class ReinitializeDevice_Request:
    class reinitializedstateofdeviceChoice(enum.IntEnum):
        coldstart = 0
        warmstart = 1
        start_backup = 2
        end_backup  = 3
        start_restore = 4
        end_restore = 5
        abort_restore = 6
        activate_changes = 7

    def __init__(self, reinitializedstateofdevice : reinitializedstateofdeviceChoice = None, password: str = None):
        self.reinitializedstateofdevice = reinitializedstateofdevice
        self.password = password

    def __str__(self):
        return "\nreinitializedstateofdevice: "+str(self.reinitializedstateofdevice)+"\npassword: "+str(self.password)

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        leng += leng1
        #reinitializedstateofdevice
        if (tag_number == 0):
            (leng1, len_value) = ASN1.decode_unsigned(buffer, offset+leng, len_value)
            leng += leng1
            self.reinitializedstateofdevice = ReinitializeDevice_Request.reinitializedstateofdeviceChoice(len_value)
        else:
            return -1
        if leng < apdu_len:
            #password
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            #max of 20!?!
            if (tag_number == 1):
                (leng1, self.password) = ASN1.decode_character_string(buffer, offset+leng,apdu_len-leng,len_value)
                leng += leng1
        return leng

class DeviceCommunicationControl_Request:
    class enabledisableChoice(enum.IntEnum):
        enable = 0
        disable = 1
        disable_initiation = 2

    def __init__(self, timeduration : int = None, enabledisable : enabledisableChoice =None, password:str =None):
        self.timeduration = timeduration
        self.enabledisable = enabledisable
        self.password = password

    def __str__(self):
        return "\ntimeduration: "+str(self.timeduration)+"\nenabledisable: "+str(self.enabledisable)+"\npassword: "+str(self.password)

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0

        (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        # timeduration optional
        if (tag_number == 0):
            leng += leng1
            (leng1, self.timeduration) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1

        # enabledisable
        (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        leng += leng1
        if (tag_number == 1):
            (leng1, len_value) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1
            self.enabledisable = DeviceCommunicationControl_Request.enabledisableChoice(len_value)
        else:
            return -1

        if leng < apdu_len:
            #password optional
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            #max of 20!?!
            if (tag_number == 2):
                (leng1, self.password) = ASN1.decode_character_string(buffer, offset+leng,apdu_len-leng,len_value)
                leng += leng1
        return leng

class AddListElement_Request:
    def __init__(self, objectidentifier: BACnetObjectIdentifier = None,
                 propertyidentifier: BACnetPropertyIdentifier =None,
                 propertyarrayindex: int =None,
                 listofelements: [] = None):
        self.objectidentifier = objectidentifier
        self.propertyidentifier = propertyidentifier
        self.propertyarrayindex = propertyarrayindex
        self.listofelements = listofelements

    def __str__(self):
        ret = "\nobjectidentifier: "+str(self.objectidentifier)+\
               "\npropertyidentifier: " + str(self.propertyidentifier)+ \
               "\npropertyarrayindex: " + str(self.propertyarrayindex)
        for val in self.listofelements:
            ret += "\n"+str(val)
        return ret

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        # object-identifier
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 0)):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            self.objectidentifier = BACnetObjectIdentifier()
            leng += BACnetObjectIdentifier.ASN1decode(self.objectidentifier, buffer, offset + leng, len_value)
        else:
            return -1

        #property-identifier
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 1)):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.propertyidentifier) = ASN1.decode_enumerated(buffer, offset + leng, len_value, prop_id = BACnetPropertyIdentifier.PROPERTY_LIST)
            leng += leng1
        else:
            return -1

        # property-array-index optional
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 2)):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.propertyarrayindex) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1

        if (ASN1.decode_is_opening_tag_number(buffer, offset + leng, 3)):
            leng += 1
            _value_list = []
            while ((apdu_len - leng) > 1 and not ASN1.decode_is_closing_tag_number(buffer, offset + leng, 3)):

                (leng1, b_value) = ASN1.bacapp_decode_application_data(buffer, offset + leng, apdu_len + offset, self.objectidentifier.Type, self.propertyidentifier)

                if leng1 <= 0:
                    return -1
                leng += leng1
                _value_list.append(b_value)
        else:
            return -1

        self.listofelements = _value_list
        leng += 1

        return leng

class RemoveListElement_Request(AddListElement_Request):
    # the same as AddListElement_Request?!?
    def __init__(self, objectidentifier: BACnetObjectIdentifier = None,
                 propertyidentifier: BACnetPropertyIdentifier = None,
                 propertyarrayindex: int = None,
                 listofelements: [] = None):
        self.objectidentifier = objectidentifier
        self.propertyidentifier = propertyidentifier
        self.propertyarrayindex = propertyarrayindex
        self.listofelements = listofelements

class IHave_Request:
    def __init__(self, deviceidentifier: BACnetObjectIdentifier = None,
                 objectidentifier: BACnetObjectIdentifier =None,
                 objectname=None):
        self.deviceidentifier = deviceidentifier
        self.objectidentifier = objectidentifier
        self.objectname = objectname

    def __str__(self):
        return "\ndeviceidentifier: "+str(self.deviceidentifier)+\
               "\nobjectidentifier: " + str(self.objectidentifier)+ \
               "\nobjectname: " + str(self.objectname)

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0

        # deviceidentifier
        (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        leng += leng1

        if(tag_number == BACnetApplicationTags.BACNETOBJECTIDENTIFIER):
            self.deviceidentifier = BACnetObjectIdentifier()
            leng += BACnetObjectIdentifier.ASN1decode(self.deviceidentifier, buffer, offset+leng, len_value)
        else:
            return -1

        #is device?
        if(self.deviceidentifier.Type != BACnetObjectType.Device):
            return -1

        #objectidentifier
        (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        leng += leng1
        if (tag_number == BACnetApplicationTags.BACNETOBJECTIDENTIFIER):
            self.objectidentifier = BACnetObjectIdentifier()
            leng += BACnetObjectIdentifier.ASN1decode(self.objectidentifier, buffer, offset + leng, len_value)
        else:
            return -1

        #objectname
        (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        leng += leng1
        if (tag_number == BACnetApplicationTags.CHARACTER_STRING):
            (leng1, self.objectname) = ASN1.decode_character_string(buffer, offset + leng, 2000, len_value)
            leng += leng1
        else:
            return -1

        return leng

    def ASN1encode(self):
        return self.deviceidentifier.ASN1encode_app() + \
               self.objectidentifier.ASN1encode_app() + \
               ASN1.encode_application_character_string(self.objectname)

class WhoHas_Request:
    def __init__(self, deviceinstancerangelowlimit=None, deviceinstancerangehighlimit=None, obj=None):
        self.deviceinstancerangelowlimit = deviceinstancerangelowlimit
        self.deviceinstancerangehighlimit = deviceinstancerangehighlimit
        self.obj = obj

    def __str__(self):
        ret = ""
        if self.deviceinstancerangelowlimit != None and self.deviceinstancerangehighlimit != None:
            ret += "\ndeviceinstancerangelowlimit: "+str(self.deviceinstancerangelowlimit)+\
                   "\ndeviceinstancerangehighlimit: " + str(self.deviceinstancerangehighlimit)
        ret += "\nobj: "+str(self.obj)
        return ret

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 0)):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.deviceinstancerangelowlimit) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1


        if (ASN1.decode_is_context_tag(buffer, offset + leng, 1)):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.deviceinstancerangehighlimit) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1


        if (ASN1.decode_is_context_tag(buffer, offset + leng, 2)):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            self.obj = BACnetObjectIdentifier()
            leng += BACnetObjectIdentifier.ASN1decode(self.obj, buffer, offset + leng, len_value)
        elif(ASN1.decode_is_context_tag(buffer, offset + leng, 3)):
            (leng1, self.obj) = ASN1.decode_context_character_string(buffer, offset + leng, 20000, 3)
            leng += leng1
        else:
            return -1

        return leng

    def ASN1encode(self):
        buffer = ASN1.encode_context_unsigned(0, self.deviceinstancerangelowlimit) + ASN1.encode_context_unsigned(1, self.deviceinstancerangehighlimit)
        if type(self.obj) == BACnetObjectIdentifier:
            buffer += self.obj.ASN1encode_context(2)
        elif type(self.obj) == str:
            buffer += ASN1.encode_context_character_string(3,self.obj)
        return  buffer

class TextMessage_Request:
    def __init__(self, textmessagesourcedevice : BACnetObjectIdentifier = None,
                 messageclass=None,
                 messagepriority : int =None,
                 message : str =None):
        self.textmessagesourcedevice = textmessagesourcedevice
        self.messageclass = messageclass
        self.messagepriority = messagepriority
        self.message = message

    class messagepriority(enum.IntEnum):
        normal = 0
        urgent = 1

    def __str__(self):
        ret = "\ntextmessagesourcedevice: "+str(self.textmessagesourcedevice)
        if self.messageclass != None:
            ret += "\nmessageclass: "+str(self.messageclass)
        ret += "\nmessagepriority: "+str(self.messagepriority)+\
               "\nmessage: " + str(self.message)
        return ret

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0

        #tag 0 textmessagesourcedevice
        self.textmessagesourcedevice = BACnetObjectIdentifier()
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 0)):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            leng += BACnetObjectIdentifier.ASN1decode(self.textmessagesourcedevice, buffer, offset+leng, len_value)
        else:
            return -1

        if self.textmessagesourcedevice.Type != BACnetObjectType.Device:
            return -1

        #tag 1 messageClass untested optional
        if(ASN1.decode_is_context_tag(buffer, offset + leng, 1)):
            leng += 1
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            if (tag_number == BACnetApplicationTags.CHARACTER_STRING):
                (leng1, self.messageclass) = ASN1.decode_character_string(buffer, offset + leng, 2000, len_value)
                leng += leng1
            elif(tag_number == BACnetApplicationTags.UNSIGNED_INT):
                (leng1, self.messageclass) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
                leng += leng1
            else:
                return -1

        #tag 2 messagePriority
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 2)):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, priority) = ASN1.decode_enumerated(buffer, offset + leng, len_value)
            leng += leng1
            self.messagepriority = TextMessage_Request.messagepriority(priority)
        else:
            return -1

        #tag 3 Message
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 3)):
            (leng1, self.message) = ASN1.decode_context_character_string(buffer, offset + leng, 20000, 3)
            leng += leng1
        else:
            return -1
        return leng

    def ASN1encode(self):
        buffer = self.textmessagesourcedevice.ASN1encode_context(0)
        #messageclass how to add????
        if self.messageclass != None:
            if type(self.messageclass) == str:
                buffer += ASN1.encode_context_character_string(1, self.messageclass)
            elif type(self.messageclass) == int:
                buffer += ASN1.encode_context_unsigned(1, self.messageclass)
        buffer += ASN1.encode_context_enumerated(2,self.messagepriority)
        buffer += ASN1.encode_context_character_string(3,self.message)
        return buffer

class IAm_Request:
    def __init__(self, iamdeviceidentifier : BACnetObjectIdentifier = None,
                 maxapdulengthaccepted : int = None,
                 segmentationsupported = None,
                 vendorid : int = None):
        self.iamdeviceidentifier = iamdeviceidentifier
        self.maxapdulengthaccepted = maxapdulengthaccepted
        self.segmentationsupported = segmentationsupported
        self.vendorid = vendorid

    def __str__(self):
        return "\niamdeviceidentifier: "+str(self.iamdeviceidentifier)+\
               "\nmaxapdulengthaccepted: "+str(self.maxapdulengthaccepted)+\
               "\nsegmentationsupported: "+str(self.segmentationsupported)+ \
               "\nvendorid: " + str(self.vendorid)

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        self.iamdeviceidentifier = BACnetObjectIdentifier()
        # OBJECT ID - object id
        (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        leng += leng1

        if tag_number != BACnetApplicationTags.BACNETOBJECTIDENTIFIER:
            return -1
        leng += BACnetObjectIdentifier.ASN1decode(self.iamdeviceidentifier, buffer, offset + leng, len_value)



        if self.iamdeviceidentifier.Type != BACnetObjectType.Device:
            logging.debug("\nGot Iam from no device!")
            return -1

        # MAX APDU - unsigned
        (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        leng += leng1
        if tag_number != BACnetApplicationTags.UNSIGNED_INT:
            return -1
        (leng1, decoded_value) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
        leng += leng1
        self.maxapdulengthaccepted = decoded_value

        # Segmentation - enumerated
        (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)

        leng += leng1
        if tag_number != BACnetApplicationTags.ENUMERATED:
            return -1
        (leng1, self.segmentationsupported) = ASN1.decode_enumerated(buffer, offset + leng, len_value,
                                                                     prop_id=BACnetPropertyIdentifier.SEGMENTATION_SUPPORTED)
        leng += leng1

        # Vendor ID - unsigned16
        (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        leng += leng1

        if tag_number != BACnetApplicationTags.UNSIGNED_INT:
            return -1

        (leng1, decoded_value) = ASN1.decode_unsigned(buffer, offset + leng, len_value)

        leng += leng1
        if decoded_value > 0xFFFF:
            return -1
        self.vendorid = decoded_value

        return leng

    def ASN1encode(self) -> bytes:

        tmp = self.iamdeviceidentifier.ASN1encode()
        return ASN1.encode_tag(BACnetApplicationTags.BACNETOBJECTIDENTIFIER, False,len(tmp)) + tmp +\
               ASN1.encode_application_unsigned(self.maxapdulengthaccepted)+\
               ASN1.encode_application_enumerated(int(self.segmentationsupported))+\
               ASN1.encode_application_unsigned(self.vendorid)

class WhoIs_Request:

    def __init__(self, deviceInstanceRangeLowLimit=None, deviceInstanceRangeHighLimit=None):
        self.deviceInstanceRangeLowLimit = deviceInstanceRangeLowLimit
        self.deviceInstanceRangeHighLimit = deviceInstanceRangeHighLimit

    def __str__(self):
        ret = ""
        if self.deviceInstanceRangeLowLimit != None:
            ret += "\ndeviceInstanceRangeLowLimit: "+str(self.deviceInstanceRangeLowLimit)
        if self.deviceInstanceRangeHighLimit != None:
            ret += "\ndeviceInstanceRangeHighLimit: " + str(self.deviceInstanceRangeHighLimit)
        return ret

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        low_limit = -1
        high_limit = -1

        if apdu_len <= 0:
            return leng

        (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        leng += leng1
        if tag_number != 0:
            return -1
        if apdu_len > leng:

            (leng1, decoded_value) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1

            if decoded_value <= ASN1.BACNET_MAX_INSTANCE:
                self.deviceInstanceRangeLowLimit = decoded_value;
            if apdu_len > leng:
                (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                if tag_number != 1:
                    return -1
                if apdu_len > leng:
                    (leng1, decoded_value) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
                    leng += leng1
                    if decoded_value <= ASN1.BACNET_MAX_INSTANCE:
                        self.deviceInstanceRangeHighLimit = decoded_value;
                else:
                    return -1

            else:
                return -1

        else:
            return -1

        return leng

    def ASN1encode(self):

        if self.deviceInstanceRangeLowLimit != None and\
                self.deviceInstanceRangeLowLimit <= ASN1.BACNET_MAX_INSTANCE and\
                self.deviceInstanceRangeHighLimit != None and\
                self.deviceInstanceRangeHighLimit <= ASN1.BACNET_MAX_INSTANCE:
            return ASN1.encode_context_unsigned(0, self.deviceInstanceRangeLowLimit) +\
                   ASN1.encode_context_unsigned(1, self.deviceInstanceRangeHighLimit)
        else:
            return bytearray(0)

class TimeSynchronization_Request:
    def __init__(self, TIME : BACnetDateTime = None):
        self.TIME = TIME

    def __str__(self):
        return str(self.TIME)

    def ASN1decode(self, buffer, offset, apdu_len):
        self.TIME = BACnetDateTime()
        leng = BACnetDateTime.ASN1decode(self.TIME,buffer, offset, apdu_len)
        return leng

    def ASN1encode(self):
        return self.TIME.ASN1encode()

class DeleteObject_Request:
    def __init__(self, objectidentifier : BACnetObjectIdentifier =None):
        self.objectidentifier = objectidentifier

    def __str__(self):
        return "\nobjectidentifier: "+str(self.objectidentifier)

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0

        (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        leng += leng1
        if tag_number == BACnetApplicationTags.BACNETOBJECTIDENTIFIER:
            self.objectidentifier = BACnetObjectIdentifier()
            leng += self.objectidentifier.ASN1decode(buffer, offset+leng, len_value)
        else:
            return -1

        return leng

class ReadRange_Request:
    def __init__(self, objectidentifier:BACnetObjectIdentifier = None, propertyidentifier :BACnetPropertyIdentifier = None, propertyarrayindex:int = None, Range = None):
        self.objectidentifier = objectidentifier
        self.propertyidentifier = propertyidentifier
        self.propertyarrayindex = propertyarrayindex
        #range is no good name!
        self.Range = Range

    def __str__(self):
        return "\nobjectidentifier: "+str(self.objectidentifier)+ \
               "\npropertyidentifier: " + str(self.propertyidentifier) + \
               "\npropertyarrayindex: " + str(self.propertyarrayindex) + \
               "\nRange: " + str(self.Range)

    class byposition:
        def __init__(self, referenceindex:int =None, count:int = None):
            self.referenceindex = referenceindex
            self.count = count

        def __str__(self):
            return "\n-byposition-"+"\nreferenceindex: "+str(self.referenceindex)+"\ncount: "+str(self.count)

    class bysequencenumber:
        def __init__(self, referencesequencenumber:int =None, count:int = None):
            self.referencesequencenumber = referencesequencenumber
            self.count = count

        def __str__(self):
            return "\n-bysequencenumber-"+"\nreferencesequencenumber: "+str(self.referencesequencenumber)+"\ncount: "+str(self.count)

    class bytime:
        def __init__(self, referencetime:BACnetDateTime =None, count:int = None):
            self.referencetime = referencetime
            self.count = count

        def __str__(self):
            return "\n-bytime-"+"\nreferencetime: "+str(self.referencetime)+"\ncount: "+str(self.count)

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        # tag 0 objectidentifier
        if ASN1.decode_is_context_tag(buffer, offset + leng, 0):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            self.objectidentifier = BACnetObjectIdentifier()
            leng += self.objectidentifier.ASN1decode(buffer, offset + leng, len_value)
        else:
            return -1

        # tag 1 propertyidentifier
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 1)):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.propertyidentifier) = ASN1.decode_enumerated(buffer, offset + leng, len_value, prop_id = BACnetPropertyIdentifier.PROPERTY_LIST)
            leng += leng1
        else:
            return -1
        # tag 2 property-array-index optional
        if leng < apdu_len:
            if (ASN1.decode_is_context_tag(buffer, offset + leng, 2)):
                (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                (leng1, self.propertyarrayindex) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
                leng += leng1
        # range optional
        if leng < apdu_len:
            if ASN1.decode_is_opening_tag_number(buffer, offset+leng, 3):
                # by-position
                leng += 1
                self.Range = ReadRange_Request.byposition()
                (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                if tag_number == BACnetApplicationTags.UNSIGNED_INT:
                    (leng1, self.Range.referenceindex) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
                    leng += leng1
                else:
                    return -1
                (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                if tag_number == BACnetApplicationTags.SIGNED_INT:
                    (leng1, self.Range.count) = ASN1.decode_signed(buffer, offset + leng, len_value)
                    leng += leng1
                else:
                    return -1
            elif ASN1.decode_is_opening_tag_number(buffer, offset+leng, 6):
                #  by-sequence-number
                leng += 1
                self.Range = ReadRange_Request.bysequencenumber()
                (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                if tag_number == BACnetApplicationTags.UNSIGNED_INT:
                    (leng1, self.Range.referencesequencenumber) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
                    leng += leng1
                else:
                    return -1
                (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                if tag_number == BACnetApplicationTags.SIGNED_INT:
                    (leng1, self.Range.count) = ASN1.decode_signed(buffer, offset + leng, len_value)
                    leng += leng1
                else:
                    return -1
            elif ASN1.decode_is_opening_tag_number(buffer, offset+leng, 7):
                # by-time
                leng += 1
                self.Range = ReadRange_Request.bytime()
                #date
                date_value = None
                (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                if tag_number == BACnetApplicationTags.DATE:
                    (leng1, date_value) = ASN1.decode_date_safe(buffer, offset+leng, len_value)
                    leng += leng1
                else:
                    return -1
                # time
                time_value = None
                (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                if tag_number == BACnetApplicationTags.TIME:
                    (leng1, time_value) = ASN1.decode_bacnet_time_safe(buffer, offset + leng, len_value)
                    leng += leng1
                else:
                    return -1

                self.Range.referencetime = BACnetDateTime(date_value, time_value)
                (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                if tag_number == BACnetApplicationTags.SIGNED_INT:
                    (leng1, self.Range.count) = ASN1.decode_signed(buffer, offset + leng, len_value)
                    leng += leng1
                else:
                    return -1
            else:
                # 4 and 5 deprecated
                return -1

            if ASN1.decode_is_closing_tag(buffer, offset + leng):
                leng += 1
            else:
                return -1



        return leng

class CreateObject_Request:
    def __init__(self, objectspecifier =None, listofinitialvalues : [] = None):
        self.objectspecifier = objectspecifier
        self.listofinitialvalues  = listofinitialvalues

    def __str__(self):
        ret = "\nobjectspecifier: "+str(self.objectspecifier)
        for val in self.listofinitialvalues:
            ret += "\n"+str(val)
        return ret

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        #objectspecifier
        if ASN1.decode_is_opening_tag_number(buffer, offset+leng, 0):
            leng += 1

            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            # objectspecifier
            if tag_number == 0:
                # BACnetObjectType
                (leng1, self.objectspecifier) = ASN1.decode_enumerated(buffer, offset + leng, len_value, prop_id = BACnetPropertyIdentifier.OBJECT_TYPE)
                leng += leng1
            elif tag_number == 1:
                # BACnetObjectIdentifier
                self.objectspecifier = BACnetObjectIdentifier()
                leng += self.objectspecifier.ASN1decode(buffer, offset + leng, len_value)
            else:
                return -1
        else:
            return -1

        # list-of-initial-values optional
        if ASN1.decode_is_closing_tag(buffer, offset+leng):
            leng += 1

        #list-of-initial-values optional
        self.listofinitialvalues = []
        if leng < apdu_len:

            if ASN1.decode_is_opening_tag_number(buffer, offset + leng, 1):
                leng += 1
                if type(self.objectspecifier) == BACnetObjectIdentifier:
                    objtype = self.objectspecifier.Type
                else:
                    objtype = self.objectspecifier

                while not ASN1.decode_is_closing_tag_number(buffer, offset + leng, 1):
                    new_entry = BACnetPropertyValue()

                    leng += BACnetPropertyValue.ASN1decode(new_entry, buffer, offset + leng, apdu_len, objtype)
                    self.listofinitialvalues.append(new_entry)

            if ASN1.decode_is_closing_tag(buffer, offset + leng):
                leng += 1



        return leng

class SubscribeCOVProperty_Request:
    def __init__(self, subscriberprocessidentifier : int =None, monitoredobjectidentifier : BACnetObjectIdentifier = None, issueconfirmednotifications :bool = None,lifetime:int = None, monitoredpropertyidentifier:BACnetPropertyReference =None,covincrement:float = None ):
        self.subscriberprocessidentifier  = subscriberprocessidentifier
        self.monitoredobjectidentifier  = monitoredobjectidentifier
        self.issueconfirmednotifications = issueconfirmednotifications
        self.lifetime = lifetime
        self.monitoredpropertyidentifier = monitoredpropertyidentifier
        self.covincrement = covincrement

    def __str__(self):
        return "\nsubscriberprocessidentifier: " + str(self.subscriberprocessidentifier) + \
               "\nmonitoredobjectidentifier: " + str(self.monitoredobjectidentifier) + \
               "\nissueconfirmednotifications: " + str(self.issueconfirmednotifications) + \
               "\nlifetime: " + str(self.lifetime) +\
               "\nmonitoredpropertyidentifier: "+str(self.monitoredpropertyidentifier) +\
               "\ncovincrement: "+str(self.covincrement)

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        # tag 0 subscriberprocessidentifier
        if ASN1.decode_is_context_tag(buffer, offset+leng, 0):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.subscriberprocessidentifier) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1
        else:
            return -1
        # tag 1 monitoredobjectidentifier
        if ASN1.decode_is_context_tag(buffer, offset+leng, 1):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            self.monitoredobjectidentifier = BACnetObjectIdentifier()
            leng += self.monitoredobjectidentifier.ASN1decode(buffer, offset+leng,len_value)
        else:
            return -1

        # tag 2 issueconfirmednotifications optional
        if ASN1.decode_is_context_tag(buffer, offset + leng, 2):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, value) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1
            self.issueconfirmednotifications = bool(value > 0)

        #tag 3 lifetime optional
        if ASN1.decode_is_context_tag(buffer, offset + leng, 3):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.lifetime) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1

        # tag 4 monitoredpropertyidentifier optional
        if ASN1.decode_is_opening_tag_number(buffer, offset + leng, 4):
            leng += 1
            self.monitoredpropertyidentifier = BACnetPropertyReference()
            leng += self.monitoredpropertyidentifier.ASN1decode(buffer,offset+leng, apdu_len -leng )
            leng += 1
        else:
            return -1

        if leng < apdu_len:
            #tag 5 covincrement optional
            if ASN1.decode_is_context_tag(buffer, offset + leng, 5):
                (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                (leng1, self.covincrement) = ASN1.decode_real_safe(buffer, offset + leng, len_value)
                leng += leng1

        return leng



class SubscribeCOV_Request:
    def __init__(self, subscriberprocessidentifier : int =None, monitoredobjectidentifier : BACnetObjectIdentifier = None, issueconfirmednotifications :bool = None,lifetime:int = None ):
        self.subscriberprocessidentifier  = subscriberprocessidentifier
        self.monitoredobjectidentifier  = monitoredobjectidentifier
        self.issueconfirmednotifications = issueconfirmednotifications
        self.lifetime = lifetime

    def __str__(self):
        return "\nsubscriberprocessidentifier: "+str(self.subscriberprocessidentifier)+ \
               "\nmonitoredobjectidentifier: " + str(self.monitoredobjectidentifier) + \
               "\nissueconfirmednotifications: " + str(self.issueconfirmednotifications) + \
               "\nlifetime: " + str(self.lifetime)

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        # tag 0 subscriberprocessidentifier
        if ASN1.decode_is_context_tag(buffer, offset+leng, 0):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.subscriberprocessidentifier) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1
        else:
            return -1
        # tag 1 monitoredobjectidentifier
        if ASN1.decode_is_context_tag(buffer, offset+leng, 1):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            self.monitoredobjectidentifier = BACnetObjectIdentifier()
            leng += self.monitoredobjectidentifier.ASN1decode(buffer, offset+leng,len_value)
        else:
            return -1

        if leng < apdu_len:
            #tag 2 issueconfirmednotifications optional
            if ASN1.decode_is_context_tag(buffer, offset + leng, 2):
                (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                (leng1, value) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
                leng += leng1
                self.issueconfirmednotifications = bool(value > 0)


        if leng < apdu_len:
            #tag 3 lifetime optional
            if ASN1.decode_is_context_tag(buffer, offset + leng, 3):
                (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                (leng1, self.lifetime) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
                leng += leng1

        return leng

class AtomicWriteFile_Request:
    def __init__(self, fileidentifier : BACnetObjectIdentifier =None, accessmethod=None):
        self.fileidentifier = fileidentifier
        self.accessmethod = accessmethod

    def __str__(self):
        return "fileidentifier: "+str(self.fileidentifier)+"\naccessmethod: "+str(self.accessmethod)

    class streamaccess:
        def __init__(self, filestartposition: int = None, filedata : bytes =None):
            self.filestartposition = filestartposition
            self.filedata = filedata

        def __str__(self):
            return "\nstreamaccess"+"\nfilestartposition: "+str(self.filestartposition)+"\nfiledata: 0x"+str(self.filedata.hex())

    class recordaccess:
        def __init__(self, filestartrecord: int = None, recordcount :int =None, filerecorddata : [] = None):
            self.filestartrecord   = filestartrecord
            self.recordcount = recordcount
            self.filerecorddata = filerecorddata

        def __str__(self):
            ret = "\nrecordaccess"+"\nfilestartrecord: "+str(self.filestartrecord)+"\nrecordcount: "+str(self.recordcount)
            for val in self.filerecorddata:
                ret += "\ndata: "+str(bytes(val).hex())
            return ret

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        # fileidentifier
        (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        leng += leng1
        if tag_number == BACnetApplicationTags.BACNETOBJECTIDENTIFIER:
            self.fileidentifier = BACnetObjectIdentifier()
            leng += self.fileidentifier.ASN1decode(buffer, offset + leng, len_value)
        else:
            return -1

        if ASN1.decode_is_opening_tag_number(buffer, offset+leng, 0):
            # stream-access
            self.accessmethod :AtomicWriteFile_Request.streamaccess = AtomicWriteFile_Request.streamaccess()
            leng += 1

            # filestartposition
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            if tag_number == BACnetApplicationTags.SIGNED_INT:
                (leng1, self.accessmethod.filestartposition) = ASN1.decode_signed(buffer, offset + leng, len_value)
                leng += leng1
            else:
                return -1

            # filedata
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            if tag_number == BACnetApplicationTags.OCTET_STRING:
                (leng1, self.accessmethod.filedata) = ASN1.decode_octet_string(buffer, offset+leng, len_value)
                leng += leng1
            else:
                return -1
            if not ASN1.decode_is_closing_tag_number(buffer, offset+leng, 0):
                return -1

            leng += 1
        elif ASN1.decode_is_opening_tag_number(buffer, offset+leng, 1):
            # record-access
            self.accessmethod :AtomicWriteFile_Request.recordaccess = AtomicWriteFile_Request.recordaccess()
            leng += 1

            # file-start-record
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            if tag_number == BACnetApplicationTags.SIGNED_INT:
                (leng1, self.accessmethod.filestartrecord) = ASN1.decode_signed(buffer, offset + leng, len_value)
                leng += leng1
            else:
                return -1

            # record-count
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            if tag_number == BACnetApplicationTags.UNSIGNED_INT:
                (leng1, self.accessmethod.recordcount) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
                leng += leng1
            else:
                return -1

            #filerecorddata
            self.accessmethod.filerecorddata = []

            for i in range (0,self.accessmethod.recordcount):
                (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                if tag_number == BACnetApplicationTags.OCTET_STRING:
                    (leng1, data) = ASN1.decode_octet_string(buffer, offset + leng, len_value)
                    leng += leng1
                    self.accessmethod.filerecorddata.append(data)
                else:
                    return -1


            if not ASN1.decode_is_closing_tag_number(buffer, offset+leng, 1):
                return -1
            leng += 1
        else:
            return -1

        return leng


class AtomicReadFile_Request:
    def __init__(self, fileidentifier : BACnetObjectIdentifier =None, accessmethod=None):
        self.fileidentifier = fileidentifier
        self.accessmethod = accessmethod

    def __str__(self):
        return "fileidentifier: "+str(self.fileidentifier)+"\naccessmethod: "+str(self.accessmethod)

    class streamaccess:
        def __init__(self, filestartposition: int = None, requestedoctetcount :int =None):
            self.filestartposition = filestartposition
            self.requestedoctetcount = requestedoctetcount

        def __str__(self):
            return "\nstreamaccess"+"\nfilestartposition: "+str(self.filestartposition)+"\nrequestedoctetcount: "+str(self.requestedoctetcount)

    class recordaccess:
        def __init__(self, filestartrecord: int = None, requestedrecordcount :int =None):
            self.filestartrecord   = filestartrecord
            self.requestedrecordcount = requestedrecordcount

        def __str__(self):
            return "\nrecordaccess"+"\nfilestartrecord: "+str(self.filestartrecord)+"\nrequestedrecordcount: "+str(self.requestedrecordcount)

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0

        # fileidentifier
        (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        leng += leng1
        if tag_number == BACnetApplicationTags.BACNETOBJECTIDENTIFIER:
            self.fileidentifier = BACnetObjectIdentifier()
            leng += self.fileidentifier.ASN1decode(buffer, offset + leng, len_value)
        else:
            return -1

        if ASN1.decode_is_opening_tag_number(buffer, offset+leng, 0):
            # stream-access
            self.accessmethod :AtomicReadFile_Request.streamaccess = AtomicReadFile_Request.streamaccess()
            leng += 1

            # filestartposition
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            if tag_number == BACnetApplicationTags.SIGNED_INT:
                (leng1, self.accessmethod.filestartposition)= ASN1.decode_signed(buffer, offset + leng, len_value)
                leng += leng1
            else:
                return -1

            # requested-octet-count
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            if tag_number == BACnetApplicationTags.UNSIGNED_INT:
                (leng1, self.accessmethod.requestedoctetcount) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
                leng += leng1
            else:
                return -1
            leng += 1
        elif ASN1.decode_is_opening_tag_number(buffer, offset+leng, 1):
            # record-access
            self.accessmethod :AtomicReadFile_Request.recordaccess = AtomicReadFile_Request.recordaccess()
            leng += 1

            #filestartrecord
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            if tag_number == BACnetApplicationTags.SIGNED_INT:
                (leng1, self.accessmethod.filestartrecord) = ASN1.decode_signed(buffer, offset + leng, len_value)
                leng += leng1
            else:
                return -1
            # requested-octet-count
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            if tag_number == BACnetApplicationTags.UNSIGNED_INT:
                (leng1, self.accessmethod.requestedrecordcount) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
                leng += leng1
            else:
                return -1
            leng += 1
        else:
            return -1

        return leng

class COVNotification_Request:
    def __init__(self, subscriberprocessidentifier=None, initiatingdeviceidentifier=None, monitoredobjectidentifier=None, timeremaining=None, listofvalues=None):
        self.subscriberprocessidentifier  = subscriberprocessidentifier
        self.initiatingdeviceidentifier = initiatingdeviceidentifier
        self.monitoredobjectidentifier = monitoredobjectidentifier
        self.timeremaining = timeremaining
        self.listofvalues = listofvalues

    def __str__(self):
        ret = "\nsubscriberprocessidentifier: " + str(self.subscriberprocessidentifier) + \
              "\ninitiatingdeviceidentifier: " + str(self.initiatingdeviceidentifier) + \
              "\nmonitoredobjectidentifier: " + str(self.monitoredobjectidentifier) + \
              "\ntimeremaining: " + str(self.timeremaining)
        for value in self.listofvalues:
              ret += "\n---------value---------\n" + str(value)
        return ret

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0

        # tag 0 - subscriberProcessIdentifier */
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 0)):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.subscriberprocessidentifier) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1

        else:
            return -1

        # tag 1 - initiatingDeviceIdentifier */
        self.initiatingdeviceidentifier = BACnetObjectIdentifier()
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 1)):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            leng += BACnetObjectIdentifier.ASN1decode(self.initiatingdeviceidentifier,buffer, offset + leng,len_value)


        else:
            return -1

        # tag 2 - monitoredObjectIdentifier */
        self.monitoredobjectidentifier = BACnetObjectIdentifier()
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 2)):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            leng += BACnetObjectIdentifier.ASN1decode(self.monitoredobjectidentifier, buffer, offset + leng, len_value)

        else:
            return -1

        # tag 3 - timeRemaining */
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 3)):

            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.timeremaining) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1

        else:
            return -1

        # tag 4: opening context tag - listOfValues

        if not (ASN1.decode_is_opening_tag_number(buffer, offset + leng, 4)):
            return -1

        # a tag number of 4 is not extended so only one octet */
        leng += 1


        _values = []
        while not ASN1.decode_is_closing_tag_number(buffer, offset + leng, 4):
            new_entry = BACnetPropertyValue()

            leng += BACnetPropertyValue.ASN1decode(new_entry, buffer, offset+leng, apdu_len, self.monitoredobjectidentifier)
            _values.append(new_entry)


        self.listofvalues = _values
        return leng

class WriteProperty_Request:
    def __init__(self,objectidentifier:BACnetObjectIdentifier = None, propertyidentifier:BACnetPropertyIdentifier = None, propertyarrayindex:int = None,propertyvalue = None,priority:int= None):
        self.objectidentifier = objectidentifier
        self.propertyidentifier = propertyidentifier
        self.propertyarrayindex = propertyarrayindex
        self.propertyvalue = propertyvalue
        self.priority = priority

    def __str__(self):
        buffer = "\nobjectidentifier: "+str(self.objectidentifier)+\
               "\npropertyidentifier: " + str(self.propertyidentifier)+\
               "\npropertyarrayindex: " + str(self.propertyarrayindex)
        for val in self.propertyvalue:
            buffer += "\npropertyvalue: " + str(val)
        buffer += "\npriority: " + str(self.priority)
        return buffer

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        # objectidentifier
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 0)):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            self.objectidentifier = BACnetObjectIdentifier()
            leng += self.objectidentifier.ASN1decode(buffer, offset + leng, len_value)
        else:
            return -1

        # propertyidentifier
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 1)):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.propertyidentifier) = ASN1.decode_enumerated(buffer, offset + leng, len_value, prop_id = BACnetPropertyIdentifier.PROPERTY_LIST)
            leng += leng1
        else:
            return -1

        # propertyarrayindex optional
        if leng < apdu_len:
            if (ASN1.decode_is_context_tag(buffer, offset + leng, 2)):
                (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                (leng1, self.propertyarrayindex) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
                leng += leng1

        #property-value
        if (ASN1.decode_is_opening_tag_number(buffer, offset + leng, 3)):
            leng += 1
            _value_list = []
            while ((apdu_len - leng) > 1 and not ASN1.decode_is_closing_tag_number(buffer, offset + leng, 3)):
                (leng1, b_value) = ASN1.bacapp_decode_application_data(buffer, offset + leng, apdu_len + offset, self.objectidentifier.Type, self.propertyidentifier)

                if leng1 <= 0:
                    return -1
                leng += leng1
                _value_list.append(b_value)
        else:
            return -1

        self.propertyvalue = _value_list
        leng += 1
        #priority
        if leng < apdu_len:
            if (ASN1.decode_is_context_tag(buffer, offset + leng, 4)):
                (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                (leng1, self.priority) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
                leng += leng1

        return leng

class WritePropertyMultiple_Request:
    def __init__(self, listofwriteaccessspecifications : [] = None):
        self.listofwriteaccessspecifications = listofwriteaccessspecifications

    def __str__(self):
        ret = ""
        for val in self.listofwriteaccessspecifications:
            ret += "\n" + str(val)
        return ret

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        self.listofwriteaccessspecifications = []
        while (apdu_len - leng) > 1:
            was = WriteAccessSpecification()
            leng += was.ASN1decode(buffer,offset+leng,apdu_len-leng)
            self.listofwriteaccessspecifications.append(was)
        return leng

class ReadPropertyMultiple_Request:
    def __init__(self, listofreadaccessspecifications : [] = None):
        self.listofreadaccessspecifications = listofreadaccessspecifications

    def __str__(self):
        ret = ""
        for val in self.listofreadaccessspecifications:
            ret += "\n"+str(val)
        return ret

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        self.listofreadaccessspecifications = []
        while (apdu_len - leng) > 1:
            ras = ReadAccessSpecification()
            leng += ras.ASN1decode(buffer,offset+leng,apdu_len-leng)
            self.listofreadaccessspecifications.append(ras)
        return leng

class ReadProperty_Request(ASN1encodeInterface):
    def __init__(self, objectidentifier:BACnetObjectIdentifier= None, propertyidentifier:BACnetPropertyIdentifier= None,propertyarrayindex:int =None):
        self.objectidentifier = objectidentifier
        self.propertyidentifier = propertyidentifier
        self.propertyarrayindex = propertyarrayindex

    def __str__(self):
        return "\nobjectidentifier: "+str(self.objectidentifier)+"\npropertyidentifier: "+str(self.propertyidentifier)+ \
               "\npropertyarrayindex: " + str(self.propertyarrayindex)

    def ASN1encode(self):
        ret = self.objectidentifier.ASN1encode_context(0)
        ret += ASN1.encode_context_enumerated(1, self.propertyidentifier)
        if self.propertyarrayindex != None:
            ret += ASN1.encode_context_unsigned(2, self.propertyarrayindex)
        return ret

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        # objectidentifier
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 0)):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            self.objectidentifier = BACnetObjectIdentifier()
            leng += self.objectidentifier.ASN1decode(buffer, offset+leng, len_value)
        else:
            return -1
        # propertyidentifier
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 1)):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.propertyidentifier) = ASN1.decode_enumerated(buffer, offset+leng, len_value, prop_id = BACnetPropertyIdentifier.PROPERTY_LIST)
            leng += leng1
        else:
            return -1

        # propertyarrayindex optional
        if leng < apdu_len:
            if (ASN1.decode_is_context_tag(buffer, offset + leng, 2)):
                (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                (leng1, self.propertyarrayindex) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
                leng += leng1

        return leng



class EventNotification_Request:
    def __init__(self, processIdentifier : int=None,
                 initiatingDeviceIdentifier : BACnetObjectIdentifier=None,
                 eventObjectIdentifier: BACnetObjectIdentifier=None,
                 timeStamp : BACnetTimeStamp =None,
                 notificationClass :int=None,
                 priority :int =None,
                 eventType :BACnetEventType=None,
                 messageText :str=None,
                 notifyType : BACnetNotifyType=None,
                 ackRequired : bool=None,
                 fromState : BACnetEventState =None,
                 toState : BACnetEventState =None,
                 eventValues:BACnetNotificationParameters=None
                 ):
        self.processIdentifier = processIdentifier
        self.initiatingDeviceIdentifier = initiatingDeviceIdentifier
        self.eventObjectIdentifier = eventObjectIdentifier
        self.timeStamp = timeStamp
        self.notificationClass = notificationClass
        self.priority = priority
        self.eventType = eventType
        self.messageText = messageText
        self.notifyType = notifyType
        self.ackRequired = ackRequired
        self.fromState = fromState
        self.toState = toState
        self.eventValues = eventValues

    def __str__(self):
        ret = "processIdentifier: " + str(self.processIdentifier) + \
              "\ninitiatingDeviceIdentifier: " + str(self.initiatingDeviceIdentifier) + \
              "\neventObjectIdentifier: " + str(self.eventObjectIdentifier) + \
              "\ntimeStamp: " + str(self.timeStamp) + \
              "\nnotification_Class: " + str(self.notificationClass) + \
              "\npriority: " + str(self.priority) + \
              "\neventType: " + str(self.eventType)
        if self.messageText != None:
            ret += "\nmessageText: " + str(self.messageText)
        ret += "\nnotifyType: " + str(self.notifyType)
        if self.ackRequired != None:
            ret += "\nackRequired: " + str(self.ackRequired)
        if self.fromState != None:
            ret += "\nfromState: " + str(self.fromState)
        ret += "\ntoState: " + str(self.toState)
        if self.eventValues != None:
            ret += "\neventValues: " + str(self.eventValues)
        return ret

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0

        # tag 0 - processIdentifier
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 0)):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.processIdentifier) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1
        else:
            return -1

        # tag 1 - initiatingObjectIdentifier
        self.initiatingDeviceIdentifier = BACnetObjectIdentifier()
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 1)):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            leng += BACnetObjectIdentifier.ASN1decode(self.initiatingDeviceIdentifier, buffer, offset + leng, len_value)
        else:
            return -1

        # tag 2 - eventObjectIdentifier
        self.eventObjectIdentifier = BACnetObjectIdentifier()
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 2)):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            leng += BACnetObjectIdentifier.ASN1decode(self.eventObjectIdentifier, buffer, offset + leng, len_value)
        else:
            return -1

        # tag 3 - timeStamp
        self.timeStamp = BACnetTimeStamp()
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 3)):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1

            leng += BACnetTimeStamp.ASN1decode(self.timeStamp, buffer, offset + leng, len_value)
            leng += 1

        else:
            return -1

        # tag 4 - noticicationClass
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 4)):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.notificationClass) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1
        else:
            return -1

        # tag 5 - priority
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 5)):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.priority) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1
        else:
            return -1

        # tag 6 - eventType
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 6)):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.eventType) = ASN1.decode_enumerated(buffer, offset + leng, len_value, prop_id =BACnetPropertyIdentifier.EVENT_TYPE)

            leng += leng1

        else:
            return -1

        # tag 7 - messageText optional
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 7)):
            (leng1, self.messageText) = ASN1.decode_context_character_string(buffer, offset + leng, 2000, 7)
            leng += leng1
            # print("messageText ", messageText)

        # tag 8 - notifyType
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 8)):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.notifyType) = ASN1.decode_enumerated(buffer, offset + leng, len_value, prop_id = BACnetPropertyIdentifier.NOTIFY_TYPE)

            leng += leng1

        else:
            return -1


        # only addd values if ALARM or EVENT
        if self.notifyType == BACnetNotifyType.ALARM or self.notifyType == BACnetNotifyType.EVENT:
            # tag 9 ack required optional
            if (ASN1.decode_is_context_tag(buffer, offset + leng, 9)):
                (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                (leng1, value) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
                if value > 0:
                    self.ackRequired = True
                else:
                    self.ackRequired = False
                leng += leng1

            # tag 10 - fromState
            if (ASN1.decode_is_context_tag(buffer, offset + leng, 10)):
                (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                (leng1, self.fromState) = ASN1.decode_enumerated(buffer, offset + leng, len_value, prop_id = BACnetPropertyIdentifier.EVENT_STATE)

                leng += leng1

        #tag 11 - toState
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 11)):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.toState) = ASN1.decode_enumerated(buffer, offset + leng, len_value, prop_id = BACnetPropertyIdentifier.EVENT_STATE)

            leng += leng1
        else:
            return -1

        #tag 12
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 12)):
            leng += 1
            self.eventValues = BACnetNotificationParameters()
            self.eventValues.ASN1decode(buffer, offset + leng, apdu_len-(offset+leng))
            leng += 1

        return leng

    def ASN1encode(self):
        buffer = ASN1.encode_context_unsigned(0, self.processIdentifier)+\
                 self.initiatingDeviceIdentifier.ASN1encode_context(1)+\
                 self.eventObjectIdentifier.ASN1encode_context(2)+\
                 self.timeStamp.ASN1encode_context(3)+\
                 ASN1.encode_context_unsigned(4, self.notificationClass)+\
                 ASN1.encode_context_unsigned(5, self.priority)+\
                 ASN1.encode_context_enumerated(6, self.eventType)
        #messageText optional
        if self.messageText != None:
            buffer += ASN1.encode_context_character_string(7,self.messageText)

        buffer += ASN1.encode_context_enumerated(8, self.notifyType)
        #fixme tag  9 /10 / 11 / 12



        return buffer

class ReadProperty_ACK:
    def __init__(self, objectidentifier:BACnetObjectIdentifier = None, propertyidentifier:BACnetPropertyIdentifier= None, propertyarrayindex:int = None, property_value = None):
        self.object_identifier = objectidentifier
        self.property_identifier = propertyidentifier
        self.property_array_index = propertyarrayindex
        self.property_value = property_value

    def __str__(self):
        ret = "\n\tobject_identifier: "+str(self.object_identifier) + \
              "\n\tproperty_identifier: " + str(self.property_identifier) + \
              "\n\tproperty_array_index: " + str(self.property_array_index)
        if self.property_value != None:
            for val in self.property_value:
                ret += "\n\tproperty_value: " + str(val)
        return ret

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0

        # 0 object_identifier
        if ASN1.decode_is_context_tag(buffer, offset + leng, 0):
            self.object_identifier = BACnetObjectIdentifier()
            leng += self.object_identifier.ASN1decode_context(buffer, offset + leng, apdu_len - leng, 0)
        else:
            return -1

        # 2 propertyidentifier
        if ASN1.decode_is_context_tag(buffer, offset + leng, 1):
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.property_identifier) = ASN1.decode_enumerated(buffer, offset + leng, len_value,
                                                                       prop_id=BACnetPropertyIdentifier.PROPERTY_LIST)

            leng += leng1
        else:
            return -1

        # 2 property_array_index
        if ASN1.decode_is_context_tag(buffer, offset + leng, 2):
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.property_array_index) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1

        # tag 3 property-value
        if ASN1.decode_is_opening_tag_number(buffer, offset + leng, 3):

            leng += 1
            # fixme ABSTRACT-SYNTAX.&Type
            self.property_value = []
            while not ASN1.decode_is_closing_tag_number(buffer, offset + leng, 3) and leng < apdu_len:
                b_value = BACnetValue()
                leng1 = b_value.ASN1decode(buffer, offset + leng, apdu_len-leng, self.object_identifier.Type,
                                           self.property_identifier)
                if leng1 < 0:
                    return -1
                leng += leng1
                self.property_value.append(b_value)
            # if leng > apdu_len return -1
            if ASN1.decode_is_closing_tag_number(buffer, offset + leng, 3):
                leng += 1
            else:
                return -1
        else:
            return -1

        return leng





