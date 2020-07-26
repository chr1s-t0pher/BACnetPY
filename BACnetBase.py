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

from BACnetEnum import *
from bitstring import BitArray
from datetime import datetime, date, time
import enum
import struct
import logging, sys

logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)

class ASN1encodeInterface:
    def ASN1encode(self) -> bytes:
        pass

class Network_Priority(enum.IntEnum):
    Life_Safety_Message = 1
    Critical_Equipment_Message = 2
    Urgent_Message = 3
    Normal_Message = 4


class NetworkLayerMessageType(enum.IntEnum):
    WHO_IS_ROUTER_TO_NETWORK = 0
    I_AM_ROUTER_TO_NETWORK = 1
    I_COULD_BE_ROUTER_TO_NETWORK = 2
    REJECT_MESSAGE_TO_NETWORK = 3
    ROUTER_BUSY_TO_NETWORK = 4
    ROUTER_AVAILABLE_TO_NETWORK = 5
    INIT_RT_TABLE = 6
    INIT_RT_TABLE_ACK = 7
    ESTABLISH_CONNECTION_TO_NETWORK = 8
    DISCONNECT_CONNECTION_TO_NETWORK = 9
    Challenge_Request = 10
    Security_Payload = 11
    Security_Response = 12
    Request_Key_Update = 13
    Update_Key_Set = 14
    Update_Distribution_Key = 15
    Request_Master_Key = 16
    Set_Master_Key = 17
    What_Is_Network_Number = 18
    Network_Number_Is = 19


class BacnetMaxSegments(enum.IntEnum):
    MAX_SEG0 = 0
    MAX_SEG2 = 0x10
    MAX_SEG4 = 0x20
    MAX_SEG8 = 0x30
    MAX_SEG16 = 0x40
    MAX_SEG32 = 0x50
    MAX_SEG64 = 0x60
    MAX_SEG65 = 0x70


class BacnetMaxAdpu(enum.IntEnum):
    MAX_APDU50 = 0
    MAX_APDU128 = 1
    MAX_APDU206 = 2
    MAX_APDU480 = 3
    MAX_APDU1024 = 4
    MAX_APDU1476 = 5


class BacnetPduTypes(enum.IntEnum):
    PDU_TYPE_CONFIRMED_SERVICE_REQUEST = 0
    SERVER = 1
    NEGATIVE_ACK = 2
    SEGMENTED_RESPONSE_ACCEPTED = 2
    MORE_FOLLOWS = 4
    SEGMENTED_MESSAGE = 8
    PDU_TYPE_UNCONFIRMED_SERVICE_REQUEST = 0x10
    PDU_TYPE_SIMPLE_ACK = 0x20
    PDU_TYPE_COMPLEX_ACK = 0x30
    PDU_TYPE_SEGMENT_ACK = 0x40
    PDU_TYPE_ERROR = 0x50
    PDU_TYPE_REJECT = 0x60
    PDU_TYPE_ABORT = 0x70
    PDU_TYPE_MASK = 0xF0


class BacnetCharacterStringEncodings(enum.IntEnum):
    CHARACTER_ANSI_X34 = 0
    CHARACTER_UTF8 = 0
    CHARACTER_MS_DBCS = 1
    CHARACTER_JISC_6226 = 2
    CHARACTER_JISX_0208 = 2
    CHARACTER_UCS4 = 3
    CHARACTER_UCS2 = 4
    CHARACTER_ISO8859 = 5


class BACnetApplicationTags(enum.IntEnum):
    NULL = 0
    BOOLEAN = 1
    UNSIGNED_INT = 2
    SIGNED_INT = 3
    REAL = 4
    DOUBLE = 5
    OCTET_STRING = 6
    CHARACTER_STRING = 7
    BIT_STRING = 8
    ENUMERATED = 9
    DATE = 10
    TIME = 11
    BACNETOBJECTIDENTIFIER = 12
    RESERVE1 = 13
    RESERVE2 = 14
    RESERVE3 = 15


class BacnetNpduControls(enum.IntEnum):
    PriorityNormalMessage = 0
    PriorityUrgentMessage = 1
    PriorityCriticalMessage = 2
    PriorityLifeSafetyMessage = 3
    ExpectingReply = 4
    SourceSpecified = 8
    DestinationSpecified = 32
    NetworkLayerMessage = 128


class BacnetNetworkMessageTypes(enum.IntEnum):
    NETWORK_MESSAGE_WHO_IS_ROUTER_TO_NETWORK = 0
    NETWORK_MESSAGE_I_AM_ROUTER_TO_NETWORK = 1
    NETWORK_MESSAGE_I_COULD_BE_ROUTER_TO_NETWORK = 2
    NETWORK_MESSAGE_REJECT_MESSAGE_TO_NETWORK = 3
    NETWORK_MESSAGE_ROUTER_BUSY_TO_NETWORK = 4
    NETWORK_MESSAGE_ROUTER_AVAILABLE_TO_NETWORK = 5
    NETWORK_MESSAGE_INIT_RT_TABLE = 6
    NETWORK_MESSAGE_INIT_RT_TABLE_ACK = 7
    NETWORK_MESSAGE_ESTABLISH_CONNECTION_TO_NETWORK = 8
    NETWORK_MESSAGE_DISCONNECT_CONNECTION_TO_NETWORK = 9
    NETWORK_MESSAGE_Challenge_Request = 10
    NETWORK_MESSAGE_Security_Payload = 11
    NETWORK_MESSAGE_Security_Response = 12
    NETWORK_MESSAGE_Request_Key_Update = 13
    NETWORK_MESSAGE_Update_Key_Set = 14
    NETWORK_MESSAGE_Update_Distribution_Key = 15
    NETWORK_MESSAGE_Request_Master_Key = 16
    NETWORK_MESSAGE_Set_Master_Key = 17
    NETWORK_MESSAGE_What_Is_Network_Number = 18
    NETWORK_MESSAGE_Network_Number_Is = 19


class error_class_enum(enum.IntEnum):
    device = 0
    object = 1
    property = 2
    resources = 3
    security = 4
    services = 5
    vt = 6
    communication = 7


class error_code_enum(enum.IntEnum):
    other = 0
    authentication_failed = 1  # formerly: removed version 1 revision 11
    configuration_in_progress = 2
    device_busy = 3
    dynamic_creation_not_supported = 4
    file_access_denied = 5
    incompatible_security_levels = 6  # formerly:removed in version 1 revision 11
    inconsistent_parameters = 7
    inconsistent_selection_criterion = 8
    invalid_data_type = 9
    invalid_file_access_method = 10
    invalid_file_start_position = 11
    invalid_operator_name = 12  # formerly:removed in version 1 revision 11
    invalid_parameter_data_type = 13
    invalid_timestamp = 14
    key_generation_error = 15  # formerly:removed in version 1 revision 11
    missing_required_parameter = 16
    no_objects_of_specified_type = 17
    no_space_for_object = 18
    no_space_to_add_list_element = 19
    no_space_to_write_property = 20
    no_vt_sessions_available = 21
    property_is_not_a_list = 22
    object_deletion_not_permitted = 23
    object_identifier_already_exists = 24
    operational_problem = 25
    password_failure = 26
    read_access_denied = 27
    security_not_supported = 28  # formerly:removed in version 1 revision 11
    service_request_denied = 29
    timeout = 30
    unknown_object = 31
    unknown_property = 32
    # this enumeration was removed = 33
    unknown_vt_class = 34
    unknown_vt_session = 35
    unsupported_object_type = 36
    value_out_of_range = 37
    vt_session_already_closed = 38
    vt_session_termination_failure = 39
    write_access_denied = 40
    character_set_not_supported = 41
    invalid_array_index = 42
    cov_subscription_failed = 43
    not_cov_property = 44
    optional_functionality_not_supported = 45
    invalid_configuration_data = 46
    datatype_not_supported = 47
    duplicate_name = 48
    duplicate_object_id = 49
    property_is_not_an_array = 50
    abort_buffer_overflow = 51
    abort_invalid_apdu_in_this_state = 52
    abort_preempted_by_higher_priority_task = 53
    abort_segmentation_not_supported = 54
    abort_proprietary = 55
    abort_other = 56
    invalid_tag = 57
    network_down = 58
    reject_buffer_overflow = 59
    reject_inconsistent_parameters = 60
    reject_invalid_parameter_data_type = 61
    reject_invalid_tag = 62
    reject_missing_required_parameter = 63
    reject_parameter_out_of_range = 64
    reject_too_many_arguments = 65
    reject_undefined_enumeration = 66
    reject_unrecognized_service = 67
    reject_proprietary = 68
    reject_other = 69
    unknown_device = 70
    unknown_route = 71
    value_not_initialized = 72
    invalid_event_state = 73
    no_alarm_configured = 74
    log_buffer_full = 75
    logged_value_purged = 76
    no_property_specified = 77
    not_configured_for_triggered_logging = 78
    unknown_subscription = 79
    parameter_out_of_range = 80
    list_element_not_found = 81
    busy = 82
    communication_disabled = 83
    success = 84
    access_denied = 85
    bad_destination_address = 86
    bad_destination_device_id = 87
    bad_signature = 88
    bad_source_address = 89
    bad_timestamp = 90
    cannot_use_key = 91
    cannot_verify_message_id = 92
    correct_key_revision = 93
    destination_device_id_required = 94
    duplicate_message = 95
    encryption_not_configured = 96
    encryption_required = 97
    incorrect_key = 98
    invalid_key_data = 99
    key_update_in_progress = 100
    malformed_message = 101
    not_key_server = 102
    security_not_configured = 103
    source_security_required = 104
    too_many_keys = 105
    unknown_authentication_type = 106
    unknown_key = 107
    unknown_key_revision = 108
    unknown_source_message = 109
    not_router_to_dnet = 110
    router_busy = 111
    unknown_network_message = 112
    message_too_long = 113
    security_error = 114
    addressing_error = 115
    write_bdt_failed = 116
    read_bdt_failed = 117
    register_foreign_device_failed = 118
    read_fdt_failed = 119
    delete_fdt_entry_failed = 120
    distribute_broadcast_failed = 121
    unknown_file_size = 122
    abort_apdu_too_long = 123
    abort_application_exceeded_reply_time = 124
    abort_out_of_resources = 125
    abort_tsm_timeout = 126
    abort_window_size_out_of_range = 127
    file_full = 128
    inconsistent_configuration = 129
    inconsistent_object_type = 130
    internal_error = 131
    not_configured = 132
    out_of_memory = 133
    value_too_long = 134
    abort_insufficient_security = 135
    abort_security_error = 136
    duplicate_entry = 137
    invalid_value_in_this_state = 138


class BACnetObjectIdentifier():
    def __init__(self, Type: BACnetObjectType = None,
                 Instance: int = None):
        self.Type = Type
        self.Instance = Instance

    def __str__(self):
        return str(self.Type) + ":" + str(self.Instance)

    def ASN1decode(self, buffer, offset, apdu_len) -> int:
        leng = 0
        (leng1, value) = ASN1.decode_unsigned(buffer, offset + leng, 4)
        leng += leng1
        self.Instance = (value & ASN1.BACNET_MAX_INSTANCE)

        self.Type = BACnetObjectType((int(value) >> ASN1.BACNET_INSTANCE_BITS) & ASN1.BACNET_MAX_OBJECT)

        return leng

    def ASN1decode_context(self, buffer, offset, apdu_len, tag_number) -> int:
        leng = 0
        if (ASN1.decode_is_context_tag(buffer, offset + leng, tag_number)):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            leng += self.ASN1decode(buffer, offset + leng, len_value)
        else:
            return -1

        return leng

    def ASN1encode(self) -> bytes:
        return (((self.Type & ASN1.BACNET_MAX_OBJECT) << ASN1.BACNET_INSTANCE_BITS) | (
                    self.Instance & ASN1.BACNET_MAX_INSTANCE)).to_bytes(4, byteorder='big')

    def ASN1encode_app(self) -> bytes:
        tmp = self.ASN1encode()
        return ASN1.encode_tag(BACnetApplicationTags.BACNETOBJECTIDENTIFIER, False, len(tmp)) + tmp

    def ASN1encode_context(self, tag_number: int) -> bytes:
        tmp = self.ASN1encode()
        return ASN1.encode_tag(tag_number, True, len(tmp)) + tmp


class BACnetDateTime(ASN1encodeInterface):
    def __init__(self, DATE: date = None, TIME: time = None):
        self.DATE = DATE
        self.TIME = TIME

    def __str__(self):
        return str(datetime.combine(self.DATE, self.TIME))

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        (leng1, self.DATE) = ASN1.decode_application_date(buffer, offset + leng)
        leng += leng1
        (leng1, self.TIME) = ASN1.decode_application_time(buffer, offset + leng)
        leng += leng1
        return leng

    def ASN1encode(self):
        return ASN1.encode_application_date(self.DATE) + ASN1.encode_application_time(self.TIME)


#todo BACnetPropertyValue add ASN1encodeInterface
class BACnetPropertyValue(ASN1encodeInterface):
    def __init__(self, identifier=None, arrayindex=None, value=None, priority=None):
        self.identifier = identifier
        self.arrayindex = arrayindex
        self.value = value
        self.priority = priority

    def __str__(self):
        ret = "identifier: " + str(self.identifier)
        if self.arrayindex != None:
            ret += "\narrayindex: " + str(self.arrayindex)
        for val in self.value:
            ret += "\n\tvalue: " + str(val)

        if self.priority != None:
            ret += "\npriority: " + str(self.priority)
        return ret

    def ASN1decode(self, buffer, offset, apdu_len, objectidentifier):
        leng = 0
        # tag 0 propertyidentifier
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 0)):
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.identifier) = ASN1.decode_enumerated(buffer, offset + leng, len_value,
                                                              prop_id=BACnetPropertyIdentifier.PROPERTY_LIST)

            leng += leng1
        else:
            return -1

        # tag 1 - propertyArrayIndex OPTIONAL
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 1)):
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.arrayindex) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1

        # Value
        if not ASN1.decode_is_opening_tag_number(buffer, offset + leng, 2):
            return -1

        # a tag number of 2 is not extended so only one octet */
        leng += 1
        b_values = []
        while not ASN1.decode_is_closing_tag_number(buffer, offset + leng, 2):
            b_value = BACnetValue()
            leng1 = b_value.ASN1decode(buffer, offset + leng, apdu_len - leng,
                                       objectidentifier.Type,
                                       self.identifier)
            if leng1 < 0:
                return -1
            leng += leng1

            b_values.append(b_value)

        self.value = b_values

        # a tag number of 2 is not extended so only one octet */
        leng += 1

        # tag 3 - priority OPTIONAL */
        if ASN1.decode_is_context_tag(buffer, offset + leng, 3):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.priority) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1

        # else:
        #   self.priority = ASN1.BACNET_NO_PRIORITY

        return leng


# todo Error add ASN1encodeInterface
class BACnetError(ASN1encodeInterface):
    # Error renamed to BACnetError
    def __init__(self, error_class: error_class_enum = None,
                 error_code: error_code_enum = None):
        self.error_class = error_class
        self.error_code = error_code

    def __str__(self):
        return "\n"+str(self.error_class) + ": " + str(self.error_code)

    def ASN1decode(self, buffer, offset, apdu_len) -> int:
        leng = 0
        # error_class
        leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        leng += leng1
        if tag_number == BACnetApplicationTags.ENUMERATED:
            (leng1, e_val) = ASN1.decode_enumerated(buffer, offset + leng, len_value)
            leng += leng1
            self.error_class = error_class_enum(e_val)

        else:
            return -1

        # error_code
        leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        leng += leng1
        if tag_number == BACnetApplicationTags.ENUMERATED:
            (leng1, e_val) = ASN1.decode_enumerated(buffer, offset + leng, len_value)
            leng += leng1
            self.error_code = error_code_enum(e_val)

        else:
            return -1

        return leng


# todo is ABSTRACT-SYNTAX.&Type
class BACnetValue(ASN1encodeInterface):
    def __init__(self, tag=None, value=None):
        self.Tag = tag
        self.Value = value

    def __str__(self):
        if self.Tag == None:
            return "\n\t\tContext Specific: " + str(self.Value)
        else:
            return str(self.Tag) + ":" + str(self.Value)

    def ASN1decode(self, buffer, offset, apdu_len, obj_type: BACnetObjectType = None,
                   prop_id: BACnetPropertyIdentifier = None):
        leng = 0

        # FIXME: use max_apdu_len!

        if not (ASN1.IS_CONTEXT_SPECIFIC(buffer[offset])):
            (tag_len, tag_number, len_value_type) = ASN1.decode_tag_number_and_value(buffer, offset)
            if tag_len > 0:
                self.Tag = BACnetApplicationTags(tag_number)
                leng += tag_len

                decode_len = 0

                if self.Tag == BACnetApplicationTags.NULL:
                    self.Value = None
                    decode_len = 0
                    # fixme fix null type nothing else to do, some Error occurs!!!!
                elif self.Tag == BACnetApplicationTags.BOOLEAN:
                    if len_value_type > 0:
                        self.Value = True
                    else:
                        self.Value = False
                elif self.Tag == BACnetApplicationTags.UNSIGNED_INT:
                    # some context specific!
                    if prop_id == BACnetPropertyIdentifier.ROUTING_TABLE:
                        # fixme untested! not supported by CBMS Devicesimulator
                        self.Tag = None
                        self.Value = BACnetRouterEntry()
                        leng -= 1
                        decode_len = self.Value.ASN1decode(buffer, offset + leng, apdu_len)
                    elif prop_id == BACnetPropertyIdentifier.ACTIVE_VT_SESSIONS:
                        self.Tag = None
                        self.Value = BACnetVTSession()
                        leng -= 1
                        decode_len = self.Value.ASN1decode(buffer, offset + leng, apdu_len)
                    elif prop_id == BACnetPropertyIdentifier.THREAT_LEVEL or prop_id == BACnetPropertyIdentifier.THREAT_AUTHORITY:
                        self.Tag = None
                        self.Value = BACnetAccessThreatLevel()
                        leng -= 1
                        decode_len = self.Value.ASN1decode(buffer, offset + leng, apdu_len)
                    else:
                        (decode_len, uint_value) = ASN1.decode_unsigned(buffer, offset+leng, len_value_type)
                        self.Value = uint_value
                elif self.Tag == BACnetApplicationTags.SIGNED_INT:
                    (decode_len, int_value) = ASN1.decode_signed(buffer, offset+leng, len_value_type)
                    self.Value = int_value
                elif self.Tag == BACnetApplicationTags.REAL:
                    (decode_len, float_value) = ASN1.decode_real_safe(buffer, offset+leng, len_value_type)
                    self.Value = float_value
                elif self.Tag == BACnetApplicationTags.DOUBLE:
                    (decode_len, double_value) = ASN1.decode_double_safe(buffer, offset+leng, len_value_type)
                    self.Value = double_value
                elif self.Tag == BACnetApplicationTags.OCTET_STRING:
                    (decode_len, octet_value) = ASN1.decode_octet_string(buffer, offset+leng, len_value_type)
                    self.Value = octet_value
                elif self.Tag == BACnetApplicationTags.CHARACTER_STRING:
                    (decode_len, string_value) = ASN1.decode_character_string(buffer, offset+leng, apdu_len, len_value_type)
                    self.Value = string_value
                elif self.Tag == BACnetApplicationTags.BIT_STRING:
                    # some context specific!
                    if prop_id == BACnetPropertyIdentifier.RECIPIENT_LIST:
                        self.Tag = None
                        self.Value = BACnetDestination()
                        leng -= 1
                        decode_len = self.Value.ASN1decode(buffer, offset + leng, apdu_len)
                    elif prop_id == BACnetPropertyIdentifier.STATUS_FLAGS:
                        self.Tag = None

                        bit_value = BACnetStatusFlags()
                        decode_len = bit_value.ASN1decode(buffer, offset, len_value_type)
                        self.Value = bit_value
                    elif prop_id == BACnetPropertyIdentifier.EVENT_ENABLE or \
                            prop_id == BACnetPropertyIdentifier.ACKED_TRANSITIONS:
                        self.Tag = None

                        bit_value = BACnetEventTransitionBits()
                        decode_len = bit_value.ASN1decode(buffer, offset, len_value_type)
                        self.Value = bit_value
                    elif prop_id == BACnetPropertyIdentifier.LIMIT_ENABLE:
                        self.Tag = None

                        bit_value = BACnetLimitEnable()
                        decode_len = bit_value.ASN1decode(buffer, offset, len_value_type)
                        self.Value = bit_value
                    elif prop_id == BACnetPropertyIdentifier.PROTOCOL_OBJECT_TYPES_SUPPORTED:
                        self.Tag = None

                        bit_value = BACnetObjectTypesSupported()
                        decode_len = bit_value.ASN1decode(buffer, offset, len_value_type)
                        self.Value = bit_value
                    elif prop_id == BACnetPropertyIdentifier.PROTOCOL_SERVICES_SUPPORTED:
                        self.Tag = None

                        bit_value = BACnetServicesSupported()
                        decode_len = bit_value.ASN1decode(buffer, offset, len_value_type)
                        self.Value = bit_value
                    else:
                        bit_value = BACnetBitString()
                        decode_len = bit_value.ASN1decode(buffer, offset, len_value_type)
                        self.Value = bit_value


                elif self.Tag == BACnetApplicationTags.ENUMERATED:

                    (decode_len, uint_value) = ASN1.decode_enumerated(buffer, offset+leng, len_value_type, obj_type,
                                                                prop_id)
                    self.Value = uint_value
                elif self.Tag == BACnetApplicationTags.DATE:
                    # some context specific!
                    if prop_id == BACnetPropertyIdentifier.EFFECTIVE_PERIOD:
                        self.Tag = None
                        self.Value = BACnetDateRange()
                        leng -= 1
                        decode_len = self.Value.ASN1decode(buffer, offset+leng, apdu_len)
                    elif prop_id == BACnetPropertyIdentifier.MINIMUM_VALUE_TIMESTAMP or\
                            prop_id == BACnetPropertyIdentifier.MAXIMUM_VALUE_TIMESTAMP or\
                            prop_id == BACnetPropertyIdentifier.CHANGE_OF_STATE_TIME or\
                            prop_id == BACnetPropertyIdentifier.TIME_OF_STATE_COUNT_RESET or\
                            prop_id == BACnetPropertyIdentifier.TIME_OF_ACTIVE_TIME_RESET or\
                            prop_id == BACnetPropertyIdentifier.MODIFICATION_DATE or\
                            prop_id == BACnetPropertyIdentifier.UPDATE_TIME or\
                            prop_id == BACnetPropertyIdentifier.COUNT_CHANGE_TIME or\
                            prop_id == BACnetPropertyIdentifier.START_TIME or\
                            prop_id == BACnetPropertyIdentifier.STOP_TIME or\
                            prop_id == BACnetPropertyIdentifier.LAST_CREDENTIAL_ADDED_TIME or\
                            prop_id == BACnetPropertyIdentifier.LAST_CREDENTIAL_REMOVED_TIME or\
                            prop_id == BACnetPropertyIdentifier.ACTIVATION_TIME or\
                            prop_id == BACnetPropertyIdentifier.EXPIRY_TIME or\
                            prop_id == BACnetPropertyIdentifier.LAST_USE_TIME or\
                            prop_id == BACnetPropertyIdentifier.TIME_OF_STRIKE_COUNT_RESET or\
                            prop_id == BACnetPropertyIdentifier.VALUE_CHANGE_TIME or\
                            ((obj_type == BACnetObjectType.DateTime_Value or obj_type == BACnetObjectType.DateTime_Pattern_Value) and (prop_id == BACnetPropertyIdentifier.PRESENT_VALUE or prop_id == BACnetPropertyIdentifier.RELINQUISH_DEFAULT)):
                        self.Tag = None
                        self.Value = BACnetDateTime()
                        leng -= 1
                        decode_len = self.Value.ASN1decode(buffer, offset + leng, apdu_len)
                    else:
                        (decode_len, date_value) = ASN1.decode_date_safe(buffer, offset+leng, len_value_type)
                        self.Value = date_value;
                elif self.Tag == BACnetApplicationTags.TIME:
                    (decode_len, time_value) = ASN1.decode_bacnet_time_safe(buffer, offset+leng, len_value_type)
                    self.Value = time_value
                elif self.Tag == BACnetApplicationTags.BACNETOBJECTIDENTIFIER:
                    #context specific
                    if prop_id == BACnetPropertyIdentifier.LAST_KEY_SERVER or \
                            prop_id == BACnetPropertyIdentifier.MANUAL_SLAVE_ADDRESS_BINDING or \
                            prop_id == BACnetPropertyIdentifier.SLAVE_ADDRESS_BINDING or\
                            prop_id == BACnetPropertyIdentifier.DEVICE_ADDRESS_BINDING:

                        self.Tag = None
                        self.Value = BACnetAddressBinding()
                        leng -= 1
                        decode_len = self.Value.ASN1decode(buffer, offset + leng, apdu_len)
                    else:
                        (decode_len, object_type, instance) = ASN1.decode_object_id_safe(buffer, offset+leng, len_value_type)
                        self.Value = BACnetObjectIdentifier(object_type, instance)

                if (decode_len < 0):
                    return -1
                leng += decode_len

        else:
            if prop_id == BACnetPropertyIdentifier.BACNET_IP_GLOBAL_ADDRESS or\
                    prop_id == BACnetPropertyIdentifier.FD_BBMD_ADDRESS:
                self.Value = BACnetHostNPort()
                leng += self.Value.ASN1decode(buffer, offset+leng, apdu_len-leng)
            elif prop_id == BACnetPropertyIdentifier.UTC_TIME_SYNCHRONIZATION_RECIPIENTS or\
                    prop_id == BACnetPropertyIdentifier.RESTART_NOTIFICATION_RECIPIENTS or\
                    prop_id == BACnetPropertyIdentifier.TIME_SYNCHRONIZATION_RECIPIENTS or\
                    prop_id == BACnetPropertyIdentifier.COVU_RECIPIENTS:
                self.Value = BACnetRecipient()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.KEY_SETS:
                self.Value = BACnetSecurityKeySet()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.EVENT_TIME_STAMPS or\
                    prop_id == BACnetPropertyIdentifier.LAST_COMMAND_TIME or\
                    prop_id == BACnetPropertyIdentifier.COMMAND_TIME_ARRAY or\
                    prop_id == BACnetPropertyIdentifier.LAST_RESTORE_TIME or\
                    prop_id == BACnetPropertyIdentifier.TIME_OF_DEVICE_RESTART or\
                    prop_id == BACnetPropertyIdentifier.ACCESS_EVENT_TIME or\
                    prop_id == BACnetPropertyIdentifier.UPDATE_TIME:
                #UPDATE_TIME once in context specific BACnetTimeStamp and non context specific BACnetDateTime
                self.Value = BACnetTimeStamp()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.LIST_OF_GROUP_MEMBERS:
                self.Value = ReadAccessSpecification()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.LIST_OF_OBJECT_PROPERTY_REFERENCES:
                self.Value = BACnetDeviceObjectPropertyReference()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.MEMBER_OF or\
                    prop_id == BACnetPropertyIdentifier.ZONE_MEMBERS or\
                    prop_id == BACnetPropertyIdentifier.DOOR_MEMBERS or\
                    prop_id == BACnetPropertyIdentifier.SUBORDINATE_LIST or\
                    prop_id == BACnetPropertyIdentifier.REPRESENTS or\
                    prop_id == BACnetPropertyIdentifier.ACCESS_EVENT_CREDENTIAL or\
                    prop_id == BACnetPropertyIdentifier.ACCESS_DOORS or\
                    prop_id == BACnetPropertyIdentifier.ZONE_TO or\
                    prop_id == BACnetPropertyIdentifier.ZONE_FROM or\
                    prop_id == BACnetPropertyIdentifier.CREDENTIALS_IN_ZONE or\
                    prop_id == BACnetPropertyIdentifier.LAST_CREDENTIAL_ADDED or\
                    prop_id == BACnetPropertyIdentifier.LAST_CREDENTIAL_REMOVED or\
                    prop_id == BACnetPropertyIdentifier.ENTRY_POINTS or\
                    prop_id == BACnetPropertyIdentifier.EXIT_POINTS or\
                    prop_id == BACnetPropertyIdentifier.MEMBERS or\
                    prop_id == BACnetPropertyIdentifier.CREDENTIALS or\
                    prop_id == BACnetPropertyIdentifier.ACCOMPANIMENT or\
                    prop_id == BACnetPropertyIdentifier.BELONGS_TO or\
                    prop_id == BACnetPropertyIdentifier.LAST_ACCESS_POINT or\
                    prop_id == BACnetPropertyIdentifier.ENERGY_METER_REF:
                self.Value = BACnetDeviceObjectReference()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.EVENT_ALGORITHM_INHIBIT_REF or\
                    prop_id == BACnetPropertyIdentifier.INPUT_REFERENCE or\
                    prop_id == BACnetPropertyIdentifier.MANIPULATED_VARIABLE_REFERENCE or\
                    prop_id == BACnetPropertyIdentifier.CONTROLLED_VARIABLE_REFERENCE:
                self.Value = BACnetObjectPropertyReference()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.LOGGING_RECORD:
                self.Value = BACnetAccumulatorRecord()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.ACTION:
                #exists once enumerated (non context specific) and context specific
                self.Value = BACnetActionList()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.SCALE:
                self.Value = BACnetScale()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.LIGHTING_COMMAND:
                self.Value = BACnetLightingCommand()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.PRESCALE:
                self.Value = BACnetPrescale()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.REQUESTED_SHED_LEVEL or\
                    prop_id == BACnetPropertyIdentifier.EXPECTED_SHED_LEVEL or\
                    prop_id == BACnetPropertyIdentifier.ACTUAL_SHED_LEVEL:
                self.Value = BACnetShedLevel()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.LOG_BUFFER and obj_type == BACnetObjectType.TrendLog:
                self.Value = BACnetLogRecord()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.DATE_LIST:
                self.Value = BACnetCalendarEntry()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.LOG_BUFFER and obj_type == BACnetObjectType.Event_Log:
                self.Value = BACnetEventLogRecord()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.PRESENT_VALUE and obj_type == BACnetObjectType.Group:
                self.Value = ReadAccessResult()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.NEGATIVE_ACCESS_RULES or\
                    prop_id == BACnetPropertyIdentifier.POSITIVE_ACCESS_RULES:
                self.Value = BACnetAccessRule()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.TAGS:
                self.Value = BACnetNameValue()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.SUBORDINATE_TAGS:
                self.Value = BACnetNameValueCollection()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.NETWORK_ACCESS_SECURITY_POLICIES:
                self.Value = BACnetNetworkSecurityPolicy()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.PORT_FILTER:
                self.Value = BACnetPortPermission()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.PRIORITY_ARRAY:
                self.Value = BACnetPriorityArray()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.PROCESS_IDENTIFIER_FILTER:
                self.Value = BACnetProcessIdSelection()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif obj_type == BACnetObjectType.Global_Group and prop_id == BACnetPropertyIdentifier.PRESENT_VALUE:
                self.Value = BACnetPropertyAccessResult()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.SETPOINT_REFERENCE:
                self.Value = BACnetSetpointReference()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.EXCEPTION_SCHEDULE:
                self.Value = BACnetSpecialEvent()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.STATE_CHANGE_VALUES:
                self.Value = BACnetTimerStateChangeValue()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.VALUE_SOURCE or\
                    prop_id == BACnetPropertyIdentifier.VALUE_SOURCE_ARRAY:
                self.Value = BACnetValueSource()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.VIRTUAL_MAC_ADDRESS_TABLE:
                self.Value = BACnetVMACEntry()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.ASSIGNED_ACCESS_RIGHTS:
                self.Value = BACnetAssignedAccessRights()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.ASSIGNED_LANDING_CALLS:
                self.Value = BACnetAssignedLandingCalls()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.ACCESS_EVENT_AUTHENTICATION_FACTOR or\
                    (obj_type == BACnetObjectType.Credential_Data_Input and prop_id == BACnetPropertyIdentifier.PRESENT_VALUE):
                self.Value = BACnetAuthenticationFactor()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.SUPPORTED_FORMATS:
                self.Value = BACnetAuthenticationFactorFormat()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.AUTHENTICATION_POLICY_LIST:
                self.Value = BACnetAuthenticationPolicy()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif obj_type == BACnetObjectType.Channel and prop_id == BACnetPropertyIdentifier.PRESENT_VALUE:
                self.Value = BACnetChannelValue()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.ACTIVE_COV_SUBSCRIPTIONS:
                self.Value = BACnetCOVSubscription()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.AUTHENTICATION_FACTORS:
                self.Value = BACnetCredentialAuthenticationFactor()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.WEEKLY_SCHEDULE:
                self.Value = BACnetDailySchedule()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.SUBSCRIBED_RECIPIENTS:
                self.Value = BACnetEventNotificationSubscription()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.EVENT_PARAMETERS:
                self.Value = BACnetEventParameter()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            elif prop_id == BACnetPropertyIdentifier.FAULT_PARAMETERS:
                self.Value = BACnetFaultParameter()
                leng += self.Value.ASN1decode(buffer, offset + leng, apdu_len - leng)
            else:
                logging.debug("context specific!!!! needs to be addded")
                leng = apdu_len

        return leng

    def ASN1encode(self):
        if self.Tag == BACnetApplicationTags.NULL:
            # fixme NULL
            pass
        elif self.Tag == BACnetApplicationTags.BOOLEAN:
            return ASN1.encode_application_boolean(self.Value)
        elif self.Tag == BACnetApplicationTags.UNSIGNED_INT:
            return ASN1.encode_application_unsigned(self.Value)
        elif self.Tag == BACnetApplicationTags.SIGNED_INT:
            return ASN1.encode_application_signed(self.Value)
        elif self.Tag == BACnetApplicationTags.REAL:
            return ASN1.encode_application_real(self.Value)
        elif self.Tag == BACnetApplicationTags.DOUBLE:
            return ASN1.encode_application_double(self.Value)
        elif self.Tag == BACnetApplicationTags.OCTET_STRING:
            return ASN1.encode_application_octet_string(self.Value, 0, len(self.Value))
        elif self.Tag == BACnetApplicationTags.CHARACTER_STRING:
            return ASN1.encode_application_character_string(self.Value)
        elif self.Tag == BACnetApplicationTags.BIT_STRING:
            return ASN1.encode_application_bitstring(self.Value)
        elif self.Tag == BACnetApplicationTags.ENUMERATED or type(self.value) == enum.IntEnum:
            return ASN1.encode_application_enumerated(self.Value)
        elif self.Tag == BACnetApplicationTags.DATE:
            return ASN1.encode_application_date(self.Value)
        elif self.Tag == BACnetApplicationTags.TIME:
            return ASN1.encode_application_time(self.Value)
        elif self.Tag == BACnetApplicationTags.BACNETOBJECTIDENTIFIER:
            return self.Value.ASN1encode_app()
        elif type(self.value) == ASN1encodeInterface:
            return self.Value.ASN1encode()
        else:
            logging.debug("something else to encode!!!!")


# todo BACnetPropertyReference add ASN1encodeInterface
class BACnetPropertyReference(ASN1encodeInterface):
    def __init__(self, propertyIdentifier: BACnetPropertyIdentifier = None, propertyArrayIndex: int = None):
        self.propertyIdentifier = propertyIdentifier

        self.propertyArrayIndex = propertyArrayIndex

    def __str__(self):
        return str(self.propertyIdentifier) + ":" + str(self.propertyArrayIndex)

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        # propertyidentifier
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 0)):

            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.propertyIdentifier) = ASN1.decode_enumerated(buffer, offset + leng, len_value,
                                                                      prop_id=BACnetPropertyIdentifier.PROPERTY_LIST)
            leng += leng1
        else:
            return -1

        if leng < apdu_len:
            if (ASN1.decode_is_context_tag(buffer, offset + leng, 1) and not ASN1.decode_is_closing_tag_number(buffer,
                                                                                                               offset + leng,
                                                                                                               1)):
                (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                (leng1, self.propertyArrayIndex) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
                leng += leng1
        return leng


# todo BACnetTimeStamp add ASN1encodeInterface
class BACnetTimeStamp(ASN1encodeInterface):
    def __init__(self, value=None):
        self.value = value

    def __str__(self):
        if type(self.value) == int:
            return "sequence number: " + str(self.value)
        elif type(self.value) == BACnetDateTime:
            return "DateTime: " + str(self.value)
        elif type(self.value) == time:
            return "Time: " + str(self.value)

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 2)):
            # BACnetDateTime
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            self.value = BACnetDateTime()
            leng += BACnetDateTime.ASN1decode(self.value, buffer, offset + leng, len_value)
            # leng += 1
        elif (ASN1.decode_is_context_tag(buffer, offset + leng, 1)):
            # sequencenumber
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.value) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1
            # leng += 1
        elif (ASN1.decode_is_context_tag(buffer, offset + leng, 0)):
            # time
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.value) = ASN1.decode_bacnet_time_safe(buffer, offset + leng, len_value)
            leng += leng1
        else:
            return -1

        return leng

    def ASN1encode(self):
        pass

    def ASN1encode_context(self, tag_number) -> bytes:
        tmp = self.ASN1encode()
        return ASN1.encode_tag(tag_number, True, len(tmp)) + tmp


class BACnetPropertyStatesChoice(enum.IntEnum):
    BOOLEAN_VALUE = 0
    BINARY_VALUE = 1
    EVENT_TYPE = 2
    POLARITY = 3
    PROGRAM_CHANGE = 4
    PROGRAM_STATE = 5
    REASON_FOR_HALT = 6
    RELIABILITY = 7
    STATE = 8
    SYSTEM_STATUS = 9
    UNITS = 10
    UNSIGNED_VALUE = 11
    LIFE_SAFETY_MODE = 12
    LIFE_SAFETY_STATE = 13
    RESTART_REASON = 14
    DOOR_ALARM_STATE = 15
    ACTION = 16
    DOOR_SECURED_STATUS = 17
    DOOR_STATUS = 18
    DOOR_VALUE = 19
    FILE_ACCESS_METHOD = 20
    LOCK_STATUS = 21
    LIFE_SAFETY_OPERATION = 22
    MAINTENANCE = 23
    NODE_TYPE = 24
    NOTIFY_TYPE = 25
    SECURITY_LEVEL = 26
    SHED_STATE = 27
    SILENCED_STATE = 28
    ACCESS_EVENT = 30
    ZONE_OCCUPANCY_STATE = 31
    ACCESS_CREDENTIAL_DISABLE_REASON = 32
    ACCESS_CREDENTIAL_DISABLE = 33
    AUTHENTICATION_STATUS = 34
    BACKUP_STATE = 36
    WRITE_STATUS = 37
    LIGHTING_IN_PROGRESS = 38
    LIGHTING_OPERATION = 39
    LIGHTING_TRANSITION = 40
    INTEGER_VALUE = 41
    BINARY_LIGHTING_VALUE = 42
    TIMER_STATE = 43
    TIMER_TRANSITION = 44
    BACNET_IP_MODE = 45
    NETWORK_PORT_COMMAND = 46
    NETWORK_TYPE = 47
    NETWORK_NUMBER_QUALITY = 48
    ESCALATOR_OPERATION_DIRECTION = 49
    ESCALATOR_FAULT = 50
    ESCALATOR_MODE = 51
    LIFT_CAR_DIRECTION = 52
    LIFT_CAR_DOOR_COMMAND = 53
    LIFT_CAR_DRIVE_STATUS = 54
    LIFT_CAR_MODE = 55
    LIFT_GROUP_MODE = 56
    LIFT_FAULT = 57
    PROTOCOL_LEVEL = 58
    EXTENDED_VALUE = 63


# todo BACnetPropertyStates add ASN1encodeInterface
class BACnetPropertyStates(ASN1encodeInterface):
    def __init__(self, value=None, _choice: BACnetPropertyStatesChoice = None):
        self.value = value
        self._choice = _choice

    def __str__(self):
        return str(self.value)

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0

        (leng1, tag_number, len_value_type) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        leng += leng1
        self._choice = BACnetPropertyStatesChoice(tag_number)

        if self._choice == BACnetPropertyStatesChoice.INTEGER_VALUE:
            (leng1, val) = ASN1.decode_signed(buffer, offset + leng, len_value_type)
            leng += leng1
            self.value: int = val
        else:
            (leng1, val) = ASN1.decode_unsigned(buffer, offset + leng, len_value_type)
            leng += leng1
            if self._choice == BACnetPropertyStatesChoice.BINARY_VALUE:
                self.value: BACnetBinaryPV = BACnetBinaryPV(val)
            elif self._choice == BACnetPropertyStatesChoice.BOOLEAN_VALUE:
                if val > 0:
                    self.value: bool = True
                else:
                    self.value: bool = False
            elif self._choice == BACnetPropertyStatesChoice.EVENT_TYPE:
                self.value: BACnetEventType = BACnetEventType(val)
            elif self._choice == BACnetPropertyStatesChoice.POLARITY:
                self.value: BACnetPolarity = BACnetPolarity(val)
            elif self._choice == BACnetPropertyStatesChoice.PROGRAM_CHANGE:
                self.value: BACnetProgramRequest = BACnetProgramRequest(val)
            elif self._choice == BACnetPropertyStatesChoice.PROGRAM_STATE:
                self.value: BACnetProgramState = BACnetProgramState(val)
            elif self._choice == BACnetPropertyStatesChoice.REASON_FOR_HALT:
                self.value: BACnetProgramError = BACnetProgramError(val)
            elif self._choice == BACnetPropertyStatesChoice.RELIABILITY:
                self.value: BACnetReliability = BACnetReliability(val)
            elif self._choice == BACnetPropertyStatesChoice.STATE:
                self.value: BACnetEventState = BACnetEventState(val)
            elif self._choice == BACnetPropertyStatesChoice.SYSTEM_STATUS:
                self.value: BACnetDeviceStatus = BACnetDeviceStatus(val)
            elif self._choice == BACnetPropertyStatesChoice.UNITS:
                self.value: BACnetEngineeringUnits = BACnetEngineeringUnits(val)
            elif self._choice == BACnetPropertyStatesChoice.UNSIGNED_VALUE:
                self.value: int = val
            elif self._choice == BACnetPropertyStatesChoice.LIFE_SAFETY_MODE:
                self.value: BACnetLifeSafetyMode = BACnetLifeSafetyMode(val)
            elif self._choice == BACnetPropertyStatesChoice.LIFE_SAFETY_STATE:
                self.value: BACnetLifeSafetyState = BACnetLifeSafetyState(val)
            elif self._choice == BACnetPropertyStatesChoice.RESTART_REASON:
                self.value: BACnetRestartReason = BACnetRestartReason(val)
            elif self._choice == BACnetPropertyStatesChoice.DOOR_ALARM_STATE:
                self.value: BACnetDoorAlarmState = BACnetDoorAlarmState(val)
            elif self._choice == BACnetPropertyStatesChoice.ACTION:
                self.value: BACnetAction = BACnetAction(val)
            elif self._choice == BACnetPropertyStatesChoice.DOOR_SECURED_STATUS:
                self.value: BACnetDoorSecuredStatus = BACnetDoorSecuredStatus(val)
            elif self._choice == BACnetPropertyStatesChoice.DOOR_STATUS:
                self.value: BACnetDoorStatus = BACnetDoorStatus(val)
            elif self._choice == BACnetPropertyStatesChoice.DOOR_VALUE:
                self.value: BACnetDoorValue = BACnetDoorValue(val)
            elif self._choice == BACnetPropertyStatesChoice.FILE_ACCESS_METHOD:
                self.value: BACnetFileAccessMethod = BACnetFileAccessMethod(val)
            elif self._choice == BACnetPropertyStatesChoice.LOCK_STATUS:
                self.value: BACnetLockStatus = BACnetLockStatus(val)
            elif self._choice == BACnetPropertyStatesChoice.LIFE_SAFETY_OPERATION:
                self.value: BACnetLifeSafetyOperation = BACnetLifeSafetyOperation(val)
            elif self._choice == BACnetPropertyStatesChoice.MAINTENANCE:
                self.value: BACnetMaintenance = BACnetMaintenance(val)
            elif self._choice == BACnetPropertyStatesChoice.NODE_TYPE:
                self.value: BACnetNodeType = BACnetNodeType(val)
            elif self._choice == BACnetPropertyStatesChoice.NOTIFY_TYPE:
                self.value: BACnetNotifyType = BACnetNotifyType(val)
            elif self._choice == BACnetPropertyStatesChoice.SECURITY_LEVEL:
                self.value: BACnetSecurityLevel = BACnetSecurityLevel(val)
            elif self._choice == BACnetPropertyStatesChoice.SHED_STATE:
                self.value: BACnetShedState = BACnetShedState(val)
            elif self._choice == BACnetPropertyStatesChoice.SILENCED_STATE:
                self.value: BACnetSilencedState = BACnetSilencedState(val)
            elif self._choice == BACnetPropertyStatesChoice.ACCESS_EVENT:
                self.value: BACnetAccessEvent = BACnetAccessEvent(val)
            elif self._choice == BACnetPropertyStatesChoice.ZONE_OCCUPANCY_STATE:
                self.value: BACnetAccessZoneOccupancyState = BACnetAccessZoneOccupancyState(val)
            elif self._choice == BACnetPropertyStatesChoice.ACCESS_CREDENTIAL_DISABLE_REASON:
                self.value: BACnetAccessCredentialDisableReason = BACnetAccessCredentialDisableReason(val)
            elif self._choice == BACnetPropertyStatesChoice.ACCESS_CREDENTIAL_DISABLE:
                self.value: BACnetAccessCredentialDisable = BACnetAccessCredentialDisable(val)
            elif self._choice == BACnetPropertyStatesChoice.AUTHENTICATION_STATUS:
                self.value: BACnetAuthenticationStatus = BACnetAuthenticationStatus(val)
            elif self._choice == BACnetPropertyStatesChoice.BACKUP_STATE:
                self.value: BACnetBackupState = BACnetBackupState(val)
            elif self._choice == BACnetPropertyStatesChoice.WRITE_STATUS:
                self.value: BACnetWriteStatus = BACnetWriteStatus(val)
            elif self._choice == BACnetPropertyStatesChoice.LIGHTING_IN_PROGRESS:
                self.value: BACnetLightingInProgress = BACnetLightingInProgress(val)
            elif self._choice == BACnetPropertyStatesChoice.LIGHTING_OPERATION:
                self.value: BACnetLightingOperation = BACnetLightingOperation(val)
            elif self._choice == BACnetPropertyStatesChoice.LIGHTING_TRANSITION:
                self.value: BACnetLightingTransition = BACnetLightingTransition(val)
            elif self._choice == BACnetPropertyStatesChoice.BINARY_LIGHTING_VALUE:
                self.value: BACnetBinaryLightingPV = BACnetBinaryLightingPV(val)
            elif self._choice == BACnetPropertyStatesChoice.TIMER_STATE:
                self.value: BACnetTimerState = BACnetTimerState(val)
            elif self._choice == BACnetPropertyStatesChoice.TIMER_TRANSITION:
                self.value: BACnetTimerTransition = BACnetTimerTransition(val)
            elif self._choice == BACnetPropertyStatesChoice.BACNET_IP_MODE:
                self.value: BACnetIPMode = BACnetIPMode(val)
            elif self._choice == BACnetPropertyStatesChoice.NETWORK_PORT_COMMAND:
                self.value: BACnetNetworkPortCommand = BACnetNetworkPortCommand(val)
            elif self._choice == BACnetPropertyStatesChoice.NETWORK_TYPE:
                self.value: BACnetNetworkType = BACnetNetworkType(val)
            elif self._choice == BACnetPropertyStatesChoice.NETWORK_NUMBER_QUALITY:
                self.value: BACnetNetworkNumberQuality = BACnetNetworkNumberQuality(val)
            elif self._choice == BACnetPropertyStatesChoice.ESCALATOR_OPERATION_DIRECTION:
                self.value: BACnetEscalatorOperationDirection = BACnetEscalatorOperationDirection(val)
            elif self._choice == BACnetPropertyStatesChoice.ESCALATOR_FAULT:
                self.value: BACnetEscalatorFault = BACnetEscalatorFault(val)
            elif self._choice == BACnetPropertyStatesChoice.ESCALATOR_MODE:
                self.value: BACnetEscalatorMode = BACnetEscalatorMode(val)
            elif self._choice == BACnetPropertyStatesChoice.LIFT_CAR_DIRECTION:
                self.value: BACnetLiftCarDirection = BACnetLiftCarDirection(val)
            elif self._choice == BACnetPropertyStatesChoice.LIFT_CAR_DOOR_COMMAND:
                self.value: BACnetLiftCarDoorCommand = BACnetLiftCarDoorCommand(val)
            elif self._choice == BACnetPropertyStatesChoice.LIFT_CAR_DRIVE_STATUS:
                self.value: BACnetLiftCarDriveStatus = BACnetLiftCarDriveStatus(val)
            elif self._choice == BACnetPropertyStatesChoice.LIFT_CAR_MODE:
                self.value: BACnetLiftCarMode = BACnetLiftCarMode(val)
            elif self._choice == BACnetPropertyStatesChoice.LIFT_GROUP_MODE:
                self.value: BACnetLiftGroupMode = BACnetLiftGroupMode(val)
            elif self._choice == BACnetPropertyStatesChoice.LIFT_FAULT:
                self.value: BACnetLiftFault = BACnetLiftFault(val)
            elif self._choice == BACnetPropertyStatesChoice.PROTOCOL_LEVEL:
                self.value: BACnetProtocolLevel = BACnetProtocolLevel(val)
            elif self._choice == BACnetPropertyStatesChoice.EXTENDED_VALUE:
                self.value: int = val

        return leng


# todo add ASN1encodeInterface
class BACnetBitString(ASN1encodeInterface):
    def __init__(self, unused_bits=None, value: BitArray = None):
        self.unused_bits = unused_bits
        self.value = value

    def __str__(self):
        return str(self.value.bin)

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        if apdu_len > 0:
            self.unused_bits = buffer[offset]
            leng += 1
            self.value = BitArray((apdu_len - 1) * 8)
            bit = 0
            for i in range(1, apdu_len):
                for i2 in range(0, 8):
                    self.value[bit] = bool(buffer[offset + i] & (1 << (7 - i2)))
                    bit += 1
        return apdu_len


#todo add asn1encode
class BACnetServicesSupported(ASN1encodeInterface):
    def __init__(self):
        self._unusedbits = 7
        self._bitstring: BACnetBitString = BACnetBitString(self._unusedbits, BitArray('0x00000000000000'))


    def ASN1decode(self, buffer, offset, apdu_len):
        self._bitstring = BACnetBitString()
        return self._bitstring.ASN1decode(buffer, offset, apdu_len)

    def __str__(self):
        return str(self._bitstring.value.bin)

    @property
    def acknowledge_alarm(self):
        return self._bitstring.value[0]

    @acknowledge_alarm.setter
    def acknowledge_alarm(self, a: bool):
        self._bitstring.value[0] = a

    @property
    def confirmed_cov_notification(self):
        return self._bitstring.value[1]

    @confirmed_cov_notification.setter
    def confirmed_cov_notification(self, a: bool):
        self._bitstring.value[1] = a

    @property
    def confirmed_cov_notification_multiple(self):
        return self._bitstring.value[42]

    @confirmed_cov_notification_multiple.setter
    def confirmed_cov_notification_multiple(self, a: bool):
        self._bitstring.value[42] = a

    @property
    def confirmed_event_notification(self):
        return self._bitstring.value[2]

    @confirmed_event_notification.setter
    def confirmed_event_notification(self, a: bool):
        self._bitstring.value[2] = a

    @property
    def get_alarm_summary(self):
        return self._bitstring.value[3]

    @get_alarm_summary.setter
    def get_alarm_summary(self, a: bool):
        self._bitstring.value[3] = a

    @property
    def get_enrollment_summary(self):
        return self._bitstring.value[4]

    @get_enrollment_summary.setter
    def get_enrollment_summary(self, a: bool):
        self._bitstring.value[4] = a

    @property
    def get_event_information(self):
        return self._bitstring.value[39]

    @get_event_information.setter
    def get_event_information(self, a: bool):
        self._bitstring.value[39] = a

    @property
    def life_safety_operation(self):
        return self._bitstring.value[37]

    @life_safety_operation.setter
    def life_safety_operation(self, a: bool):
        self._bitstring.value[39] = a

    @property
    def subscribe_cov(self):
        return self._bitstring.value[5]

    @subscribe_cov.setter
    def subscribe_cov(self, a: bool):
        self._bitstring.value[5] = a

    @property
    def subscribe_cov_property(self):
        return self._bitstring.value[38]

    @subscribe_cov_property.setter
    def subscribe_cov_property(self, a: bool):
        self._bitstring.value[38] = a

    @property
    def subscribe_cov_property_multiple(self):
        return self._bitstring.value[41]

    @subscribe_cov_property_multiple.setter
    def subscribe_cov_property_multiple(self, a: bool):
        self._bitstring.value[41] = a

    @property
    def atomic_read_file(self):
        return self._bitstring.value[6]

    @atomic_read_file.setter
    def atomic_read_file(self, a: bool):
        self._bitstring.value[6] = a

    @property
    def atomic_write_file(self):
        return self._bitstring.value[7]

    @atomic_write_file.setter
    def atomic_write_file(self, a: bool):
        self._bitstring.value[7] = a

    @property
    def add_list_element(self):
        return self._bitstring.value[8]

    @add_list_element.setter
    def add_list_element(self, a: bool):
        self._bitstring.value[8] = a

    @property
    def remove_list_element(self):
        return self._bitstring.value[9]

    @remove_list_element.setter
    def remove_list_element(self, a: bool):
        self._bitstring.value[9] = a

    @property
    def create_object(self):
        return self._bitstring.value[10]

    @create_object.setter
    def create_object(self, a: bool):
        self._bitstring.value[10] = a

    @property
    def delete_object(self):
        return self._bitstring.value[11]

    @delete_object.setter
    def delete_object(self, a: bool):
        self._bitstring.value[11] = a

    @property
    def read_property(self):
        return self._bitstring.value[12]

    @read_property.setter
    def read_property(self, a: bool):
        self._bitstring.value[12] = a

    @property
    def read_property_multiple(self):
        return self._bitstring.value[14]

    @read_property_multiple.setter
    def read_property_multiple(self, a: bool):
        self._bitstring.value[14] = a

    @property
    def read_range(self):
        return self._bitstring.value[35]

    @read_range.setter
    def read_range(self, a: bool):
        self._bitstring.value[35] = a

    @property
    def write_group(self):
        return self._bitstring.value[40]

    @write_group.setter
    def write_group(self, a: bool):
        self._bitstring.value[40] = a

    @property
    def write_property(self):
        return self._bitstring.value[15]

    @write_property.setter
    def write_property(self, a: bool):
        self._bitstring.value[15] = a

    @property
    def write_property_multiple(self):
        return self._bitstring.value[16]

    @write_property_multiple.setter
    def write_property_multiple(self, a: bool):
        self._bitstring.value[16] = a

    @property
    def device_communication_control(self):
        return self._bitstring.value[17]

    @device_communication_control.setter
    def device_communication_control(self, a: bool):
        self._bitstring.value[17] = a

    @property
    def confirmed_private_transfer(self):
        return self._bitstring.value[18]

    @confirmed_private_transfer.setter
    def confirmed_private_transfer(self, a: bool):
        self._bitstring.value[18] = a

    @property
    def confirmed_text_message(self):
        return self._bitstring.value[19]

    @confirmed_text_message.setter
    def confirmed_text_message(self, a: bool):
        self._bitstring.value[19] = a

    @property
    def reinitialize_device(self):
        return self._bitstring.value[20]

    @reinitialize_device.setter
    def reinitialize_device(self, a: bool):
        self._bitstring.value[20] = a

    @property
    def vt_open(self):
        return self._bitstring.value[21]

    @vt_open.setter
    def vt_open(self, a: bool):
        self._bitstring.value[21] = a

    @property
    def vt_close(self):
        return self._bitstring.value[22]

    @vt_close.setter
    def vt_close(self, a: bool):
        self._bitstring.value[22] = a

    @property
    def vt_data(self):
        return self._bitstring.value[23]

    @vt_data.setter
    def vt_data(self, a: bool):
        self._bitstring.value[23] = a

    @property
    def who_Am_I(self):
        return self._bitstring.value[47]

    @who_Am_I.setter
    def who_Am_I(self, a: bool):
        self._bitstring.value[47] = a

    @property
    def you_Are(self):
        return self._bitstring.value[48]

    @you_Are.setter
    def you_Are(self, a: bool):
        self._bitstring.value[48] = a

    @property
    def i_am(self):
        return self._bitstring.value[26]

    @i_am.setter
    def i_am(self, a: bool):
        self._bitstring.value[26] = a

    @property
    def i_have(self):
        return self._bitstring.value[27]

    @i_have.setter
    def i_have(self, a: bool):
        self._bitstring.value[27] = a

    @property
    def unconfirmed_cov_notification(self):
        return self._bitstring.value[28]

    @unconfirmed_cov_notification.setter
    def unconfirmed_cov_notification(self, a: bool):
        self._bitstring.value[28] = a

    @property
    def unconfirmed_cov_notification_multiple(self):
        return self._bitstring.value[43]

    @unconfirmed_cov_notification_multiple.setter
    def unconfirmed_cov_notification_multiple(self, a: bool):
        self._bitstring.value[43] = a

    @property
    def unconfirmed_event_notification(self):
        return self._bitstring.value[29]

    @unconfirmed_event_notification.setter
    def unconfirmed_event_notification(self, a: bool):
        self._bitstring.value[29] = a

    @property
    def unconfirmed_private_transfer(self):
        return self._bitstring.value[30]

    @unconfirmed_private_transfer.setter
    def unconfirmed_private_transfer(self, a: bool):
        self._bitstring.value[30] = a

    @property
    def unconfirmed_text_message(self):
        return self._bitstring.value[31]

    @unconfirmed_text_message.setter
    def unconfirmed_text_message(self, a: bool):
        self._bitstring.value[31] = a

    @property
    def time_synchronization(self):
        return self._bitstring.value[32]

    @time_synchronization.setter
    def time_synchronization(self, a: bool):
        self._bitstring.value[32] = a

    @property
    def utc_time_synchronization(self):
        return self._bitstring.value[36]

    @utc_time_synchronization.setter
    def utc_time_synchronization(self, a: bool):
        self._bitstring.value[36] = a

    @property
    def who_has(self):
        return self._bitstring.value[33]

    @who_has.setter
    def who_has(self, a: bool):
        self._bitstring.value[33] = a

    @property
    def who_is(self):
        return self._bitstring.value[34]

    @who_is.setter
    def who_is(self, a: bool):
        self._bitstring.value[34] = a


#todo add ASN1encode
class BACnetObjectTypesSupported(ASN1encodeInterface):
    def __init__(self):
        self._unusedbits = 3
        self._bitstring: BACnetBitString = BACnetBitString(self._unusedbits, BitArray('0x0000000000000000'))

    def __str__(self):
        return str(self._bitstring.value.bin)

    @property
    def ANALOG_INPUT(self):
        return self._bitstring.value[0]

    @ANALOG_INPUT.setter
    def ANALOG_INPUT(self, a: bool):
        self._bitstring.value[0] = a

    @property
    def ANALOG_OUTPUT(self):
        return self._bitstring.value[1]

    @ANALOG_OUTPUT.setter
    def ANALOG_OUTPUT(self, a: bool):
        self._bitstring.value[1] = a

    @property
    def ANALOG_VALUE(self):
        return self._bitstring.value[2]

    @ANALOG_VALUE.setter
    def ANALOG_VALUE(self, a: bool):
        self._bitstring.value[2] = a

    @property
    def BINARY_INPUT(self):
        return self._bitstring.value[3]

    @BINARY_INPUT.setter
    def BINARY_INPUT(self, a: bool):
        self._bitstring.value[3] = a

    @property
    def BINARY_OUTPUT(self):
        return self._bitstring.value[4]

    @BINARY_OUTPUT.setter
    def BINARY_OUTPUT(self, a: bool):
        self._bitstring.value[4] = a

    @property
    def BINARY_VALUE(self):
        return self._bitstring.value[5]

    @BINARY_VALUE.setter
    def BINARY_VALUE(self, a: bool):
        self._bitstring.value[5] = a

    @property
    def CALENDAR(self):
        return self._bitstring.value[6]

    @CALENDAR.setter
    def CALENDAR(self, a: bool):
        self._bitstring.value[6] = a

    @property
    def COMMAND(self):
        return self._bitstring.value[7]

    @COMMAND.setter
    def COMMAND(self, a: bool):
        self._bitstring.value[7] = a

    @property
    def DEVICE(self):
        return self._bitstring.value[8]

    @DEVICE.setter
    def DEVICE(self, a: bool):
        self._bitstring.value[8] = a

    @property
    def EVENT_ENROLLMENT(self):
        return self._bitstring.value[9]

    @EVENT_ENROLLMENT.setter
    def EVENT_ENROLLMENT(self, a: bool):
        self._bitstring.value[9] = a

    @property
    def FILE(self):
        return self._bitstring.value[10]

    @FILE.setter
    def FILE(self, a: bool):
        self._bitstring.value[10] = a

    @property
    def GROUP(self):
        return self._bitstring.value[11]

    @GROUP.setter
    def GROUP(self, a: bool):
        self._bitstring.value[11] = a

    @property
    def LOOP(self):
        return self._bitstring.value[12]

    @LOOP.setter
    def LOOP(self, a: bool):
        self._bitstring.value[12] = a

    @property
    def MULTI_STATE_INPUT(self):
        return self._bitstring.value[13]

    @MULTI_STATE_INPUT.setter
    def MULTI_STATE_INPUT(self, a: bool):
        self._bitstring.value[13] = a

    @property
    def MULTI_STATE_OUTPUT(self):
        return self._bitstring.value[14]

    @MULTI_STATE_OUTPUT.setter
    def MULTI_STATE_OUTPUT(self, a: bool):
        self._bitstring.value[14] = a

    @property
    def NOTIFICATION_CLASS(self):
        return self._bitstring.value[15]

    @NOTIFICATION_CLASS.setter
    def NOTIFICATION_CLASS(self, a: bool):
        self._bitstring.value[15] = a

    @property
    def PROGRAM(self):
        return self._bitstring.value[16]

    @PROGRAM.setter
    def PROGRAM(self, a: bool):
        self._bitstring.value[16] = a

    @property
    def SCHEDULE(self):
        return self._bitstring.value[17]

    @SCHEDULE.setter
    def SCHEDULE(self, a: bool):
        self._bitstring.value[17] = a

    @property
    def AVERAGING(self):
        return self._bitstring.value[18]

    @AVERAGING.setter
    def AVERAGING(self, a: bool):
        self._bitstring.value[18] = a

    @property
    def MULTI_STATE_VALUE(self):
        return self._bitstring.value[19]

    @MULTI_STATE_VALUE.setter
    def MULTI_STATE_VALUE(self, a: bool):
        self._bitstring.value[19] = a

    @property
    def TRENDLOG(self):
        return self._bitstring.value[20]

    @TRENDLOG.setter
    def TRENDLOG(self, a: bool):
        self._bitstring.value[20] = a

    @property
    def LIFE_SAFETY_POINT(self):
        return self._bitstring.value[21]

    @LIFE_SAFETY_POINT.setter
    def LIFE_SAFETY_POINT(self, a: bool):
        self._bitstring.value[21] = a

    @property
    def LIFE_SAFETY_ZONE(self):
        return self._bitstring.value[22]

    @LIFE_SAFETY_ZONE.setter
    def LIFE_SAFETY_ZONE(self, a: bool):
        self._bitstring.value[22] = a

    @property
    def ACCUMULATOR(self):
        return self._bitstring.value[23]

    @ACCUMULATOR.setter
    def ACCUMULATOR(self, a: bool):
        self._bitstring.value[23] = a

    @property
    def PULSE_CONVERTER(self):
        return self._bitstring.value[24]

    @PULSE_CONVERTER.setter
    def PULSE_CONVERTER(self, a: bool):
        self._bitstring.value[24] = a

    @property
    def EVENT_LOG(self):
        return self._bitstring.value[25]

    @EVENT_LOG.setter
    def EVENT_LOG(self, a: bool):
        self._bitstring.value[25] = a

    @property
    def GLOBAL_GROUP(self):
        return self._bitstring.value[26]

    @GLOBAL_GROUP.setter
    def GLOBAL_GROUP(self, a: bool):
        self._bitstring.value[26] = a

    @property
    def TREND_LOG_MULTIPLE(self):
        return self._bitstring.value[27]

    @TREND_LOG_MULTIPLE.setter
    def TREND_LOG_MULTIPLE(self, a: bool):
        self._bitstring.value[27] = a

    @property
    def LOAD_CONTROL(self):
        return self._bitstring.value[28]

    @LOAD_CONTROL.setter
    def LOAD_CONTROL(self, a: bool):
        self._bitstring.value[28] = a

    @property
    def STRUCTURED_VIEW(self):
        return self._bitstring.value[29]

    @STRUCTURED_VIEW.setter
    def STRUCTURED_VIEW(self, a: bool):
        self._bitstring.value[29] = a

    @property
    def ACCESS_DOOR(self):
        return self._bitstring.value[30]

    @ACCESS_DOOR.setter
    def ACCESS_DOOR(self, a: bool):
        self._bitstring.value[30] = a

    @property
    def TIMER(self):
        return self._bitstring.value[31]

    @TIMER.setter
    def TIMER(self, a: bool):
        self._bitstring.value[31] = a

    @property
    def ACCESS_CREDENTIAL(self):
        return self._bitstring.value[32]

    @ACCESS_CREDENTIAL.setter
    def ACCESS_CREDENTIAL(self, a: bool):
        self._bitstring.value[32] = a

    @property
    def ACCESS_POINT(self):
        return self._bitstring.value[33]

    @ACCESS_POINT.setter
    def ACCESS_POINT(self, a: bool):
        self._bitstring.value[33] = a

    @property
    def ACCESS_RIGHTS(self):
        return self._bitstring.value[34]

    @ACCESS_RIGHTS.setter
    def ACCESS_RIGHTS(self, a: bool):
        self._bitstring.value[34] = a

    @property
    def ACCESS_USER(self):
        return self._bitstring.value[35]

    @ACCESS_USER.setter
    def ACCESS_USER(self, a: bool):
        self._bitstring.value[35] = a

    @property
    def ACCESS_ZONE(self):
        return self._bitstring.value[36]

    @ACCESS_ZONE.setter
    def ACCESS_ZONE(self, a: bool):
        self._bitstring.value[36] = a

    @property
    def CREDENTIAL_DATA_INPUT(self):
        return self._bitstring.value[37]

    @CREDENTIAL_DATA_INPUT.setter
    def CREDENTIAL_DATA_INPUT(self, a: bool):
        self._bitstring.value[37] = a

    @property
    def NETWORK_SECURITY(self):
        return self._bitstring.value[38]

    @NETWORK_SECURITY.setter
    def NETWORK_SECURITY(self, a: bool):
        self._bitstring.value[38] = a

    @property
    def BITSTRING_VALUE(self):
        return self._bitstring.value[39]

    @BITSTRING_VALUE.setter
    def BITSTRING_VALUE(self, a: bool):
        self._bitstring.value[39] = a

    @property
    def CHARACTERSTRING_VALUE(self):
        return self._bitstring.value[40]

    @CHARACTERSTRING_VALUE.setter
    def CHARACTERSTRING_VALUE(self, a: bool):
        self._bitstring.value[40] = a

    @property
    def DATE_PATTERN_VALUE(self):
        return self._bitstring.value[41]

    @DATE_PATTERN_VALUE.setter
    def DATE_PATTERN_VALUE(self, a: bool):
        self._bitstring.value[41] = a

    @property
    def DATE_VALUE(self):
        return self._bitstring.value[42]

    @DATE_VALUE.setter
    def DATE_VALUE(self, a: bool):
        self._bitstring.value[42] = a

    @property
    def DATETIME_PATTERN_VALUE(self):
        return self._bitstring.value[43]

    @DATETIME_PATTERN_VALUE.setter
    def DATETIME_PATTERN_VALUE(self, a: bool):
        self._bitstring.value[43] = a

    @property
    def DATETIME_VALUE(self):
        return self._bitstring.value[44]

    @DATETIME_VALUE.setter
    def DATETIME_VALUE(self, a: bool):
        self._bitstring.value[44] = a

    @property
    def INTEGER_VALUE(self):
        return self._bitstring.value[45]

    @INTEGER_VALUE.setter
    def INTEGER_VALUE(self, a: bool):
        self._bitstring.value[45] = a

    @property
    def LARGE_ANALOG_VALUE(self):
        return self._bitstring.value[46]

    @LARGE_ANALOG_VALUE.setter
    def LARGE_ANALOG_VALUE(self, a: bool):
        self._bitstring.value[46] = a

    @property
    def OCTETSTRING_VALUE(self):
        return self._bitstring.value[47]

    @OCTETSTRING_VALUE.setter
    def OCTETSTRING_VALUE(self, a: bool):
        self._bitstring.value[47] = a

    @property
    def POSITIVE_INTEGER_VALUE(self):
        return self._bitstring.value[48]

    @POSITIVE_INTEGER_VALUE.setter
    def POSITIVE_INTEGER_VALUE(self, a: bool):
        self._bitstring.value[48] = a

    @property
    def TIME_PATTERN_VALUE(self):
        return self._bitstring.value[49]

    @TIME_PATTERN_VALUE.setter
    def TIME_PATTERN_VALUE(self, a: bool):
        self._bitstring.value[49] = a

    @property
    def TIME_VALUE(self):
        return self._bitstring.value[50]

    @TIME_VALUE.setter
    def TIME_VALUE(self, a: bool):
        self._bitstring.value[50] = a

    @property
    def NOTIFICATION_FORWARDER(self):
        return self._bitstring.value[51]

    @NOTIFICATION_FORWARDER.setter
    def NOTIFICATION_FORWARDER(self, a: bool):
        self._bitstring.value[51] = a

    @property
    def ALERT_ENROLLMENT(self):
        return self._bitstring.value[52]

    @ALERT_ENROLLMENT.setter
    def ALERT_ENROLLMENT(self, a: bool):
        self._bitstring.value[52] = a

    @property
    def CHANNEL(self):
        return self._bitstring.value[53]

    @CHANNEL.setter
    def CHANNEL(self, a: bool):
        self._bitstring.value[53] = a

    @property
    def LIGHTING_OUTPUT(self):
        return self._bitstring.value[54]

    @LIGHTING_OUTPUT.setter
    def LIGHTING_OUTPUT(self, a: bool):
        self._bitstring.value[54] = a

    @property
    def BINARY_LIGHTING_OUTPUT(self):
        return self._bitstring.value[55]

    @BINARY_LIGHTING_OUTPUT.setter
    def BINARY_LIGHTING_OUTPUT(self, a: bool):
        self._bitstring.value[55] = a

    @property
    def NETWORK_PORT(self):
        return self._bitstring.value[56]

    @NETWORK_PORT.setter
    def NETWORK_PORT(self, a: bool):
        self._bitstring.value[56] = a

    @property
    def ELEVATOR_GROUP(self):
        return self._bitstring.value[57]

    @ELEVATOR_GROUP.setter
    def ELEVATOR_GROUP(self, a: bool):
        self._bitstring.value[57] = a

    @property
    def ESCALATOR(self):
        return self._bitstring.value[58]

    @ESCALATOR.setter
    def ESCALATOR(self, a: bool):
        self._bitstring.value[58] = a

    @property
    def LIFT(self):
        return self._bitstring.value[59]

    @LIFT.setter
    def LIFT(self, a: bool):
        self._bitstring.value[59] = a

    @property
    def STAGING(self):
        return self._bitstring.value[60]

    @STAGING.setter
    def STAGING(self, a: bool):
        self._bitstring.value[60] = a

    def ASN1decode(self, buffer, offset, apdu_len):
        self._bitstring = BACnetBitString()
        return self._bitstring.ASN1decode(buffer, offset, apdu_len)


#todo add ASN1encode
class BACnetLimitEnable(ASN1encodeInterface):
    def __init__(self):
        self._unusedbits = 6
        self._bitstring: BACnetBitString = BACnetBitString(self._unusedbits, BitArray('0x00'))
        self.lowlimitenable: bool = False
        self.highlimitenable: bool = False

    def __str__(self):
        return str(self._bitstring.value.bin)

    def ASN1decode(self, buffer, offset, apdu_len):
        self._bitstring = BACnetBitString()
        return self._bitstring.ASN1decode(buffer, offset, apdu_len)

    @property
    def lowlimitenable(self):
        return self._bitstring.value[0]

    @lowlimitenable.setter
    def lowlimitenable(self, a: bool):
        self._bitstring.value[0] = a

    @property
    def highlimitenable(self):
        return self._bitstring.value[1]

    @highlimitenable.setter
    def highlimitenable(self, a: bool):
        self._bitstring.value[1] = a

#todo add ASN1encode
class BACnetDaysOfWeek(ASN1encodeInterface):
    def __init__(self):
        self._unusedbits = 1
        self._bitstring: BACnetBitString = BACnetBitString(self._unusedbits, BitArray('0x00'))
        self.monday: bool = False
        self.tuesday: bool = False
        self.wednesday: bool = False
        self.thursday: bool = False
        self.friday: bool = False
        self.saturday: bool = False
        self.sunday: bool = False

    def __str__(self):
        return str(self._bitstring.value.bin)

    def ASN1decode(self, buffer, offset, apdu_len):
        self._bitstring = BACnetBitString()
        return self._bitstring.ASN1decode(buffer, offset, apdu_len)

    @property
    def monday(self):
        return self._bitstring.value[0]

    @monday.setter
    def monday(self, a: bool):
        self._bitstring.value[0] = a

    @property
    def tuesday(self):
        return self._bitstring.value[1]

    @tuesday.setter
    def tuesday(self, a: bool):
        self._bitstring.value[1] = a

    @property
    def wednesday(self):
        return self._bitstring.value[2]

    @wednesday.setter
    def wednesday(self, a: bool):
        self._bitstring.value[2] = a

    @property
    def thursday(self):
        return self._bitstring.value[3]

    @thursday.setter
    def thursday(self, a: bool):
        self._bitstring.value[3] = a

    @property
    def friday(self):
        return self._bitstring.value[4]

    @friday.setter
    def friday(self, a: bool):
        self._bitstring.value[4] = a

    @property
    def saturday(self):
        return self._bitstring.value[5]

    @saturday.setter
    def saturday(self, a: bool):
        self._bitstring.value[5] = a

    @property
    def sunday(self):
        return self._bitstring.value[6]

    @sunday.setter
    def sunday(self, a: bool):
        self._bitstring.value[6] = a


#todo add ASN1encode
class BACnetLogStatus(ASN1encodeInterface):
    def __init__(self):
        self._unusedbits = 5
        self._bitstring: BACnetBitString = BACnetBitString(self._unusedbits, BitArray('0x00'))
        self.logdisabled: bool = False
        self.bufferpurged: bool = False
        self.loginterrupted: bool = False

    def __str__(self):
        return str(self._bitstring.value.bin)

    def ASN1decode(self, buffer, offset, apdu_len):
        self._bitstring = BACnetBitString()
        return self._bitstring.ASN1decode(buffer, offset, apdu_len)

    @property
    def logdisabled(self):
        return self._bitstring.value[0]

    @logdisabled.setter
    def logdisabled(self, a: bool):
        self._bitstring.value[0] = a

    @property
    def bufferpurged(self):
        return self._bitstring.value[1]

    @bufferpurged.setter
    def bufferpurged(self, a: bool):
        self._bitstring.value[1] = a

    @property
    def loginterrupted(self):
        return self._bitstring.value[2]

    @loginterrupted.setter
    def loginterrupted(self, a: bool):
        self._bitstring.value[2] = a


#todo add asn1encode
class BACnetResultFlags(ASN1encodeInterface):
    def __init__(self):
        self._unusedbits = 5
        self._bitstring: BACnetBitString = BACnetBitString(self._unusedbits, BitArray('0x00'))
        self.firstitem: bool = False
        self.lastitem: bool = False
        self.moreitems: bool = False

    def __str__(self):
        return str(self._bitstring.value.bin)

    def ASN1decode(self, buffer, offset, apdu_len):
        self._bitstring = BACnetBitString()
        return self._bitstring.ASN1decode(buffer, offset, apdu_len)

    @property
    def firstitem(self):
        return self._bitstring.value[0]

    @firstitem.setter
    def firstitem(self, a: bool):
        self._bitstring.value[0] = a

    @property
    def lastitem(self):
        return self._bitstring.value[1]

    @lastitem.setter
    def lastitem(self, a: bool):
        self._bitstring.value[1] = a

    @property
    def moreitems(self):
        return self._bitstring.value[2]

    @moreitems.setter
    def moreitems(self, a: bool):
        self._bitstring.value[2] = a


# todo add ASN1encode
class BACnetEventTransitionBits(ASN1encodeInterface):
    def __init__(self):
        self._unusedbits = 5
        self._bitstring: BACnetBitString = BACnetBitString(self._unusedbits, BitArray('0x00'))
        #self.tooffnormal: bool = False
        #self.tofault: bool = False
        #self.tonormal: bool = False

    def __str__(self):
        return str(self._bitstring.value.bin)

    def ASN1decode(self, buffer, offset, apdu_len):
        self._bitstring = BACnetBitString()
        return self._bitstring.ASN1decode(buffer, offset, apdu_len)

    @property
    def tooffnormal(self):
        return self._bitstring.value[0]

    @tooffnormal.setter
    def inalarm(self, a: bool):
        self._bitstring.value[0] = a

    @property
    def tofault(self):
        return self._bitstring.value[1]

    @tofault.setter
    def tofault(self, a: bool):
        self._bitstring.value[1] = a

    @property
    def tonormal(self):
        return self._bitstring.value[2]

    @tonormal.setter
    def tonormal(self, a: bool):
        self._bitstring.value[2] = a


#todo add ASN1encode
class BACnetStatusFlags(ASN1encodeInterface):
    def __init__(self):
        self._unusedbits = 4
        self._bitstring: BACnetBitString = BACnetBitString(self._unusedbits, BitArray('0x00'))
        self.inalarm: bool = False
        self.fault: bool = False
        self.overridden: bool = False
        self.outofservice: bool = False

    def __str__(self):
        return "BACnetStatusFlags: "+str(self._bitstring.value.bin)

    def ASN1decode(self, buffer, offset, apdu_len):
        self._bitstring = BACnetBitString()
        return self._bitstring.ASN1decode(buffer, offset, apdu_len)

    @property
    def inalarm(self):
        return self._bitstring.value[0]

    @inalarm.setter
    def inalarm(self, a: bool):
        self._bitstring.value[0] = a

    @property
    def fault(self):
        return self._bitstring.value[1]

    @fault.setter
    def fault(self, a: bool):
        self._bitstring.value[1] = a

    @property
    def overridden(self):
        return self._bitstring.value[2]

    @overridden.setter
    def overridden(self, a: bool):
        self._bitstring.value[2] = a

    @property
    def outofservice(self):
        return self._bitstring.value[3]

    @outofservice.setter
    def outofservice(self, a: bool):
        self._bitstring.value[3] = a


# todo BACnetNotificationParameters finish ASN1decode and add ASN1encodeInterface
class BACnetNotificationParameters(ASN1encodeInterface):
    def __init__(self, value=None):
        self.value = value

    def __str__(self):
        return str(self.value)

    class changeofbitstring:
        def __init__(self, referencedbitstring: BACnetBitString = None, statusflags: BACnetStatusFlags = None):
            self.referencedbitstring = referencedbitstring
            self.statusflags = statusflags

        def __str__(self):
            return "\nreferencedbitstring: " + str(self.referencedbitstring) + "\nstatusflags: " + str(self.statusflags)

        def ASN1decode(self, buffer, offset, apdu_len):
            leng = 0
            (leng1, tag_number, len_value_type) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1

            if tag_number == 0:
                self.referencedbitstring = BACnetBitString()
                leng += self.referencedbitstring.ASN1decode(buffer, offset + leng, len_value_type)
            else:
                return -1

            # BACnetStatusFlags
            (leng1, tag_number, len_value_type) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            if tag_number == 1:
                leng += leng1
                self.statusflags = BACnetStatusFlags()
                leng += self.statusflags.ASN1decode(buffer, offset + leng, len_value_type)
            else:
                return -1

            return leng

    class changeofstate:
        def __init__(self, newstate: BACnetPropertyStates = None, statusflags: BACnetStatusFlags = None):
            self.newstate = newstate
            self.statusflags = statusflags

        def __str__(self):
            return "\nnewstate: " + str(self.newstate) + "\nstatusflags: " + str(self.statusflags)

        def ASN1decode(self, buffer, offset, apdu_len):
            leng = 0
            (leng1, tag_number) = ASN1.decode_tag_number(buffer, offset + leng)
            # new state BACnetPropertyStates
            if tag_number == 0:
                leng += leng1
                self.newstate = BACnetPropertyStates()
                leng += self.newstate.ASN1decode(buffer, offset + leng, apdu_len - leng)
                leng += 1
            else:
                return -1

            # BACnetStatusFlags
            (leng1, tag_number, len_value_type) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            if tag_number == 1:
                leng += leng1
                self.statusflags = BACnetStatusFlags()
                leng += self.statusflags.ASN1decode(buffer, offset + leng, len_value_type)
            else:
                return -1
            return leng

    class changeofvalue:
        def __init__(self, newvalue=None, statusflags=None):
            self.newvalue = newvalue
            self.statusflags = statusflags

        def __str__(self):
            return "\nnewvalue: " + str(self.newvalue) + "\nstatusflags: " + str(self.statusflags)

        def ASN1decode(self, buffer, offset, apdu_len):
            leng = 0
            (leng1, tag_number) = ASN1.decode_tag_number(buffer, offset + leng)
            # newvalue
            if tag_number == 0:
                leng += leng1
                (leng1, tag_number, len_value_type) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                if tag_number == 0:
                    self.newvalue = BACnetBitString()
                    leng += self.newvalue.ASN1decode(buffer, offset + leng, len_value_type)
                elif tag_number == 1:
                    (leng1, self.newvalue) = ASN1.decode_real(buffer, offset + leng)
                    leng += leng1
                leng += 1
            else:
                return -1

            # BACnetStatusFlags
            (leng1, tag_number, len_value_type) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            if tag_number == 1:
                leng += leng1
                self.statusflags = BACnetStatusFlags()
                leng += self.statusflags.ASN1decode(buffer, offset + leng, len_value_type)
            else:
                return -1
            return leng

    class commandfailure:
        def __init__(self, commandvalue=None, statusflags=None, feedbackvalue=None):
            self.commandvalue = commandvalue
            self.statusflags = statusflags
            self.feedbackvalue = feedbackvalue

    class floatinglimit:
        def __init__(self, referencevalue=None, statusflags=None, setpointvalue=None, errorlimit=None):
            self.referencevalue = referencevalue
            self.statusflags = statusflags
            self.setpointvalue = setpointvalue
            self.errorlimit = errorlimit

        def __str__(self):
            return "\nreferencevalue: " + str(self.referencevalue) + "\nstatusflags: " + \
                   str(self.statusflags) + "\nsetpointvalue: " + str(self.setpointvalue) + \
                   str(self.statusflags) + "\nerrorlimit: " + str(self.errorlimit)

        def ASN1decode(self, buffer, offset, apdu_len):
            leng = 0

    class outofrange:
        def __init__(self, exceedingvalue=None, statusflags=None, deadband=None, exceededlimit=None):
            self.exceedingvalue = exceedingvalue
            self.statusflags = statusflags
            self.deadband = deadband
            self.exceededlimit = exceededlimit

    class complexeventtype:
        def __init__(self, value: BACnetPropertyValue = None):
            self.value = value

    class changeoflifesafety:
        def __init__(self, newstate=None, newmode=None, statusflags=None, operationexpected=None):
            self.newstate = newstate
            self.newmode = newmode
            self.statusflags = statusflags
            self.operationexpected = operationexpected

    class extended:
        def __init__(self, vendorid=None, extendedeventtype=None, parameters=None):
            self.vendorid = vendorid
            self.extendedeventtype = extendedeventtype
            self.parameters = parameters

    class bufferready:
        def __init__(self, bufferproperty=None, previousnotification=None, currentnotification=None):
            self.bufferproperty = bufferproperty
            self.previousnotification = previousnotification
            self.currentnotification = currentnotification

    class unsignedrange:
        def __init__(self, exceedingvalue=None, statusflags=None, exceededlimit=None):
            self.exceedingvalue = exceedingvalue
            self.statusflags = statusflags
            self.exceededlimit = exceededlimit

    class accessevent:
        def __init__(self, accessevent=None, statusflags=None, accesseventtag=None, accesseventtime=None,
                     accesscredential=None, authenticationfactor=None):
            self.accessevent = accessevent
            self.statusflags = statusflags
            self.accesseventtag = accesseventtag
            self.accesseventtime = accesseventtime
            self.accesscredential = accesscredential
            self.authenticationfactor = authenticationfactor

    class doubleoutofrange:
        def __init__(self, exceedingvalue=None, statusflags=None, deadband=None, exceededlimit=None):
            self.exceedingvalue = exceedingvalue
            self.statusflags = statusflags
            self.deadband = deadband
            self.exceededlimit = exceededlimit

    class signedoutofrange:
        def __init__(self, exceedingvalue=None, statusflags=None, deadband=None, exceededlimit=None):
            self.exceedingvalue = exceedingvalue
            self.statusflags = statusflags
            self.deadband = deadband
            self.exceededlimit = exceededlimit

    class unsignedoutofrange:
        def __init__(self, exceedingvalue=None, statusflags=None, deadband=None, exceededlimit=None):
            self.exceedingvalue = exceedingvalue
            self.statusflags = statusflags
            self.deadband = deadband
            self.exceededlimit = exceededlimit

    class changeofcharacterstring:
        def __init__(self, changedvalue=None, statusflags=None, alarmvalue=None):
            self.changedvalue = changedvalue
            self.statusflags = statusflags
            self.alarmvalue = alarmvalue

    class changeofstatusflags:
        def __init__(self, presentvalue=None, referencedflags=None):
            self.presentvalue = presentvalue
            self.referencedflags = referencedflags

    class changeofreliability:
        def __init__(self, reliability=None, statusflags=None, propertyvalues=None):
            self.reliability = reliability
            self.statusflags = statusflags
            self.propertyvalues = propertyvalues

    class changeofdiscretevalue:
        def __init__(self, newvalue=None, statusflags=None):
            self.newvalue = newvalue
            self.statusflags = statusflags

    class changeoftimer:
        def __init__(self, newstate=None, statusflags=None, updatetime=None, laststatechange=None, initialtimeout=None,
                     expirationtime=None):
            self.newstate = newstate
            self.statusflags = statusflags
            self.updatetime = updatetime
            self.laststatechange = laststatechange
            self.initialtimeout = initialtimeout
            self.expirationtime = expirationtime

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        # todo decode all EVENTTYPES
        (leng1, tag_number) = ASN1.decode_tag_number(buffer, offset + leng)
        leng += leng1
        eventtype = BACnetEventType(tag_number)
        if eventtype == BACnetEventType.CHANGE_OF_BITSTRING:
            self.value = BACnetNotificationParameters.changeofbitstring()
            self.value.ASN1decode(buffer, offset + leng, apdu_len - leng)
        elif eventtype == BACnetEventType.CHANGE_OF_STATE:
            self.value = BACnetNotificationParameters.changeofstate()
            self.value.ASN1decode(buffer, offset + leng, apdu_len - leng)
        elif eventtype == BACnetEventType.CHANGE_OF_VALUE:
            self.value = BACnetNotificationParameters.changeofvalue()
            self.value.ASN1decode(buffer, offset + leng, apdu_len - leng)
        elif eventtype == BACnetEventType.COMMAND_FAILURE:
            print("COMMAND_FAILURE needs to be added!")
        elif eventtype == BACnetEventType.FLOATING_LIMIT:
            print("FLOATING_LIMIT needs to be added!")
        elif eventtype == BACnetEventType.OUT_OF_RANGE:
            print("OUT_OF_RANGE needs to be added!")
        elif eventtype == BACnetEventType.COMPLEX:
            print("COMPLEX needs to be added!")
        elif eventtype == BACnetEventType.CHANGE_OF_LIFE_SAFETY:
            print("CHANGE_OF_LIFE_SAFETY needs to be added!")
        elif eventtype == BACnetEventType.EXTENDED:
            print("EXTENDED needs to be added!")
        elif eventtype == BACnetEventType.BUFFER_READY:
            print("BUFFER_READY needs to be added!")
        elif eventtype == BACnetEventType.UNSIGNED_RANGE:
            print("UNSIGNED_RANGE needs to be added!")
        elif eventtype == BACnetEventType.ACCESS_EVENT:
            print("ACCESS_EVENT needs to be added!")
        elif eventtype == BACnetEventType.DOUBLE_OUT_OF_RANGE:
            print("DOUBLE_OUT_OF_RANGE needs to be added!")
        elif eventtype == BACnetEventType.SIGNED_OUT_OF_RANGE:
            print("SIGNED_OUT_OF_RANGE needs to be added!")
        elif eventtype == BACnetEventType.UNSIGNED_OUT_OF_RANGE:
            print("UNSIGNED_OUT_OF_RANGE needs to be added!")
        elif eventtype == BACnetEventType.CHANGE_OF_CHARACTERSTRING:
            print("CHANGE_OF_CHARACTERSTRING needs to be added!")
        elif eventtype == BACnetEventType.CHANGE_OF_STATUS_FLAG:
            print("CHANGE_OF_STATUS_FLAG needs to be added!")
        elif eventtype == BACnetEventType.CHANGE_OF_RELIABILITY:
            print("CHANGE_OF_RELIABILITY needs to be added!")
        elif eventtype == BACnetEventType.NONE:
            print("NONE needs to be added!")
        elif eventtype == BACnetEventType.CHANGE_OF_DISCRETE_VALUE:
            print("EVENT_CHANGE_OF_DISCRETE_VALUE needs to be added!")
        elif eventtype == BACnetEventType.CHANGE_OF_TIMER:
            print("EVENT_CHANGE_OF_TIMER needs to be added!")


##todo ReadAccessSpecification add ASN1encodeInterface
class ReadAccessSpecification(ASN1encodeInterface):
    def __init__(self, objectidentifier: BACnetObjectIdentifier = None, listofpropertyreferences: [] = None):
        self.objectidentifier = objectidentifier
        self.listofpropertyreferences = listofpropertyreferences

    def __str__(self):
        ret = "\nobjectidentifier: " + str(self.objectidentifier)
        for val in self.listofpropertyreferences:
            ret += "\n" + str(val)
        return ret

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        # objectidentifier
        self.objectidentifier = BACnetObjectIdentifier()
        leng1 = self.objectidentifier.ASN1decode_context(buffer, offset + leng, apdu_len - leng, 0)
        if leng1 < 0:
            return -1
        leng += leng1

        # listofpropertyreferences
        if (ASN1.decode_is_opening_tag_number(buffer, offset + leng, 1)):
            leng += 1
            self.listofpropertyreferences = []

            while ((apdu_len - leng) > 1 and not ASN1.decode_is_closing_tag_number(buffer, offset + leng, 1)):
                b_value = BACnetPropertyReference()
                leng += b_value.ASN1decode(buffer, offset + leng, apdu_len - leng)

                self.listofpropertyreferences.append(b_value)
        else:
            return -1

        leng += 1

        return leng


# todo WriteAccessSpecification add ASN1encodeInterface
class WriteAccessSpecification(ASN1encodeInterface):
    def __init__(self, objectidentifier: BACnetObjectIdentifier = None, listofproperties: [] = None):
        self.objectidentifier = objectidentifier
        self.listofproperties = listofproperties

    def __str__(self):
        ret = "\nobjectidentifier: " + str(self.objectidentifier)
        for val in self.listofproperties:
            ret += "\n" + str(val)
        return ret

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        # objectidentifier
        self.objectidentifier = BACnetObjectIdentifier()
        leng1 = self.objectidentifier.ASN1decode_context(buffer, offset + leng, apdu_len - leng, 0)
        if leng1 < 0:
            return -1
        leng += leng1

        # listofproperties
        if (ASN1.decode_is_opening_tag_number(buffer, offset + leng, 1)):
            leng += 1
            self.listofproperties = []

            while ((apdu_len - leng) > 1 and not ASN1.decode_is_closing_tag_number(buffer, offset + leng, 1)):
                b_value = BACnetPropertyValue()
                leng += b_value.ASN1decode(buffer, offset + leng, apdu_len - leng, self.objectidentifier)

                self.listofproperties.append(b_value)
        else:
            return -1

        leng += 1

        return leng


# todo BACnetDeviceObjectPropertyReference add ASN1encodeInterface
class BACnetDeviceObjectPropertyReference(ASN1encodeInterface):
    def __init__(self, objectidentifier: BACnetObjectIdentifier = None,
                 propertyidentifier: BACnetPropertyIdentifier = None,
                 propertyarrayindex: int = None,
                 deviceidentifier: BACnetObjectIdentifier = None):
        self.objectidentifier = objectidentifier
        self.propertyidentifier = propertyidentifier
        self.propertyarrayindex = propertyarrayindex
        self.deviceidentifier = deviceidentifier

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        # tag 0 objectidentifier
        self.objectidentifier = BACnetObjectIdentifier()
        leng1 = self.objectidentifier.ASN1decode_context(buffer, offset + leng, apdu_len - leng, 0)
        if leng1 < 0:
            return -1
        leng += leng1

        # tag 1 propertyidentifier
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 1)):
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.propertyidentifier) = ASN1.decode_enumerated(buffer, offset + leng, len_value,
                                                                      prop_id=BACnetPropertyIdentifier.PROPERTY_LIST)

            leng += leng1
        else:
            return -1

        if leng < apdu_len:
            # tag 2 property-array-index optional
            if (ASN1.decode_is_context_tag(buffer, offset + leng, 2)):
                leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                (leng1, self.propertyarrayindex) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
                leng += leng1

        if leng < apdu_len:
            # tag 3 device-identifier optional
            self.deviceidentifier = BACnetObjectIdentifier()
            leng1 = self.deviceidentifier.ASN1decode_context(buffer, offset + leng, apdu_len - leng, 3)
            if leng1 < 0:
                return -1
            leng += leng1

        return leng


# todo BACnetDeviceObjectPropertyValue add ASN1encodeInterface
class BACnetDeviceObjectPropertyValue(ASN1encodeInterface):
    def __init__(self, deviceidentifier: BACnetObjectIdentifier = None,
                 objectidentifier: BACnetObjectIdentifier = None,
                 propertyidentifier: BACnetPropertyIdentifier = None,
                 propertyarrayindex: int = None,
                 propertyvalue=None):
        self.deviceidentifier = deviceidentifier
        self.objectidentifier = objectidentifier
        self.propertyidentifier = propertyidentifier
        self.propertyarrayindex = propertyarrayindex
        self.propertyvalue = propertyvalue

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        # tag 0 device-identifier
        self.deviceidentifier = BACnetObjectIdentifier()
        leng1 = self.deviceidentifier.ASN1decode_context(buffer, offset + leng, apdu_len - leng, 0)
        if leng1 < 0:
            return -1
        leng += leng1

        # tag 1 objectidentifier
        self.objectidentifier = BACnetObjectIdentifier()
        leng1 = self.objectidentifier.ASN1decode_context(buffer, offset + leng, apdu_len - leng, 1)
        if leng1 < 0:
            return -1
        leng += leng1

        # tag 2 propertyidentifier
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 2)):
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.propertyidentifier) = ASN1.decode_enumerated(buffer, offset + leng, len_value,
                                                                      prop_id=BACnetPropertyIdentifier.PROPERTY_LIST)

            leng += leng1
        else:
            return -1

        if leng < apdu_len:
            # tag 3 property-array-index optional
            if (ASN1.decode_is_context_tag(buffer, offset + leng, 3)):
                leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                (leng1, self.propertyarrayindex) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
                leng += leng1

        if leng < apdu_len:
            if ASN1.decode_is_opening_tag_number(buffer, offset + leng, 4):
                leng += 1
                # fixme ABSTRACT-SYNTAX.&Type

                self.propertyvalue = []
                while not ASN1.decode_is_closing_tag_number(buffer, offset + leng, 4) and leng < apdu_len:
                    b_value = BACnetValue()
                    leng1 = b_value.ASN1decode(buffer, offset + leng, len_value, self.objectidentifier.Type,
                                               self.propertyidentifier)
                    if leng1 < 0:
                        return -1
                    leng += leng1
                    self.propertyvalue.append(b_value)
                # if leng > apdu_len return -1
                if ASN1.decode_is_closing_tag_number(buffer, offset + leng, 4):
                    leng += 1
                else:
                    return -1


            else:
                return -1
        else:
            return -1

        return leng


# todo BACnetDeviceObjectReference add ASN1encodeInterface
class BACnetDeviceObjectReference(ASN1encodeInterface):
    def __init__(self, deviceidentifier: BACnetObjectIdentifier = None,
                 objectidentifier: BACnetObjectIdentifier = None):
        self.deviceidentifier = deviceidentifier
        self.objectidentifier = objectidentifier

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        # tag 0 device-identifier optinal
        self.deviceidentifier = BACnetObjectIdentifier()
        leng1 = self.deviceidentifier.ASN1decode_context(buffer, offset + leng, apdu_len - leng, 0)
        if leng1 > 0:
            leng += leng1

        # tag 1 objectidentifier
        self.objectidentifier = BACnetObjectIdentifier()
        leng1 = self.objectidentifier.ASN1decode_context(buffer, offset + leng, apdu_len - leng, 1)
        if leng1 < 0:
            return -1
        leng += leng1

        return leng


# todo BACnetObjectPropertyReference add ASN1encodeInterface
class BACnetObjectPropertyReference(ASN1encodeInterface):
    def __init__(self, objectidentifier: BACnetObjectIdentifier = None,
                 propertyidentifier: BACnetPropertyIdentifier = None,
                 propertyarrayindex: int = None):
        self.objectidentifier = objectidentifier
        self.propertyidentifier = propertyidentifier
        self.propertyarrayindex = propertyarrayindex

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        # tag 0 objectidentifier
        self.objectidentifier = BACnetObjectIdentifier()
        leng1 = self.objectidentifier.ASN1decode_context(buffer, offset + leng, apdu_len - leng, 0)
        if leng1 < 0:
            return -1
        leng += leng1

        # tag 1 propertyidentifier
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 1)):
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.propertyidentifier) = ASN1.decode_enumerated(buffer, offset + leng, len_value,
                                                                      prop_id=BACnetPropertyIdentifier.PROPERTY_LIST)

            leng += leng1
        else:
            return -1

        if leng < apdu_len:
            # tag 2 property-array-index optional
            if (ASN1.decode_is_context_tag(buffer, offset + leng, 2)):
                leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                (leng1, self.propertyarrayindex) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
                leng += leng1

        return leng


# todo BACnetObjectPropertyValue add ASN1encodeInterface
class BACnetObjectPropertyValue(ASN1encodeInterface):
    def __init__(self, objectidentifier: BACnetObjectIdentifier = None,
                 propertyidentifier: BACnetPropertyIdentifier = None,
                 propertyarrayindex: int = None,
                 propertyvalue=None,
                 priority: int = None):
        self.objectidentifier = objectidentifier
        self.propertyidentifier = propertyidentifier
        self.propertyarrayindex = propertyarrayindex
        self.propertyvalue = propertyvalue
        self.priority = priority

    def __str__(self):
        return "\nBACnetObjectPropertyValue: " + \
               "\nobjectidentifier: " + str(self.objectidentifier) + \
               "\npropertyidentifier: " + str(self.propertyidentifier) + \
               "\npropertyarrayindex: " + str(self.propertyarrayindex) + \
               "\npropertyvalue: " + str(self.propertyvalue) + \
               "\npriority: " + str(self.priority)

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        # tag 0 objectidentifier
        self.objectidentifier = BACnetObjectIdentifier()
        leng1 = self.objectidentifier.ASN1decode_context(buffer, offset + leng, apdu_len - leng, 0)
        if leng1 < 0:
            return -1
        leng += leng1

        # tag 1 propertyidentifier
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 1)):
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.propertyidentifier) = ASN1.decode_enumerated(buffer, offset + leng, len_value,
                                                                      prop_id=BACnetPropertyIdentifier.PROPERTY_LIST)

            leng += leng1
        else:
            return -1

        if leng < apdu_len:
            # tag 2 property-array-index optional
            if (ASN1.decode_is_context_tag(buffer, offset + leng, 2)):
                leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                (leng1, self.propertyarrayindex) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
                leng += leng1

        if leng < apdu_len:
            # tag 3 property-value
            if ASN1.decode_is_opening_tag_number(buffer, offset + leng, 3):
                leng += 1
                # fixme ABSTRACT-SYNTAX.&Type

                self.propertyvalue = []
                while not ASN1.decode_is_closing_tag_number(buffer, offset + leng, 3) and leng < apdu_len:
                    b_value = BACnetValue()
                    leng1 = b_value.ASN1decode(buffer, offset + leng, len_value, self.objectidentifier.Type,
                                               self.propertyidentifier)
                    if leng1 < 0:
                        return -1
                    leng += leng1
                    self.propertyvalue.append(b_value)
                # if leng > apdu_len return -1
                if ASN1.decode_is_closing_tag_number(buffer, offset + leng, 3):
                    leng += 1
                else:
                    return -1
            else:
                return -1

        if leng < apdu_len:
            # tag 4 priority optional
            if (ASN1.decode_is_context_tag(buffer, offset + leng, 4)):
                leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                (leng1, self.priority) = ASN1.decode_unsigned(buffer, offset + leng, len_value)

                leng += leng1

        return leng


# todo BACnetAccumulatorRecord add ASN1encodeInterface
class BACnetAccumulatorRecord(ASN1encodeInterface):
    class statuschoice(enum.IntEnum):
        normal = 0
        starting = 1
        recovered = 2
        abnormal = 3
        failed = 4

    def __init__(self, timestamp: BACnetDateTime = None,
                 presentvalue: int = None,
                 accumulatedvalue: int = None,
                 accumulatorstatus: statuschoice = None):
        self.timestamp = timestamp
        self.presentvalue = presentvalue
        self.accumulatedvalue = accumulatedvalue
        self.accumulatorstatus = accumulatorstatus

    def __str__(self):
        return "timestamp: " + str(self.timestamp) + \
               "presentvalue: " + str(self.presentvalue) + \
               "accumulatedvalue: " + str(self.accumulatedvalue) + \
               "accumulatorstatus: " + str(self.accumulatorstatus)

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        # 0 timestamp
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 0)):
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            self.timestamp = BACnetTimeStamp()
            leng += self.timestamp.ASN1decode(buffer, offset + leng, len_value)
        else:
            return -1

        # 1 present-value
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 1)):
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.presentvalue) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1
        else:
            return -1

        # 2 accumulated-value
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 2)):
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.accumulatedvalue) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1
        else:
            return -1

        # 3 accumulator-status
        if (ASN1.decode_is_context_tag(buffer, offset + leng, 2)):
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, val) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1
            self.accumulatorstatus = BACnetAccumulatorRecord.statuschoice(val)
        else:
            return -1
        return leng


# todo BACnetActionCommand add ASN1encodeInterface
class BACnetActionCommand(ASN1encodeInterface):
    def __init__(self, device_identifier: BACnetObjectIdentifier = None,
                 object_identifier: BACnetObjectIdentifier = None,
                 property_identifier: BACnetPropertyIdentifier = None,
                 property_array_index: int = None,
                 property_value: BACnetValue = None,
                 priority: int = None,
                 post_delay: int = None,
                 quit_on_failure: bool = None,
                 write_successful: bool = None
                 ):
        self.device_identifier = device_identifier
        self.object_identifier = object_identifier
        self.property_identifier = property_identifier
        self.property_array_index = property_array_index
        self.property_value = property_value
        self.priority = priority
        self.post_delay = post_delay
        self.quit_on_failure = quit_on_failure
        self.write_successful = write_successful

    def __str__(self):
        return "\ndevice_identifier: " + str(self.device_identifier) + \
               "\nobject_identifier: " + str(self.object_identifier) + \
               "\nproperty_identifier: " + str(self.property_identifier) + \
               "\nproperty_array_index: " + str(self.property_array_index) + \
               "\nproperty_value: " + str(self.property_value) + \
               "\npriority: " + str(self.priority) + \
               "\npost_delay: " + str(self.post_delay) + \
               "\nquit_on_failure: " + str(self.quit_on_failure) + \
               "\nwrite_successful: " + str(self.write_successful)

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        # 0 device_identifier optional
        if ASN1.decode_is_context_tag(buffer, offset + leng, 0):
            self.device_identifier = BACnetObjectIdentifier()
            leng += self.device_identifier.ASN1decode_context(buffer, offset + leng, apdu_len - leng, 0)

        # 1 object_identifier
        if ASN1.decode_is_context_tag(buffer, offset + leng, 1):
            self.object_identifier = BACnetObjectIdentifier()
            leng += self.object_identifier.ASN1decode_context(buffer, offset + leng, apdu_len - leng, 1)
        else:
            return -1

        # 2 propertyidentifier
        if ASN1.decode_is_context_tag(buffer, offset + leng, 2):
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.property_identifier) = ASN1.decode_enumerated(buffer, offset + leng, len_value,
                                                                       prop_id=BACnetPropertyIdentifier.PROPERTY_LIST)

            leng += leng1
        else:
            return -1

        # 3 property_array_index
        if ASN1.decode_is_context_tag(buffer, offset + leng, 3):
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.property_array_index) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1

        # tag 4 property-value
        if ASN1.decode_is_opening_tag_number(buffer, offset + leng, 4):
            leng += 1
            # fixme ABSTRACT-SYNTAX.&Type

            self.property_value = []
            while not ASN1.decode_is_closing_tag_number(buffer, offset + leng, 4) and leng < apdu_len:
                b_value = BACnetValue()
                leng1 = b_value.ASN1decode(buffer, offset + leng, len_value, self.object_identifier.Type,
                                           self.property_identifier)
                if leng1 < 0:
                    return -1
                leng += leng1
                self.property_value.append(b_value)
            # if leng > apdu_len return -1
            if ASN1.decode_is_closing_tag_number(buffer, offset + leng, 4):
                leng += 1
            else:
                return -1
        else:
            return -1

        if leng < apdu_len:
            # tag 5 priority optional
            if ASN1.decode_is_context_tag(buffer, offset + leng, 5):
                leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                (leng1, self.priority) = ASN1.decode_unsigned(buffer, offset + leng, len_value)

                leng += leng1

        if leng < apdu_len:
            # tag 6 post-delay  optional
            if (ASN1.decode_is_context_tag(buffer, offset + leng, 6)):
                leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                (leng1, self.post_delay) = ASN1.decode_unsigned(buffer, offset + leng, len_value)

                leng += leng1

        if leng < apdu_len:
            # tag 7 quit-on-failure optional
            if (ASN1.decode_is_context_tag(buffer, offset + leng, 7)):
                leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                (leng1, u_val) = ASN1.decode_unsigned(buffer, offset + leng, len_value)

                leng += leng1
                if u_val > 0:
                    self.quit_on_failure = True
                else:
                    self.quit_on_failure = False

        if leng < apdu_len:
            # tag 8 write-successful optional
            if (ASN1.decode_is_context_tag(buffer, offset + leng, 7)):
                leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                (leng1, u_val) = ASN1.decode_unsigned(buffer, offset + leng, len_value)

                leng += leng1
                if u_val > 0:
                    self.write_successful = True
                else:
                    self.write_successful = False

        return leng


# todo BACnetActionList add ASN1encodeInterface
class BACnetActionList(ASN1encodeInterface):
    def __init__(self, action: [] = None):
        self.action = action

    def __str__(self):
        ret = ""
        for val in self.action:
            ret += "\n" + str(val)
        return ret

    def ASN1decode(self, buffer, offset, apdu_len) -> int:
        leng = 0
        # SEQUENCE OF BACnetActionCommand
        if (ASN1.decode_is_opening_tag_number(buffer, offset + leng, 0)):
            leng += 1
            self.action = []
            while not ASN1.decode_is_closing_tag_number(buffer, offset + leng, 0):
                b_value = BACnetActionCommand()
                leng1 = b_value.ASN1decode(buffer, offset + leng, apdu_len - leng)
                if leng1 < 0:
                    return -1
                leng += leng1
                self.action.append(b_value)
            leng += 1
        return leng


# todo BACnetWeekNDay add ASN1encodeInterface
class BACnetWeekNDay(ASN1encodeInterface):
    def __init__(self, month: int = None,
                 week_of_month: int = None,
                 day_of_week: int = None):
        self._month = month
        self._week_of_month = week_of_month
        self._day_of_week = day_of_week

    def __str__(self):
        return "month: " + str(self._month) + " week_of_month: " + str(self._week_of_month) + " day_of_week: " + str(
            self._day_of_week)

    @property
    def month(self) -> int:
        return self._month

    @month.setter
    def month(self, a: int):
        if a <= 255 and a >= 0:
            self._month = a

    @property
    def week_of_month(self) -> int:
        return self._week_of_month

    @week_of_month.setter
    def week_of_month(self, a: int):
        if a <= 255 and a >= 0:
            self._week_of_month = a

    @property
    def day_of_week(self) -> int:
        return self._day_of_week

    @day_of_week.setter
    def day_of_week(self, a: int):
        if a <= 255 and a >= 0:
            self._day_of_week = a

    def ASN1decode(self, buffer, offset, apdu_len):
        if apdu_len >= 3:
            self._month = buffer[offset]
            self._week_of_month = buffer[offset + 1]
            self.day_of_week = buffer[offset + 2]
        else:
            return -1
        return 3


# todo BACnetScale add ASN1encodeInterface
class BACnetScale(ASN1encodeInterface):
    def __init__(self, value=None):
        self.value = value

    def __str__(self):
        return "value: " + str(self.value)

    def ASN1decode(self, buffer, offset, apdu_len) -> int:
        leng = 0
        if ASN1.decode_is_context_tag(buffer, offset + leng, 0):
            # float-scale
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.value) = ASN1.decode_real_safe(buffer, offset + leng, len_value)
            leng += leng1
        elif ASN1.decode_is_context_tag(buffer, offset + leng, 1):
            # integer-scale
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.value) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1
        else:
            return -1
        return leng


# todo BACnetLightingCommand add ASN1encodeInterface
class BACnetLightingCommand(ASN1encodeInterface):
    def __init__(self, operation: BACnetLightingOperation = None,
                 target_level: float = None,
                 ramp_rate: float = None,
                 step_increment: float = None,
                 fade_time: int = None,
                 priority: int = None):
        self.operation = operation
        self.target_level = target_level
        self.ramp_rate = ramp_rate
        self.step_increment = step_increment
        self.fade_time = fade_time
        self.priority = priority

    def __str__(self):
        return "\noperation: " + str(self.operation) + \
               "\ntarget_level: " + str(self.target_level) + \
               "\nramp_rate: " + str(self.ramp_rate) + \
               "\nstep_increment: " + str(self.step_increment) + \
               "\nfade_time: " + str(self.fade_time) + \
               "\npriority: " + str(self.priority)

    def ASN1decode(self, buffer, offset, apdu_len) -> int:
        leng = 0
        # operation
        if ASN1.decode_is_context_tag(buffer, offset + leng, 0):
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, u_val) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1
            self.operation = BACnetLightingOperation(u_val)
        else:
            return -1

        if leng < apdu_len:
            # target-level
            if ASN1.decode_is_context_tag(buffer, offset + leng, 1):
                leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                (leng1, self.target_level) = ASN1.decode_real_safe(buffer, offset + leng, len_value)
                leng += leng1

        if leng < apdu_len:
            # ramp-rate
            if ASN1.decode_is_context_tag(buffer, offset + leng, 2):
                leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                (leng1, self.ramp_rate) = ASN1.decode_real_safe(buffer, offset + leng, len_value)
                leng += leng1

        if leng < apdu_len:
            # step-increment
            if ASN1.decode_is_context_tag(buffer, offset + leng, 3):
                leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                (leng1, self.step_increment) = ASN1.decode_real_safe(buffer, offset + leng, len_value)
                leng += leng1

        if leng < apdu_len:
            # fade-time
            if ASN1.decode_is_context_tag(buffer, offset + leng, 4):
                leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                (leng1, self.fade_time) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
                leng += leng1

        if leng < apdu_len:
            # priority
            if ASN1.decode_is_context_tag(buffer, offset + leng, 5):
                leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                (leng1, self.priority) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
                leng += leng1

        return leng


# todo BACnetPrescale add ASN1encodeInterface
class BACnetPrescale(ASN1encodeInterface):
    def __init__(self, multiplier: int = None,
                 modulo_divide: int = None):
        self.multiplier = multiplier
        self.modulo_divide = modulo_divide

    def __str__(self):
        return "\nmultiplier: " + str(self.multiplier) + \
               "\nmodulo_divide: " + str(self.modulo_divide)

    def ASN1decode(self, buffer, offset, apdu_len) -> int:
        leng = 0
        # multiplier
        if ASN1.decode_is_context_tag(buffer, offset + leng, 0):
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.multiplier) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1
        else:
            return -1

        # modulo_divide
        if ASN1.decode_is_context_tag(buffer, offset + leng, 1):
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.modulo_divide) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1
        else:
            return -1

        return leng


class BACnetShedLevelChoice(enum.IntEnum):
    percent = 0
    level = 1
    amount = 2


# todo BACnetShedLevel add ASN1encodeInterface
class BACnetShedLevel(ASN1encodeInterface):
    def __init__(self, choice: BACnetShedLevelChoice = None,
                 value=None):
        self.choice = choice
        self.value = value

    def __str__(self):
        return str(self.choice) + ": " + str(self.value)

    def ASN1decode(self, buffer, offset, apdu_len) -> int:
        leng = 0
        if ASN1.decode_is_context_tag(buffer, offset + leng, 0):
            # percent
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.value) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1

            self.choice = BACnetShedLevelChoice.percent
        elif ASN1.decode_is_context_tag(buffer, offset + leng, 1):
            # level
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.value) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1

            self.choice = BACnetShedLevelChoice.level
        elif ASN1.decode_is_context_tag(buffer, offset + leng, 2):
            # amount
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.value) = ASN1.decode_real_safe(buffer, offset + leng, len_value)
            leng += leng1

            self.choice = BACnetShedLevelChoice.amount
        else:
            return -1

        return leng


class BACnetLogRecordChoice(enum.IntEnum):
    log_status = 0
    boolean_value = 1
    real_value = 2
    enumerated_value = 3
    unsigned_value = 4
    integer_value = 5
    bitstring_value = 6
    null_value = 7
    failure = 8
    time_change = 9
    any_value = 10


# todo BACnetLogRecord add ASN1encodeInterface
class BACnetLogRecord(ASN1encodeInterface):
    def __init__(self, timestamp: BACnetDateTime = None,
                 log_datum=None,
                 status_flags: BACnetStatusFlags = None):
        self.timestamp = timestamp
        self.log_datum = log_datum
        self.status_flags = status_flags

    def __str__(self):
        return str(self.timestamp) + "\n " + str(self.log_datum) + "\n " + str(self.status_flags)

    def ASN1decode(self, buffer, offset: int, apdu_len: int, obj_type: BACnetObjectType = None,
                   prop_id: BACnetPropertyIdentifier = None) -> int:
        leng = 0
        # timestamp
        if ASN1.decode_is_context_tag(buffer, offset + leng, 0):
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            self.timestamp = BACnetTimeStamp()
            leng += self.timestamp.ASN1decode(buffer, offset + leng, len_value)
        else:
            return -1

        if ASN1.decode_is_context_tag(buffer, offset + leng, 1):
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            if tag_number == BACnetLogRecordChoice.log_status:
                self.log_datum = BACnetLogStatus()
                leng += self.log_datum.ASN1decode(buffer, offset + leng, len_value)
            elif tag_number == BACnetLogRecordChoice.boolean_value:
                if buffer[offset + leng] > 0:
                    self.log_datum = bool(True)
                else:
                    self.log_datum = bool(False)
                leng += 1
            elif tag_number == BACnetLogRecordChoice.real_value:
                (leng1, self.log_datum) = ASN1.decode_real_safe(buffer, offset + leng, len_value)
                leng += leng1
            elif tag_number == BACnetLogRecordChoice.enumerated_value:
                (leng1, self.log_datum) = ASN1.decode_enumerated(buffer, offset + leng, len_value)
                leng += leng1
            elif tag_number == BACnetLogRecordChoice.unsigned_value:
                (leng1, self.log_datum) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
                leng += leng1
            elif tag_number == BACnetLogRecordChoice.integer_value:
                (leng1, self.log_datum) = ASN1.decode_signed(buffer, offset + leng, len_value)
                leng += leng1
            elif tag_number == BACnetLogRecordChoice.bitstring_value:
                self.log_datum = BACnetBitString()
                leng += self.log_datum.ASN1decode(buffer, offset + leng, len_value)
            elif tag_number == BACnetLogRecordChoice.null_value:
                self.log_datum = None
                leng += 1
            elif tag_number == BACnetLogRecordChoice.failure:
                self.log_datum = BACnetError()
                leng += self.log_datum.ASN1decode(buffer, offset + leng, apdu_len - leng)
                if ASN1.decode_is_closing_tag_number(buffer, offset + leng, BACnetLogRecordChoice.failure):
                    leng += 1
                else:
                    return -1
            elif tag_number == BACnetLogRecordChoice.time_change:
                (leng1, self.log_datum) = ASN1.decode_real_safe(buffer, offset + leng, len_value)
                leng += leng1
            elif tag_number == BACnetLogRecordChoice.any_value:
                # ABSTRACT-SYNTAX.&Type
                # fixme test if is correct? how to get object_type and property_id???

                self.log_datum = []
                while not ASN1.decode_is_closing_tag_number(buffer, offset + leng,
                                                            BACnetLogRecordChoice.any_value) and leng < apdu_len:
                    b_value = BACnetValue()
                    leng1 = b_value.ASN1decode(buffer, offset + leng, apdu_len - leng, obj_type, prop_id)
                    if leng1 < 0:
                        return -1
                    leng += leng1
                    self.log_datum.append(b_value)
                # if leng > apdu_len return -1
                if ASN1.decode_is_closing_tag_number(buffer, offset + leng, BACnetLogRecordChoice.any_value):
                    leng += 1
                else:
                    return -1
            else:
                logging.debug("BACnetLogRecordChoice unknown!")
                return -1
        else:
            return -1

        if leng < apdu_len:
            # status-flags optional
            if ASN1.decode_is_context_tag(buffer, offset + leng, 2):
                leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
                leng += leng1
                self.status_flags = BACnetStatusFlags()
                leng += self.status_flags.ASN1decode(buffer, offset + leng, len_value)

        return leng


# todo BACnetDateRange add ASN1encodeInterface
class BACnetDateRange(ASN1encodeInterface):
    def __init__(self,start_date:date = None, end_date:date = None):
        self.start_date = start_date
        self.end_date = end_date

    def __str__(self):
        return "start_date: "+str(self.start_date)+" : "+"end date: "+str(self.end_date)

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        if tag_number == BACnetApplicationTags.DATE:
            leng += leng1
            leng1, self.start_date = ASN1.decode_date_safe(buffer, offset+leng, len_value)
            leng += leng1

        else:
            return -1
        leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        if tag_number == BACnetApplicationTags.DATE:
            leng += leng1
            leng1, self.end_date = ASN1.decode_date_safe(buffer, offset + leng, len_value)
            leng += leng1

        else:
            return -1

        return leng


# todo BACnetCalendarEntry add ASN1encodeInterface
class BACnetCalendarEntry(ASN1encodeInterface):
    def __init__(self, value = None):
        self.value = value

    def __str__(self):
        return "BACnetCalendarEntry: "+str(type(self.value))+" "+str(self.value)

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        leng += leng1
        if tag_number == 0:
            leng1, self.value = ASN1.decode_date_safe(buffer, offset + leng, len_value)
            leng += leng1
        elif tag_number == 1:
            self.value = BACnetDateRange()
            leng += self.value.ASN1decode(buffer, offset+leng, len_value)
        elif tag_number == 2:
            self.value = BACnetWeekNDay()
            leng += self.value.ASN1decode(buffer, offset + leng, len_value)
        else:
            return -1

        return leng


# todo BACnetEventLogRecord add ASN1encodeInterface
class BACnetEventLogRecord(ASN1encodeInterface):
    def __init__(self, timestamp: BACnetDateTime = None,
                 log_datum = None):
        self.timestamp = timestamp
        self.log_datum = log_datum

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        if ASN1.decode_is_context_tag(buffer, offset + leng, 0):
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            self.timestamp = BACnetDateTime
            leng += self.timestamp.ASN1decode(buffer, offset+leng, len_value)
        else:
            return -1

        return leng


class BACnetReadResult(ASN1encodeInterface):
    def __init__(self, propertyidentifier: BACnetPropertyIdentifier = None,
                 propertyarrayindex: int = None,
                 readresult=None):
        self.property_identifier = propertyidentifier
        self.property_arrayindex = propertyarrayindex
        self.read_result = readresult  # either error or BACnetValue

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        # 2 propertyidentifier
        if ASN1.decode_is_context_tag(buffer, offset + leng, 2):
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.property_identifier) = ASN1.decode_enumerated(buffer, offset + leng, len_value,
                                                                       prop_id=BACnetPropertyIdentifier.PROPERTY_LIST)

            leng += leng1
        else:
            return -1

        # 3 property_array_index
        if ASN1.decode_is_context_tag(buffer, offset + leng, 3):
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.property_array_index) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1

        if leng < apdu_len:
            if ASN1.decode_is_opening_tag_number(buffer, offset + leng, 4):
                self.read_result = BACnetValue()

                leng += self.read_result.ASN1decode(buffer, offset + leng, apdu_len - leng)
                if ASN1.decode_is_closing_tag_number(buffer, offset + leng, BACnetLogRecordChoice.any_value):
                    leng += 1
                else:
                    return -1
            elif ASN1.decode_is_opening_tag_number(buffer, offset + leng, 5):
                self.read_result = BACnetError()
                leng += self.read_result.ASN1decode(buffer, offset + leng, apdu_len - leng)
                if ASN1.decode_is_closing_tag_number(buffer, offset + leng, BACnetLogRecordChoice.failure):
                    leng += 1
                else:
                    return -1
        return leng


# todo ReadAccessResult add ASN1encodeInterface
class ReadAccessResult(ASN1encodeInterface):
    def __init__(self, objectidentifier: BACnetObjectIdentifier = None,
                 listofresults: [] = None):
        self.objectidentifier = objectidentifier
        self.listofresults = listofresults

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        # tag 0 objectidentifier
        self.objectidentifier = BACnetObjectIdentifier()
        if ASN1.decode_is_closing_tag_number(buffer, offset + leng, 0):
            leng += self.objectidentifier.ASN1decode_context(buffer, offset + leng, apdu_len - leng, 0)
        else:
            return -1

        if (ASN1.decode_is_opening_tag_number(buffer, offset + leng, 1)):
            leng += 1
            self.listofresults = []

            while ((apdu_len - leng) > 1 and not ASN1.decode_is_closing_tag_number(buffer, offset + leng, 1)):
                b_value = BACnetReadResult()
                leng += b_value.ASN1decode(buffer, offset + leng, apdu_len - leng)

                self.listofresults.append(b_value)
        else:
            return -1

        if (ASN1.decode_is_closing_tag_number(buffer, offset + leng, 1)):
            leng += 1
        else:
            return -1

        return leng


#todo BACnetAddress add ASN1encodeInterface
class BACnetAddress(ASN1encodeInterface):
#todo is experimental
    def __init__(self, network_number: int = None, mac_address: bytes = None, address = None, net_type: BACnetNetworkType = None):
        self.network_number = network_number
        self.mac_address = mac_address

        if net_type == BACnetNetworkType.IPV4 and type(address) == str:
            tmp1 = address.split(':')
            tmp = bytes(map(int, tmp1[0].split('.'))) + bytearray(int(tmp1[1]).to_bytes(2, 'big'))
            self.mac_address: bytes = tmp


        elif net_type == BACnetNetworkType.ETHERNET and type(address) == str:
            tmp = bytes(map(int, address.split('-')))
            self.mac_address: bytes = tmp

        elif net_type == BACnetNetworkType.IPV4 and type(address) == BACnetObjectIdentifier:
            tmp: BACnetObjectIdentifier = address
            self.mac_address: bytes = tmp.Instance.to_bytes(6,byteorder='little')
            #is correct?

    def __str__(self):
        return "\nBACnetAddress"+"\n\tnetwork_number: "+str(self.network_number)+"\n\tmac_address: "+str(self.mac_address)



    def IP_and_port(self):
        return (str(self.mac_address[0]) + "." + str(self.mac_address[1]) + "." + str(self.mac_address[2]) + "." + str(self.mac_address[3])), int(
            self.mac_address[4] << 8) + self.mac_address[5]

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        if tag_number == BACnetApplicationTags.UNSIGNED_INT:
            leng += leng1
            leng1, self.network_number = ASN1.decode_unsigned(buffer, offset+leng, len_value)
            leng += leng1
        else:
            return -1

        leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        if tag_number == BACnetApplicationTags.OCTET_STRING:
            leng += leng1
            leng1, self.mac_address = ASN1.decode_octet_string(buffer, offset + leng, len_value)
            leng += leng1
        else:
            return -1

        return leng


# todo BACnetAddressBinding add ASN1encodeInterface
class BACnetAddressBinding(ASN1encodeInterface):
    def __init__(self,device_identifier:BACnetObjectIdentifier = None, device_address:BACnetAddress = None):
        self.device_identifier = device_identifier
        self.device_address = device_address

    def __str__(self):
        return "\nBACnetAddressBinding"+\
                "\n\tdevice_identifier: "+str(self.device_identifier)+\
                "\n\tdevice_address: "+str(self.device_address)

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        #device_identifier
        if tag_number == BACnetApplicationTags.BACNETOBJECTIDENTIFIER:
            leng += leng1
            self.device_identifier = BACnetObjectIdentifier()
            leng += self.device_identifier.ASN1decode(buffer, offset+leng, len_value)
        else:
            return -1
        leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        if tag_number == BACnetApplicationTags.UNSIGNED_INT:
            self.device_address = BACnetAddress()
            leng += self.device_address.ASN1decode(buffer, offset+leng, len_value)
        else:
            return -1

        return leng


# todo BACnetHostAddress add ASN1encodeInterface
class BACnetHostAddress(ASN1encodeInterface):
    def __init__(self,value = None):
        self.value = value

    def __str__(self):
        if type(self.value) == str:
            return "name: "+str(self.value)
        elif type(self.value) == bytes:
            return "ip-address: "+str(self.value)
        else:
            return "None"

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        if tag_number == BACnetApplicationTags.NULL:
            leng += leng1
            self.value = None
        elif tag_number == BACnetApplicationTags.OCTET_STRING:
            leng += leng1
            leng1, self.value = ASN1.decode_octet_string(buffer, offset + leng, len_value)
            leng += leng1
        elif tag_number == BACnetApplicationTags.CHARACTER_STRING:
            leng += leng1
            leng1, self.value = ASN1.decode_character_string(buffer, offset + leng, apdu_len - leng, len_value)
            leng += leng1
        else:
            return -1
        return leng


# todo BACnetHostNPort add ASN1encodeInterface
class BACnetHostNPort(ASN1encodeInterface):
    def __init__(self,host:BACnetHostAddress = None, port:int = None):
        self.host = host
        self.port = port

    def __str__(self):
        return "\nBACnetHostNPort"+"\n\thost: "+str(self.host)+"\n\tport: "+str(self.port)

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        if ASN1.decode_is_opening_tag_number(buffer, offset + leng, 0):
            leng += 1
            self.host = BACnetHostAddress()
            leng += self.host.ASN1decode(buffer, offset+leng, apdu_len-leng)
            leng += 1
        else:
            return -1

        if ASN1.decode_is_context_tag(buffer, offset + leng, 1):
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.port) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1
        else:
            return -1

        return leng


# todo BACnetRecipient add ASN1encodeInterface
class BACnetRecipient(ASN1encodeInterface):
    def __init__(self, value = None):
        self.value = value

    def __str__(self):
        if type(self.value) == BACnetObjectIdentifier:
            return "\n\t\tBACnetRecipient"+"\n\t\t\tdevice: "+str(self.value)
        elif type(self.value) == BACnetAddress:
            return "\n\t\tBACnetRecipient"+"\n\t\t\taddress: "+str(self.value)
        else:
            return str(self.value)

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)

        if tag_number == 0:
            # device_identifier
            leng += leng1
            self.value = BACnetObjectIdentifier()
            leng += self.value.ASN1decode(buffer, offset + leng, len_value)

        elif tag_number == 1:
            # address
            self.value = BACnetAddress()
            leng += self.value.ASN1decode(buffer, offset + leng, len_value)

        else:
            return -1

        return leng


# todo BACnetRecipientProcess add ASN1encodeInterface
class BACnetRecipientProcess(ASN1encodeInterface):
    def __init__(self, recipient:BACnetRecipient = None, process_identifier:int = None):
        self.recipient = recipient
        self.process_identifier = process_identifier

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        #recipient
        if ASN1.decode_is_opening_tag_number(buffer, offset + leng, 0):
            leng += 1
            self.recipient = BACnetRecipient()
            leng += self.recipient.ASN1decode(buffer, offset+leng, apdu_len-leng)
            leng += 1
        else:
            return -1
        #process-identifier
        if ASN1.decode_is_context_tag(buffer, offset + leng, 1):
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.process_identifier) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1
        else:
            return -1

        return leng


# todo BACnetKeyIdentifier add ASN1encodeInterface
class BACnetKeyIdentifier(ASN1encodeInterface):
    def __init__(self, algorithm:int = None, key_id:int = None):
        self.algorithm = algorithm
        self.key_id = key_id

    def __str__(self):
        return "\n\t\t\t\talgorithm: "+str(self.algorithm)+" key_id: "+str(self.key_id)

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        #algorithm
        if ASN1.decode_is_context_tag(buffer, offset + leng, 0):
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.algorithm) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1
        else:
            return -1

        if ASN1.decode_is_context_tag(buffer, offset + leng, 1):
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.key_id) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1
        else:
            return -1

        return leng


# todo BACnetSecurityKeySet add ASN1encodeInterface
class BACnetSecurityKeySet(ASN1encodeInterface):
    def __init__(self, key_revision:int = None,
                 activation_time:BACnetDateTime = None,
                 expiration_time:BACnetDateTime = None,
                 key_ids:[] = None):
        self.key_revision = key_revision
        self.activation_time = activation_time
        self.expiration_time = expiration_time
        self.key_ids = key_ids

    def __str__(self):
        ret = "\n\t\t\tkey_revision: "+str(self.key_revision)+ \
              "\n\t\t\tactivation_time: " + str(self.activation_time) + \
              "\n\t\t\texpiration_time: " + str(self.expiration_time)
        for val in self.key_ids:
            ret += "\n\t\t\tkey_id: "+str(val)
        return ret

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        #key_revision
        if ASN1.decode_is_context_tag(buffer, offset + leng, 0):
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (leng1, self.key_revision) = ASN1.decode_unsigned(buffer, offset + leng, len_value)
            leng += leng1
        else:
            return -1

        # activation_time
        if ASN1.decode_is_opening_tag_number(buffer, offset + leng, 1):
            leng += 1
            self.activation_time = BACnetDateTime()
            leng += self.activation_time.ASN1decode(buffer, offset+leng, apdu_len-leng)
            leng += 1

        else:
            return -1

        # expiration_time
        if ASN1.decode_is_opening_tag_number(buffer, offset + leng, 2):
            leng += 1
            self.expiration_time = BACnetDateTime()
            leng += self.expiration_time.ASN1decode(buffer, offset + leng, apdu_len - leng)
            leng += 1

        else:
            return -1

        self.key_ids = []
        if ASN1.decode_is_opening_tag_number(buffer, offset + leng, 3) and leng < apdu_len:
            leng += 1

            while not ASN1.decode_is_closing_tag_number(buffer, offset + leng, 3):

                b_value = BACnetKeyIdentifier()
                leng += b_value.ASN1decode(buffer, offset+leng, apdu_len-leng)

                self.key_ids.append(b_value)
            leng += 1
        else:
            return -1

        return leng


# todo BACnetDestination add ASN1encodeInterface
class BACnetDestination(ASN1encodeInterface):
    def __init__(self, valid_days:BACnetDaysOfWeek = None,
                 from_time:time = None,
                 to_time:time = None,
                 recipient:BACnetRecipient = None,
                 process_identifier:int = None,
                 issue_confirmed_notifications:bool = None,
                 transitions:BACnetEventTransitionBits = None):
        self.valid_days = valid_days
        self.from_time = from_time
        self.to_time = to_time
        self.recipient = recipient
        self.process_identifier = process_identifier
        self.issue_confirmed_notifications = issue_confirmed_notifications
        self.transitions = transitions

    def __str__(self):
        return "\n\t\t\tvalid_days: "+str(self.valid_days)+ \
               "\n\t\t\tfrom_time: " + str(self.from_time) + \
               "\n\t\t\tto_time: " + str(self.to_time) + \
               "\n\t\t\trecipient: "+str(self.recipient)+ \
               "\n\t\t\tprocess_identifier: " + str(self.process_identifier) + \
               "\n\t\t\tissue_confirmed_notifications: "+str(self.issue_confirmed_notifications)+ \
               "\n\t\t\ttransitions: " + str(self.transitions)

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0

        leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        if tag_number != BACnetApplicationTags.BIT_STRING:

            return -1
        leng += leng1
        self.valid_days = BACnetDaysOfWeek()

        leng1 = self.valid_days.ASN1decode(buffer, offset+leng, len_value)

        if leng1 < 0:

            return -1
        leng += leng1

        leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        if tag_number != BACnetApplicationTags.TIME:

            return -1
        leng += leng1
        leng1, self.from_time = ASN1.decode_bacnet_time_safe(buffer, offset+leng, len_value)

        leng += leng1


        leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        if tag_number != BACnetApplicationTags.TIME:
            return -1
        leng += leng1
        leng1, self.to_time = ASN1.decode_bacnet_time_safe(buffer, offset + leng, len_value)

        leng += leng1


        self.recipient = BACnetRecipient()
        leng1 = self.recipient.ASN1decode(buffer, offset + leng, apdu_len - leng)

        if leng1 < 0:

            return -1
        leng += leng1


        leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        if tag_number != BACnetApplicationTags.UNSIGNED_INT:
            return -1
        leng += leng1
        leng1, self.process_identifier = ASN1.decode_unsigned(buffer, offset + leng, len_value)

        leng += leng1


        leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        if tag_number != BACnetApplicationTags.BOOLEAN:
            return -1
        leng += leng1
        if len_value > 0:
            self.issue_confirmed_notifications = True
        else:
            self.issue_confirmed_notifications = False


        leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        if tag_number != BACnetApplicationTags.BIT_STRING:
            return -1
        leng += leng1

        self.transitions = BACnetEventTransitionBits()
        leng1 = self.transitions.ASN1decode(buffer, offset + leng, len_value)
        if leng1 < 0:

            return -1
        leng += leng1

        return leng


# todo BACnetRouterEntry add ASN1encodeInteface
class BACnetRouterEntry(ASN1encodeInterface):
    class statuschoice(enum.IntEnum):
        available = 0
        busy = 1
        disconnected = 2

    def __init__(self, network_number: int = None, mac_address: bytes = None, status:statuschoice = None,performance_index:int = None):
        self.network_number = network_number
        self.mac_address = mac_address
        self.status = status
        self.performance_index = performance_index

    def ASN1decode(self, buffer, offset, apdu_len):
        leng = 0
        #network_number
        leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        if tag_number != BACnetApplicationTags.UNSIGNED_INT:
            return -1
        leng += leng1
        leng1, self.network_number = ASN1.decode_unsigned(buffer, offset + leng, len_value)
        leng += leng1

        #mac_address
        leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        if tag_number != BACnetApplicationTags.OCTET_STRING:
            return -1
        leng += leng1
        leng1, self.mac_address = ASN1.decode_octet_string(buffer, offset + leng, len_value)
        leng += leng1

        # status
        leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
        if tag_number != BACnetApplicationTags.ENUMERATED:
            return -1
        leng += leng1
        leng1, u_val = ASN1.decode_unsigned(buffer, offset + leng, len_value)
        leng += leng1
        self.status = BACnetRouterEntry.statuschoice(u_val)

        # performance_index optional
        if leng < apdu_len:
            leng1, tag_number, len_value = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            if tag_number != BACnetApplicationTags.UNSIGNED_INT:
                leng += leng1
                leng1, self.network_number = ASN1.decode_unsigned(buffer, offset + leng, len_value)
                leng += leng1

        return leng


# todo BACnetAccessRule add ASN1decode, ASN1encodeInterface
class BACnetAccessRule(ASN1encodeInterface):
    class timerangespecifierChoice(enum.IntEnum):
        specified = 0
        always = 1

    class locationspecifierChoice(enum.IntEnum):
        specified = 0
        all = 1

    def __init__(self, time_range_specifier:timerangespecifierChoice = None,
                 time_range:BACnetDeviceObjectPropertyReference = None,
                 location_specifier:locationspecifierChoice = None,
                 location:BACnetDeviceObjectReference = None,
                 enable:bool = None):
        self.time_range_specifier = time_range_specifier
        self.time_range = time_range
        self.location_specifier = location_specifier
        self.location = location
        self.enable = enable

    def ASN1decode(self, buffer, offset, apdu_len):
        pass


# todo BACnetNameValue add ASN1decode, ASN1encodeInterface
class BACnetNameValue:
    def __init__(self, name:str = None,
                 value:BACnetValue = None):
        self.name = name
        self.value = value

    def ASN1decode(self, buffer, offset, apdu_len):
        pass


# todo BACnetNameValueCollection add ASN1decode, ASN1encodeInterface
class BACnetNameValueCollection:
    def __init__(self, members:[] = None):
        self.members = members

    def ASN1decode(self, buffer, offset, apdu_len):
        pass


# todo BACnetNetworkSecurityPolicy add ASN1decode, ASN1encodeInterface
class BACnetNetworkSecurityPolicy:
    def __init__(self, port_id:int = None,
                 security_level:BACnetSecurityPolicy = None):
        self.port_id = port_id
        self.security_level = security_level

    def ASN1decode(self, buffer, offset, apdu_len):
        pass


# todo BACnetPortPermission add ASN1decode, ASN1encodeInterface
class BACnetPortPermission:
    def __init__(self, port_id:int = None,
                 enabled:bool = None):
        self.port_id = port_id
        self.enabled = enabled

    def ASN1decode(self, buffer, offset, apdu_len):
        pass


# todo BACnetPriorityArray add ASN1decode, ASN1encodeInterface
class BACnetPriorityArray:
    # SEQUENCE SIZE (16) OF BACnetPriorityValue
    def __init__(self, value:[16] = None):
        self.value = value

    def ASN1decode(self, buffer, offset, apdu_len):
        pass


# todo BACnetPriorityValue add ASN1decode, ASN1encodeInterface
class BACnetPriorityValue:
    def __init__(self, value = None):
        self.value = value

    def ASN1decode(self, buffer, offset, apdu_len):
        pass


# todo BACnetProcessIdSelection add ASN1decode, ASN1encodeInterface
class BACnetProcessIdSelection:
    def __init__(self, value = None):
        self.value = value

    def ASN1decode(self, buffer, offset, apdu_len):
        pass


# todo BACnetPropertyAccessResult add ASN1decode, ASN1encodeInterface
class BACnetPropertyAccessResult:
    def __init__(self, object_identifier:BACnetObjectIdentifier = None,
                 property_identifier:BACnetPropertyIdentifier = None,
                 property_array_index:int = None,
                 device_identifier:BACnetObjectIdentifier = None,
                 access_result = None):
        self.object_identifier  = object_identifier
        self.property_identifier = property_identifier
        self.property_array_index = property_array_index
        self.device_identifier  = device_identifier
        self.access_result  = access_result

    def ASN1decode(self, buffer, offset, apdu_len):
        pass


# todo BACnetSetpointReference add ASN1decode, ASN1encodeInterface
class BACnetSetpointReference:
    def __init__(self, value = None):
        self.value = value

    def ASN1decode(self, buffer, offset, apdu_len):
        pass


# todo BACnetSpecialEvent add ASN1decode, ASN1encodeInterface
class BACnetSpecialEvent:
    def __init__(self, period = None,
                 list_of_time_values:[] = None,
                 event_priority:int = None):
        self.period = period
        self.list_of_time_values = list_of_time_values
        self.event_priority = event_priority

    def ASN1decode(self, buffer, offset, apdu_len):
        pass


# todo BACnetTimerStateChangeValue add ASN1decode, ASN1encodeInterface
class BACnetTimerStateChangeValue:
    def __init__(self, value = None):
        self.value = value

    def ASN1decode(self, buffer, offset, apdu_len):
        pass


# todo BACnetTimeValue add ASN1decode, ASN1encodeInterface
class BACnetTimeValue:
    def __init__(self, Time:time = None,
                 value = None):
        self.Time = Time
        self.value = value

    def ASN1decode(self, buffer, offset, apdu_len):
        pass

# todo BACnetValueSource add ASN1decode, ASN1encodeInterface
class BACnetValueSource:
    def __init__(self, value = None):
        self.value = value

    def ASN1decode(self, buffer, offset, apdu_len):
        pass

# todo BACnetVMACEntry add ASN1decode, ASN1encodeInterface
class BACnetVMACEntry:
    def __init__(self, virtual_mac_address = None, native_mac_address = None):
        self.virtual_mac_address = virtual_mac_address
        self.native_mac_address = native_mac_address

    def ASN1decode(self, buffer, offset, apdu_len):
        pass

# todo BACnetVTSession add ASN1decode, ASN1encodeInterface
class BACnetVTSession:
    def __init__(self, local_vt_session_id:int = None,
                 remote_vt_session_id:int = None,
                 remote_vt_address:BACnetAddress = None):
        self.local_vt_session_id  = local_vt_session_id
        self.remote_vt_session_id = remote_vt_session_id
        self.remote_vt_address = remote_vt_address

    def ASN1decode(self, buffer, offset, apdu_len):
        pass

# todo BACnetAccessThreatLevel? add ASN1decode, ASN1encodeInterface
class BACnetAccessThreatLevel:
    def __init__(self, value:int = None):
        self.value  = value

    def ASN1decode(self, buffer, offset, apdu_len):
        pass

# todo BACnetAssignedAccessRights add ASN1decode, ASN1encodeInterface
class BACnetAssignedAccessRights:
    def __init__(self, assigned_access_rights:BACnetDeviceObjectReference = None,
                 enable:bool = None):
        self.assigned_access_rights  = assigned_access_rights
        self.enable = enable

    def ASN1decode(self, buffer, offset, apdu_len):
        pass

# todo BACnetAssignedLandingCalls add ASN1decode, ASN1encodeInterface
class BACnetAssignedLandingCalls:
    class landing_call:
        def __init__(self, floor_number:int = None,
                     direction:BACnetLiftCarDirection = None):
            self.floor_number = floor_number
            self.direction = direction

        def ASN1decode(self, buffer, offset, apdu_len):
            pass

    def __init__(self, landing_calls:[] = None):
        self.landing_calls   = landing_calls

    def ASN1decode(self, buffer, offset, apdu_len):
        pass

# todo BACnetAuthenticationFactor add ASN1decode, ASN1encodeInterface
class BACnetAuthenticationFactor:
    def __init__(self, format_type:BACnetAuthenticationFactorType = None,
                 format_class:int = None,
                 value:bytes = None):
        self.format_type = format_type
        self.format_class = format_class
        self.value = value

    def ASN1decode(self, buffer, offset, apdu_len):
        pass


# todo BACnetAuthenticationFactorFormat add ASN1decode, ASN1encodeInterface
class BACnetAuthenticationFactorFormat:
    def __init__(self, format_type:BACnetAuthenticationFactorType = None,
                 vendor_id:int = None,
                 vendor_format:int = None):
        self.format_type = format_type
        self.vendor_id = vendor_id
        self.vendor_format = vendor_format

    def ASN1decode(self, buffer, offset, apdu_len):
        pass


# todo BACnetAuthenticationPolicy add ASN1decode, ASN1encodeInterface
class BACnetAuthenticationPolicy:
    class policy:
        def __init__(self, credential_data_input:BACnetDeviceObjectReference = None,
                     index: int = None):
            self.credential_data_input = credential_data_input
            self.index = index

    def __init__(self, policies:[] = None,
                 order_enforced:bool = None,
                 timeout:int = None):
        self.policies = policies
        self.order_enforced = order_enforced
        self.timeout = timeout

    def ASN1decode(self, buffer, offset, apdu_len):
        pass


# todo BACnetBDTEntry add ASN1decode, ASN1encodeInterface

# todo BACnetChannelValue add ASN1decode, ASN1encodeInterface
class BACnetChannelValue:
    def __init__(self, value = None):
        self.value = value

    def ASN1decode(self, buffer, offset, apdu_len):
        pass


# todo BACnetCOVSubscription add ASN1decode, ASN1encodeInterface
class BACnetCOVSubscription:
    def __init__(self, recipient:BACnetRecipientProcess = None,
                 monitored_property_reference:BACnetObjectPropertyReference = None,
                 issue_confirmed_notifications:bool = None,
                 time_remaining:int = None,
                 cov_increment:float = None):
        self.recipient = recipient
        self.monitored_property_reference = monitored_property_reference
        self.issue_confirmed_notifications = issue_confirmed_notifications
        self.time_remaining = time_remaining
        self.cov_increment = cov_increment

    def ASN1decode(self, buffer, offset, apdu_len):
        pass


# todo BACnetCredentialAuthenticationFactor add ASN1decode, ASN1encodeInterface
class BACnetCredentialAuthenticationFactor:
    def __init__(self, disable:BACnetAccessAuthenticationFactorDisable = None,
                 authentication_factor:BACnetAuthenticationFactor = None):
        self.disable = disable
        self.authentication_factor = authentication_factor

    def ASN1decode(self, buffer, offset, apdu_len):
        pass


# todo BACnetDailySchedule add ASN1decode, ASN1encodeInterface
class BACnetDailySchedule:
    def __init__(self, day_schedule:[] = None):
        self.day_schedule = day_schedule

    def ASN1decode(self, buffer, offset, apdu_len):
        pass


# todo BACnetEventNotificationSubscription add ASN1decode, ASN1encodeInterface
class BACnetEventNotificationSubscription:
    def __init__(self, recipient:BACnetRecipient = None,
                 process_identifier:int = None,
                 issue_confirmed_notifications:bool = None,
                 time_remaining:int = None):
        self.recipient = recipient
        self.process_identifier = process_identifier
        self.issue_confirmed_notifications = issue_confirmed_notifications
        self.time_remaining = time_remaining

    def ASN1decode(self, buffer, offset, apdu_len):
        pass


# todo BACnetEventParameter add ASN1decode, ASN1encodeInterface
class BACnetEventParameter:
    def __init__(self, value = None):
        self.value = value

    def ASN1decode(self, buffer, offset, apdu_len):
        pass


# todo BACnetFaultParameter add ASN1decode, ASN1encodeInterface
class BACnetFaultParameter:
    def __init__(self, value = None):
        self.value = value

    def ASN1decode(self, buffer, offset, apdu_len):
        pass


# todo BACnetFDTEntry add ASN1decode, ASN1encodeInterface
# todo BACnetGroupChannelValue add ASN1decode, ASN1encodeInterface
# todo BACnetLandingCallStatus add ASN1decode, ASN1encodeInterface
# todo BACnetLandingDoorStatus add ASN1decode, ASN1encodeInterface
# todo BACnetLiftCarCallList add ASN1decode, ASN1encodeInterface
# todo BACnetLogData add ASN1decode, ASN1encodeInterface
# todo BACnetLogMultipleRecord add ASN1decode, ASN1encodeInterface
# todo BACnetCOVMultipleSubscription add ASN1decode, ASN1encodeInterface
# todo BACnetClientCOV add ASN1decode, ASN1encodeInterface
# todo BACnetOptionalBinaryPV add ASN1decode, ASN1encodeInterface
# todo BACnetOptionalCharacterString add  ASN1decode, ASN1encodeInterface
# todo BACnetOptionalREAL add ASN1decode, ASN1encodeInterface
# todo BACnetOptionalUnsigned add ASN1decode, ASN1encodeInterface

class BacnetBvlcFunctions(enum.IntEnum):
    BVLC_RESULT = 0
    BVLC_WRITE_BROADCAST_DISTRIBUTION_TABLE = 1
    BVLC_READ_BROADCAST_DIST_TABLE = 2
    BVLC_READ_BROADCAST_DIST_TABLE_ACK = 3
    BVLC_FORWARDED_NPDU = 4
    BVLC_REGISTER_FOREIGN_DEVICE = 5
    BVLC_READ_FOREIGN_DEVICE_TABLE = 6
    BVLC_READ_FOREIGN_DEVICE_TABLE_ACK = 7
    BVLC_DELETE_FOREIGN_DEVICE_TABLE_ENTRY = 8
    BVLC_DISTRIBUTE_BROADCAST_TO_NETWORK = 9
    BVLC_ORIGINAL_UNICAST_NPDU = 10
    BVLC_ORIGINAL_BROADCAST_NPDU = 11

class BVLC_new:
    def __init__(self, type = None,function:BacnetBvlcFunctions = None, length:int = None):
        self.type = type
        self.function = function
        self.length = length

    def decode(self, buffer, offset) ->int:
        leng = 0
        self.type = buffer[offset+leng]
        leng += 1
        self.function = buffer[offset+leng]
        leng += 1
        self.length = buffer[offset+leng]
        leng += 1


        return leng

class BVLC:
    BVLL_TYPE_BACNET_IP = 0x81
    BVLC_HEADER_LENGTH = 4

    def __init__(self, transport):
        if type(transport) == BacnetIpUdpProtocolTransport:
            # self.BVLL_TYPE_BACNET_IP = 0x81
            # self.BVLC_HEADER_LENGTH = 4
            BVLC_MAX_APDU = BacnetMaxAdpu.MAX_APDU1476

        """ IPV6???????
        if type(transport) == 
        """

    def Decode(buffer, offset):
        type = buffer[0]
        function = buffer[1]
        msg_length = struct.unpack('!H', buffer[2:4])[0]

        if type != BVLC.BVLL_TYPE_BACNET_IP or msg_length != len(buffer):
            print("BVLC no correct Bacnet Message!!!")

        if function == BacnetBvlcFunctions.BVLC_RESULT:
            return (4, function, msg_length)
        elif function == BacnetBvlcFunctions.BVLC_ORIGINAL_UNICAST_NPDU:
            return (4, function, msg_length)
        elif function == BacnetBvlcFunctions.BVLC_ORIGINAL_BROADCAST_NPDU:
            return (4, function, msg_length)
        elif function == BacnetBvlcFunctions.BVLC_FORWARDED_NPDU:
            pass
        elif function == BacnetBvlcFunctions.BVLC_DISTRIBUTE_BROADCAST_TO_NETWORK:
            pass
        elif function == BacnetBvlcFunctions.BVLC_REGISTER_FOREIGN_DEVICE:
            pass
        elif function == BacnetBvlcFunctions.BVLC_READ_FOREIGN_DEVICE_TABLE:
            pass
        elif function == BacnetBvlcFunctions.BVLC_DELETE_FOREIGN_DEVICE_TABLE_ENTRY:
            pass
        elif function == BacnetBvlcFunctions.BVLC_READ_BROADCAST_DIST_TABLE:
            pass
        elif function == BacnetBvlcFunctions.BVLC_WRITE_BROADCAST_DISTRIBUTION_TABLE:
            pass
        else:
            return (-1, None, None)

    def First4BytesHeaderEncode(function, msg_length):
        b = bytearray(4)
        b[0] = BVLC.BVLL_TYPE_BACNET_IP
        print(function)
        b[1] = function
        b[2] = ((msg_length) & 0xFF00) >> 8
        b[3] = ((msg_length) & 0x00FF) >> 0
        return b

    def encode(offset, function, msg_length):
        return BVLC.First4BytesHeaderEncode(function, msg_length)

class ASN1:
    BACNET_MAX_OBJECT = 0x3FF
    BACNET_INSTANCE_BITS = 22
    BACNET_MAX_INSTANCE = 0x3FFFFF
    MAX_BITSTRING_BYTES = 15
    BACNET_ARRAY_ALL = 0xFFFFFFFF
    BACNET_NO_PRIORITY = 0
    BACNET_MIN_PRIORITY = 1
    BACNET_MAX_PRIORITY = 16

    def encode_bacnet_object_id(object_type, instance):
        return ASN1.encode_unsigned32(((object_type & ASN1.BACNET_MAX_OBJECT) << ASN1.BACNET_INSTANCE_BITS) | (
                    instance & ASN1.BACNET_MAX_INSTANCE))

    def encode_tag(tag_number: BACnetApplicationTags, context_specific, len_value_type):
        tag = list()
        value = 0
        if context_specific:
            value = 0x8

        if tag_number <= 14:
            value += tag_number << 4
            tag.extend(struct.pack('!B', value))
        else:
            value += 0xF0
            tag.extend(struct.pack('!B', value))
            tag.extend(struct.pack('!B', tag_number))

        if len_value_type <= 4:
            tag[0] += len_value_type
            return bytes(tag)
        else:
            tag[0] += 5
            if len_value_type <= 253:
                tag.extend(struct.pack('!B', len_value_type))
                return bytes(tag)
            elif len_value_type <= 65535:
                tag.extend(struct.pack('!B', 254))
                return bytes(tag) + ASN1.encode_unsigned16(len_value_type)
            else:
                tag.extend(struct.pack('!B', 255))
                return bytes(tag) + ASN1.encode_unsigned32(len_value_type)

    def encode_bacnet_enumerated(value: int):
        return ASN1.encode_bacnet_unsigned(value)

    def encode_unsigned16(value: int):
        return bytes(struct.pack('!H', value))

    def encode_unsigned24(value: int):
        ret_value = list()
        ret_value.extend(struct.pack('!B', (value & 0xff0000) >> 16))
        ret_value.extend(struct.pack('!B', (value & 0x00ff00) >> 8))
        ret_value.extend(struct.pack('!B', (value & 0x0000ff) >> 0))
        return bytes(ret_value)

    def encode_unsigned32(value: int):
        return bytes(struct.pack('!I', value))

    def encode_bacnet_unsigned(value: int):
        if value < 0x100:
            return bytes(struct.pack('!B', value))
        elif value < 0x10000:
            return ASN1.encode_unsigned16(value)
        elif value < 0x1000000:
            return ASN1.encode_unsigned24(value)
        else:
            return ASN1.encode_unsigned32(value)

    def encode_signed16(value):
        return bytes(struct.pack('!h', value))

    def encode_signed24(value):
        ret_value = list()
        ret_value.extend(struct.pack('!B', (value & 0xff0000) >> 16))
        ret_value.extend(struct.pack('!B', (value & 0x00ff00) >> 8))
        ret_value.extend(struct.pack('!B', (value & 0x0000ff) >> 0))
        return bytes(ret_value)

    def encode_signed32(value):
        return bytes(struct.pack('!i', value))

    def encode_opening_tag(tag_number):
        tag = list()

        tag.extend(struct.pack('!B', 0x8))
        if tag_number <= 14:
            tag[0] = tag[0] | (tag_number << 4)
        else:
            tag[0] = tag[0] | 0xF0
            tag.extend(struct.pack('!B', tag_number))

        # set type field to opening tag *
        tag[0] = tag[0] | 6
        return bytes(tag)

    def encode_closing_tag(tag_number):
        tag = list()
        tag.extend(struct.pack('!B', 0x8))
        if tag_number <= 14:
            tag[0] = tag[0] | (tag_number << 4)
        else:
            tag[0] = tag[0] | 0xF0
            tag.extend(struct.pack('!B', tag_number))

        # set type field to closing tag *
        tag[0] = tag[0] | 7

        return bytes(tag)

    def encode_context_character_string(tag_number: int, value: str):
        tmp = ASN1.encode_bacnet_character_string(value)
        return ASN1.encode_tag(tag_number, True, len(tmp)) + tmp

    def encode_context_object_id(tag_number, object_type, instance):
        return ASN1.encode_tag(tag_number, True, 4) + ASN1.encode_bacnet_object_id(object_type, instance)

    def encode_context_enumerated(tag_number, value):
        length = 0
        if value < 0x100:
            length = 1
        elif value < 0x10000:
            length = 2
        elif value < 0x1000000:
            length = 3
        else:
            length = 4

        return ASN1.encode_tag(tag_number, True, length) + ASN1.encode_bacnet_enumerated(value)

    def encode_bacnet_signed(value):
        if value >= -128 and value < 128:
            return bytes(struct.pack('!b', value))
        elif value >= -32768 and value < 32768:
            return ASN1.encode_signed16(value)

        elif value > -8388607 and value < 8388608:
            return ASN1.encode_signed24(value)

        else:
            return ASN1.encode_signed32(value)

    def encode_bacnet_real(value):
        return bytes(struct.pack('!f', value))

    def encode_bacnet_double(value):
        return bytes(struct.pack('!d', value))

    def encode_application_boolean(boolean_value):
        if boolean_value == True:
            return ASN1.encode_tag(BACnetApplicationTags.BOOLEAN, False, 1)
        else:
            return ASN1.encode_tag(BACnetApplicationTags.BOOLEAN, False, 0)

    def encode_application_unsigned(value: int):
        tmp = ASN1.encode_bacnet_unsigned(value)
        return ASN1.encode_tag(BACnetApplicationTags.UNSIGNED_INT, False, len(tmp)) + tmp

    def encode_application_signed(value):
        tmp = ASN1.encode_bacnet_signed(value)
        return ASN1.encode_tag(BACnetApplicationTags.SIGNED_INT, False, len(tmp)) + tmp

    def encode_application_real(value):
        return ASN1.encode_tag(BACnetApplicationTags.REAL, False, 4) + \
               ASN1.encode_bacnet_real(value)

    def encode_application_double(value):
        return ASN1.encode_tag(BACnetApplicationTags.DOUBLE, False, 8) + \
               ASN1.encode_bacnet_double(value)

    def encode_octet_string(octet_string, octet_offset, octet_count):
        ret_value = list()
        if octet_string != None:

            for i in range(octet_offset, (octet_offset + octet_count)):
                ret_value.extend(struct.pack('!B', octet_string[i]))
        return bytes(ret_value)

    def encode_context_unsigned(tag_number: int, value: int):
        lenght = 0

        if value < 0x100:
            lenght = 1
        elif value < 0x10000:
            lenght = 2
        elif value < 0x1000000:
            lenght = 3
        else:
            lenght = 4
        return ASN1.encode_tag(tag_number, True, lenght) + \
               ASN1.encode_bacnet_unsigned(value)

    def encode_application_octet_string(octet_string, octet_offset, octet_count):
        return ASN1.encode_tag(BACnetApplicationTags.OCTET_STRING, False, octet_count) + \
               ASN1.encode_octet_string(octet_string, octet_offset, octet_count)

    def encode_application_character_string(value):
        tmp = ASN1.encode_bacnet_character_string(value)
        return ASN1.encode_tag(BACnetApplicationTags.CHARACTER_STRING, False, len(tmp)) + \
               tmp

    def encode_bacnet_character_string(value):
        return bytes(struct.pack('!B', BacnetCharacterStringEncodings.CHARACTER_UTF8)) + bytes(value, "utf-8")

    def encode_application_bitstring(bit_string):
        print("needs to be added bitstring!!!")
        pass  # needs something!!! bacnetbitstring

    def encode_application_enumerated(value: int):
        tmp = ASN1.encode_bacnet_enumerated(value)

        return ASN1.encode_tag(BACnetApplicationTags.ENUMERATED, False, len(tmp)) + \
               tmp

    def encode_bacnet_date(value: date):
        return (value.year - 1900).to_bytes(1, byteorder='big') + value.month.to_bytes(1,
                                                                                       byteorder='big') + value.day.to_bytes(
            1, byteorder='big') + value.isoweekday().to_bytes(1, byteorder='big')

    def encode_bacnet_time(value: time):
        return value.hour.to_bytes(1, byteorder='big') + value.minute.to_bytes(1,
                                                                               byteorder='big') + value.second.to_bytes(
            1, byteorder='big') + (int(value.microsecond / 10000)).to_bytes(1, byteorder='big')

    def encode_application_date(value: date):
        return ASN1.encode_tag(BACnetApplicationTags.DATE, False, 4) + ASN1.encode_bacnet_date(value)

    def encode_application_time(value: time):
        buffer = ASN1.encode_tag(BACnetApplicationTags.TIME, False, 4)
        return ASN1.encode_tag(BACnetApplicationTags.TIME, False, 4) + ASN1.encode_bacnet_time(value)

    def bacapp_encode_application_data(value):
        if value.Value == None:
            return bytes(struct.pack('!B', BACnetApplicationTags.BACNET_APPLICATION_TAG_NULL))

        if value.Tag == BACnetApplicationTags.NULL:
            pass
        elif value.Tag == BACnetApplicationTags.BOOLEAN:
            return ASN1.encode_application_boolean(value.Value)
        elif value.Tag == BACnetApplicationTags.UNSIGNED_INT:
            return ASN1.encode_application_unsigned(value.Value)
        elif value.Tag == BACnetApplicationTags.SIGNED_INT:
            return ASN1.encode_application_signed(value.Value)
        elif value.Tag == BACnetApplicationTags.REAL:
            return ASN1.encode_application_real(value.Value)
        elif value.Tag == BACnetApplicationTags.DOUBLE:
            return ASN1.encode_application_double(value.Value)
        elif value.Tag == BACnetApplicationTags.OCTET_STRING:
            return ASN1.encode_application_octet_string(value.Value, 0, len(value.Value))
        elif value.Tag == BACnetApplicationTags.CHARACTER_STRING:
            return ASN1.encode_application_character_string(value.Value)
        elif value.Tag == BACnetApplicationTags.BIT_STRING:
            return ASN1.encode_application_bitstring(value.Value)
        elif value.Tag == BACnetApplicationTags.ENUMERATED:
            return ASN1.encode_application_enumerated(value.Value)
        elif value.Tag == BACnetApplicationTags.DATE:
            return ASN1.encode_application_date(value.Value)
        elif value.Tag == BACnetApplicationTags.TIME:
            return ASN1.encode_application_time(value.Value)
        else:
            print("bacapp_encode_application_data missing tag")

    def decode_unsigned(buffer, offset, len_value):
        value = 0
        for i in range(0, len_value):
            value += buffer[offset + i] << (8 * (len_value - i - 1))
        return (len_value, value)

    def IS_EXTENDED_TAG_NUMBER(x):
        return ((x & 0xF0) == 0xF0)

    def IS_EXTENDED_VALUE(x):
        return ((x & 0x07) == 5)

    def IS_CONTEXT_SPECIFIC(x):
        return ((x & 0x8) == 0x8)

    def IS_OPENING_TAG(x):
        return ((x & 0x07) == 6)

    def IS_CLOSING_TAG(x):
        return ((x & 0x07) == 7)

    def decode_tag_number(buffer, offset):  # byte[] buffer, int offset, out byte tag_number)
        leng = 1  # return value */

        # decode the tag number first
        if ASN1.IS_EXTENDED_TAG_NUMBER(buffer[offset]):
            # extended tag
            tag_number = buffer[offset + leng]
            leng += 1
        else:
            tag_number = buffer[offset] >> 4

        return (leng, tag_number)

    def decode_signed(buffer, offset, len_value):
        value = 0
        for i in range(0, len_value):
            value += buffer[offset + i] << (8 * (len_value - i - 1))
        # check if is negativ
        if value > (256 ** len_value) / 2 - 1:
            value = -(256 ** len_value - value)
        return (len_value, value)

    def decode_real(buffer, offset):
        return (4, struct.unpack("!f", buffer[offset:(offset + 4)])[0])

    def decode_real_safe(buffer, offset, len_value):  # byte[] buffer, int offset, uint len_value, out float value)

        if len_value != 4:
            value = 0.0
            return (len_value, value)
        else:
            (leng, value) = ASN1.decode_real(buffer, offset)
        return (leng, value)

    def decode_double(buffer, offset):
        return (8, struct.unpack("!d", buffer[offset:(offset + 8)])[0])

    def decode_double_safe(buffer, offset, len_value):
        if (len_value != 8):
            value = 0.0
            return (len_value, value)
        else:
            (leng, value) = ASN1.decode_double(buffer, offset)
        return (leng, value)

    def decode_octet_string(buffer, offset,
                            len_value_type):  # byte[] buffer, int offset, int max_length, byte[] octet_string, int octet_string_offset, uint octet_string_length)
        tmp = bytes(buffer[offset:(offset + len_value_type)])
        return (len(tmp), tmp)

    def multi_charset_characterstring_decode(buffer, offset, max_length, encoding, length):

        char_string = ""
        enc = 'utf_8'  # default
        if encoding == BacnetCharacterStringEncodings.CHARACTER_UTF8:
            enc = 'utf_8'
        elif encoding == BacnetCharacterStringEncodings.CHARACTER_UCS2:
            enc = 'utf_16'
        elif encoding == BacnetCharacterStringEncodings.CHARACTER_UCS4:
            enc = 'utf_32'  # probaby doesn't exist
        elif encoding == BacnetCharacterStringEncodings.CHARACTER_ISO8859:
            enc = 'latin_1'
        elif encoding == BacnetCharacterStringEncodings.CHARACTER_JISX_0208:
            enc = 'shift_jisx0213'
        elif encoding == BacnetCharacterStringEncodings.CHARACTER_MS_DBCS:
            enc = 'dbcs'

        c = list()
        for i in range(length):
            c.extend(struct.unpack('!B', buffer[offset + i:offset + i + 1]))

        if enc == 'utf_8':
            char_string = bytes(c).decode('latin_1')  ### for ÜäööäüööÖÖÄÄÖÖ and so on!!!!!
            c = char_string.encode(enc)
            char_string = bytes(c).decode('utf_8')

        else:
            char_string = bytes(c).decode(enc)

        return (True, char_string)

    def decode_character_string(buffer, offset, max_length, len_value):
        leng = 0
        status = False

        (status, char_string) = ASN1.multi_charset_characterstring_decode(buffer, offset + 1, max_length,
                                                                          buffer[offset], len_value - 1)
        if (status):
            leng = len_value
        return (leng, char_string)

    def decode_context_character_string(buffer, offset, max_length,
                                        tag_number):
        leng = 0
        status = False
        len_value = 0
        char_string = ""
        if ASN1.decode_is_context_tag(buffer, offset + leng, tag_number):
            (leng1, tag_number, len_value) = ASN1.decode_tag_number_and_value(buffer, offset + leng)
            leng += leng1
            (status, char_string) = ASN1.multi_charset_characterstring_decode(buffer, offset + 1 + leng, max_length,
                                                                              buffer[offset + leng], len_value - 1)
            if status:
                leng += len_value
            else:
                leng = -1

        return (leng, char_string)

    def decode_date(buffer, offset):  # byte[] buffer, int offset, out DateTime bdate)
        (year, month, day, wday) = struct.unpack('BBBB', buffer[offset:(offset + 4)])
        if (month == 0xFF and day == 0xFF and wday == 0xFF and year == 0xFF):
            bdate = date(1, 1, 1)
        else:
            bdate = date(year + 1900, month, day)
        return (4, bdate)

    def decode_date_safe(buffer, offset, len_value):  # byte[] buffer, int offset, uint len_value, out DateTime bdate)
        if (len_value != 4):
            return (len_value, date(1, 1, 1))
        else:
            return ASN1.decode_date(buffer, offset)

    def decode_bacnet_time(buffer, offset):  # byte[] buffer, int offset, out DateTime btime)
        (hour, min, sec, hundredths) = struct.unpack('BBBB', buffer[offset:(offset + 4)])
        if (hour == 0xFF and min == 0xFF and sec == 0xFF and hundredths == 0xFF):
            btime = time(1, 1, 1, 1)
        else:
            if (hundredths > 100):
                hundredths = 0
            btime = time(hour, min, sec, hundredths * 10000)
        return (4, btime)

    def decode_bacnet_time_safe(buffer, offset, len_value):
        if (len_value != 4):
            return (len_value, time(1, 1, 1, 1))
        else:
            return ASN1.decode_bacnet_time(buffer, offset)

    def decode_object_id(buffer, offset):  # byte[] buffer, int offset, out ushort object_type, out uint instance)
        value = 0
        leng = 0

        (leng, value) = ASN1.decode_unsigned(buffer, offset, 4)

        object_instance = (value & ASN1.BACNET_MAX_INSTANCE)

        object_type = BACnetObjectType((int(value) >> ASN1.BACNET_INSTANCE_BITS) & ASN1.BACNET_MAX_OBJECT)

        return (leng, object_type, object_instance)

    def decode_is_context_tag_with_length(buffer, offset, tag_number):  # , out int tag_length):
        my_tag_number = 0
        (tag_length, my_tag_number) = ASN1.decode_tag_number(buffer, offset)

        return (tag_length, ((ASN1.IS_CONTEXT_SPECIFIC(buffer[offset]) and (my_tag_number == tag_number))))

    def decode_object_id_safe(buffer, offset,
                              len_value):  # byte[] buffer, int offset, uint len_value, out ushort object_type, out uint instance)
        if len_value != 4:
            return (0, 0, 0)
        else:
            return ASN1.decode_object_id(buffer, offset)

    def decode_context_object_id(buffer, offset, tag_number):
        leng = 0
        (leng, is_context) = ASN1.decode_is_context_tag_with_length(buffer, offset + leng, tag_number)

        if is_context:
            (leng1, object_type, instance) = ASN1.decode_object_id(buffer, offset + leng)
            leng += leng1
        else:
            object_type = 0
            instance = 0
            leng = -1

        return (leng, object_type, instance)

    def decode_application_time(buffer, offset):  # byte[] buffer, int offset, out DateTime btime)
        leng = 0
        (leng1, tag_number) = ASN1.decode_tag_number(buffer, offset + leng)
        leng += leng1

        if tag_number == BACnetApplicationTags.TIME:
            (leng1, btime) = ASN1.decode_bacnet_time(buffer, offset + leng)
            leng += leng1
        else:
            btime = time(1, 1, 1)
            leng = -1
        return (leng, btime)

    def decode_application_date(buffer, offset):  # (byte[] buffer, int offset, out DateTime bdate)

        leng = 0
        (leng1, tag_number) = ASN1.decode_tag_number(buffer, offset + leng)
        leng += leng1
        if tag_number == BACnetApplicationTags.DATE:
            (leng1, bdate) = ASN1.decode_date(buffer, offset + leng)
            leng += leng1
        else:
            bdate = date(1, 1, 1)
            leng = -1
        return (leng, bdate)

    def decode_tag_number_and_value(buffer, offset):

        (leng, tag_number) = ASN1.decode_tag_number(buffer, offset)

        if ASN1.IS_EXTENDED_VALUE(buffer[offset]):

            if buffer[offset + leng] == 255:
                leng += 1
                (leng1, value32) = ASN1.decode_unsigned(buffer, offset + leng, 4)
                leng += leng1
                value = value32
            elif buffer[offset + leng] == 254:
                leng += 1
                (leng1, value16) = ASN1.decode_unsigned(buffer, offset + leng, 2)
                leng += leng1
                value = value16
            else:
                value = buffer[offset + leng]
                leng += 1

        elif ASN1.IS_OPENING_TAG(buffer[offset]):

            value = 0
        elif ASN1.IS_CLOSING_TAG(buffer[offset]):

            value = 0
        else:

            value = buffer[offset] & 0x07

        return (leng, tag_number, value)

    def decode_enumerated(buffer, offset, len_value, obj_type: BACnetObjectType = None,
                          prop_id: BACnetPropertyIdentifier = None):
        (leng, value) = ASN1.decode_unsigned(buffer, offset, len_value)
        if prop_id != None:
            # faster for None Type
            try:
                if prop_id == BACnetPropertyIdentifier.SEGMENTATION_SUPPORTED:
                    value = BACnetSegmentation(value)
                elif prop_id == BACnetPropertyIdentifier.PROPERTY_LIST:
                    value = BACnetPropertyIdentifier(value)
                elif prop_id == BACnetPropertyIdentifier.EVENT_TYPE:
                    value = BACnetEventType(value)
                elif prop_id == BACnetPropertyIdentifier.NOTIFY_TYPE:
                    value = BACnetNotifyType(value)
                elif prop_id == BACnetPropertyIdentifier.FAULT_TYPE:
                    value = BACnetFaultType(value)
                elif prop_id == BACnetPropertyIdentifier.EVENT_STATE:
                    value = BACnetEventState(value)
                elif prop_id == BACnetPropertyIdentifier.OBJECT_TYPE:
                    value = BACnetObjectType(value)
                elif prop_id == BACnetPropertyIdentifier.REASON_FOR_DISABLE:
                    value = BACnetAccessCredentialDisableReason(value)
                elif prop_id == BACnetPropertyIdentifier.CREDENTIAL_DISABLE:
                    value = BACnetAccessCredentialDisable(value)
                elif prop_id == BACnetPropertyIdentifier.PASSBACK_MODE:
                    value = BACnetAccessPassbackMode(value)
                elif prop_id == BACnetPropertyIdentifier.USER_TYPE:
                    value = BACnetAccessUserType(value)
                elif prop_id == BACnetPropertyIdentifier.NETWORK_NUMBER_QUALITY:
                    value = BACnetNetworkNumberQuality(value)
                elif prop_id == BACnetPropertyIdentifier.OCCUPANCY_STATE:
                    value = BACnetAccessZoneOccupancyState(value)
                elif obj_type == BACnetObjectType.Loop:
                    if prop_id == BACnetPropertyIdentifier.ACTION:
                        value = BACnetAction(value)
                elif obj_type == BACnetObjectType.Binary_Input or \
                        obj_type == BACnetObjectType.Binary_Output or \
                        obj_type == BACnetObjectType.Binary_Value:
                    if prop_id == BACnetPropertyIdentifier.PRESENT_VALUE or \
                            prop_id == BACnetPropertyIdentifier.ALARM_VALUE or \
                            prop_id == BACnetPropertyIdentifier.FEEDBACK_VALUE or \
                            prop_id == BACnetPropertyIdentifier.RELINQUISH_DEFAULT:
                        value = BACnetBinaryPV(value)
                elif prop_id == BACnetPropertyIdentifier.AUTHENTICATION_STATUS:
                    value = BACnetAuthenticationStatus(value)
                elif prop_id == BACnetPropertyIdentifier.AUTHORIZATION_EXEMPTIONS:
                    value = BACnetAuthorizationExemption(value)
                elif prop_id == BACnetPropertyIdentifier.AUTHORIZATION_MODE:
                    value = BACnetAuthorizationMode(value)
                elif prop_id == BACnetPropertyIdentifier.BACKUP_AND_RESTORE_STATE:
                    value = BACnetBackupState(value)
                elif prop_id == BACnetPropertyIdentifier.SYSTEM_STATUS:
                    value = BACnetDeviceStatus(value)
                elif prop_id == BACnetPropertyIdentifier.SECURED_STATUS:
                    value = BACnetDoorSecuredStatus(value)
                elif prop_id == BACnetPropertyIdentifier.DOOR_STATUS or prop_id == BACnetPropertyIdentifier.CAR_DOOR_STATUS:
                    value = BACnetDoorStatus(value)
                elif prop_id == BACnetPropertyIdentifier.UNITS or prop_id == BACnetPropertyIdentifier.CAR_LOAD_UNITS:
                    value = BACnetEngineeringUnits(value)
                elif prop_id == BACnetPropertyIdentifier.ESCALATOR_MODE:
                    value = BACnetEscalatorMode(value)
                elif prop_id == BACnetPropertyIdentifier.OPERATION_DIRECTION:
                    value = BACnetEscalatorOperationDirection(value)
                elif prop_id == BACnetPropertyIdentifier.FILE_ACCESS_METHOD:
                    value = BACnetFileAccessMethod(value)
                elif prop_id == BACnetPropertyIdentifier.OPERATION_EXPECTED:
                    value = BACnetLifeSafetyOperation(value)
                elif prop_id == BACnetPropertyIdentifier.CAR_DOOR_COMMAND:
                    value = BACnetLiftCarDoorCommand(value)
                elif prop_id == BACnetPropertyIdentifier.CAR_DRIVE_STATUS:
                    value = BACnetLiftCarDriveStatus(value)
                elif prop_id == BACnetPropertyIdentifier.CAR_MODE:
                    value = BACnetLiftCarMode(value)
                elif prop_id == BACnetPropertyIdentifier.GROUP_MODE:
                    value = BACnetLiftGroupMode(value)
                elif prop_id == BACnetPropertyIdentifier.LOGGING_TYPE:
                    value = BACnetLoggingType(value)
                elif prop_id == BACnetPropertyIdentifier.RELIABILITY:
                    value = BACnetReliability(value)
                elif prop_id == BACnetPropertyIdentifier.LAST_RESTART_REASON:
                    value = BACnetRestartReason(value)
                elif prop_id == BACnetPropertyIdentifier.NETWORK_TYPE:
                    value = BACnetNetworkType(value)
                elif prop_id == BACnetPropertyIdentifier.BASE_DEVICE_SECURITY_POLICY:
                    value = BACnetSecurityLevel(value)
                elif prop_id == BACnetPropertyIdentifier.CAR_MOVING_DIRECTION or prop_id == BACnetPropertyIdentifier.CAR_ASSIGNED_DIRECTION:
                    value = BACnetLiftCarDirection(value)
                elif prop_id == BACnetPropertyIdentifier.BACNET_IP_MODE or prop_id == BACnetPropertyIdentifier.BACNET_IPV6_MODE:
                    value = BACnetIPMode(value)
                elif prop_id == BACnetPropertyIdentifier.MAINTENANCE_REQUIRED:
                    value = BACnetMaintenance(value)
                elif prop_id == BACnetPropertyIdentifier.POLARITY:
                    value = BACnetPolarity(value)
                elif prop_id == BACnetPropertyIdentifier.SEGMENTATION_SUPPORTED:
                    value = BACnetSegmentation(value)
                elif prop_id == BACnetPropertyIdentifier.PROTOCOL_LEVEL:
                    value = BACnetProtocolLevel(value)
                elif prop_id == BACnetPropertyIdentifier.SILENCED:
                    value = BACnetSilencedState(value)
                elif prop_id == BACnetPropertyIdentifier.BACKUP_AND_RESTORE_STATE:
                    value = BACnetBackupState(value)
                elif obj_type == BACnetObjectType.Access_Point:
                    if prop_id == BACnetPropertyIdentifier.ACCESS_EVENT or \
                            prop_id == BACnetPropertyIdentifier.ACCESS_ALARM_EVENTS or \
                            prop_id == BACnetPropertyIdentifier.ACCESS_TRANSACTION_EVENTS or \
                            prop_id == BACnetPropertyIdentifier.FAILED_ATTEMPT_EVENTS:
                        value = BACnetAccessEvent(value)
                elif obj_type == BACnetObjectType.Access_Credential:
                    if prop_id == BACnetPropertyIdentifier.LAST_ACCESS_EVENT:
                        value = BACnetAccessEvent(value)
                    if prop_id == BACnetPropertyIdentifier.CREDENTIAL_STATUS:
                        value = BACnetBinaryPV(value)
                elif obj_type == BACnetObjectType.Access_Door:
                    if prop_id == BACnetPropertyIdentifier.PRESENT_VALUE or prop_id == BACnetPropertyIdentifier.RELINQUISH_DEFAULT:
                        value = BACnetDoorValue(value)
                    elif prop_id == BACnetPropertyIdentifier.LOCK_STATUS:
                        value = BACnetLockStatus(value)
                    elif prop_id == BACnetPropertyIdentifier.DOOR_ALARM_STATE or \
                            prop_id == BACnetPropertyIdentifier.MASKED_ALARM_VALUES or \
                            prop_id == BACnetPropertyIdentifier.ALARM_VALUES or \
                            prop_id == BACnetPropertyIdentifier.FAULT_VALUES:
                        value = BACnetDoorAlarmState(value)
                elif obj_type == BACnetObjectType.Life_Safety_Point or obj_type == BACnetObjectType.Life_Safety_Zone:
                    if prop_id == BACnetPropertyIdentifier.MODE or prop_id == BACnetPropertyIdentifier.ACCEPTED_MODES:
                        value = BACnetLifeSafetyMode(value)
                    if prop_id == BACnetPropertyIdentifier.PRESENT_VALUE or \
                            prop_id == BACnetPropertyIdentifier.TRACKING_VALUE or \
                            prop_id == BACnetPropertyIdentifier.LIFE_SAFETY_ALARM_VALUES or \
                            prop_id == BACnetPropertyIdentifier.ALARM_VALUES or \
                            prop_id == BACnetPropertyIdentifier.FAULT_VALUES:
                        value = BACnetLifeSafetyState(value)
                elif obj_type == BACnetObjectType.Escalator:
                    if prop_id == BACnetPropertyIdentifier.fault_signals:
                        value = BACnetEscalatorFault(value)
                elif obj_type == BACnetObjectType.Lift:
                    if prop_id == BACnetPropertyIdentifier.fault_signals:
                        value = BACnetLiftFault(value)
                elif obj_type == BACnetObjectType.Lighting_Output:
                    if prop_id == BACnetPropertyIdentifier.IN_PROGRESS:
                        value = BACnetLightingInProgress(value)
                    elif prop_id == BACnetPropertyIdentifier.PRESENT_VALUE or \
                            prop_id == BACnetPropertyIdentifier.FEEDBACK_VALUE or \
                            prop_id == BACnetPropertyIdentifier.RELINQUISH_DEFAULT:
                        value = BACnetBinaryLightingPV(value)
                    elif prop_id == BACnetPropertyIdentifier.TRANSITION:
                        value = BACnetLightingTransition(value)
                elif obj_type == BACnetObjectType.Network_Port:
                    if prop_id == BACnetPropertyIdentifier.COMMAND:
                        value = BACnetNetworkPortCommand(value)
                elif obj_type == BACnetObjectType.Structured_View:
                    if prop_id == BACnetPropertyIdentifier.NODE_TYPE or prop_id == BACnetPropertyIdentifier.SUBORDINATE_NODE_TYPES:
                        value = BACnetNodeType(value)
                    elif prop_id == BACnetPropertyIdentifier.SUBORDINATE_RELATIONSHIPS or prop_id == BACnetPropertyIdentifier.DEFAULT_SUBORDINATE_RELATIONSHIP:
                        value = BACnetRelationship(value)
                elif obj_type == BACnetObjectType.Program:
                    if prop_id == BACnetPropertyIdentifier.REASON_FOR_HALT:
                        value = BACnetProgramError(value)
                    elif prop_id == BACnetPropertyIdentifier.PROGRAM_CHANGE:
                        value = BACnetProgramRequest(value)
                    elif prop_id == BACnetPropertyIdentifier.PROGRAM_STATE:
                        value = BACnetProgramState(value)
                elif obj_type == BACnetObjectType.Load_Control:
                    if prop_id == BACnetPropertyIdentifier.PRESENT_VALUE:
                        value = BACnetShedState(value)
                elif obj_type == BACnetObjectType.Timer:
                    if prop_id == BACnetPropertyIdentifier.TIMER_STATE or \
                            prop_id == BACnetPropertyIdentifier.ALARM_VALUES:
                        value = BACnetTimerState(value)
                    elif prop_id == BACnetPropertyIdentifier.LAST_STATE_CHANGE:
                        value = BACnetTimerTransition(value)
                elif prop_id == BACnetPropertyIdentifier.VT_CLASSES_SUPPORTED:
                    value = BACnetVTClass(value)
                elif obj_type == BACnetObjectType.Channel:
                    if prop_id == BACnetPropertyIdentifier.WRITE_STATUS:
                        value = BACnetWriteStatus(value)
            except ValueError:
                logging.debug("vendor specific enum value! " + str(value))
        return (leng, value)

    def decode_is_context_tag(buffer, offset, tag_number):
        (leng, my_tag_number) = ASN1.decode_tag_number(buffer, offset)

        return ASN1.IS_CONTEXT_SPECIFIC(buffer[offset]) and (my_tag_number == tag_number)

    def decode_is_opening_tag_number(buffer, offset, tag_number):
        my_tag_number = 0
        (leng, my_tag_number) = ASN1.decode_tag_number(buffer, offset)
        return (ASN1.IS_OPENING_TAG(buffer[offset]) and (my_tag_number == tag_number))

    def decode_is_closing_tag_number(buffer, offset, tag_number):
        my_tag_number = 0

        (leng, my_tag_number) = ASN1.decode_tag_number(buffer, offset)
        return (ASN1.IS_CLOSING_TAG(buffer[offset]) and (my_tag_number == tag_number))

    def decode_is_closing_tag(buffer, offset):
        return (buffer[offset] & 0x07) == 7

    def decode_is_opening_tag(buffer, offset):
        return (buffer[offset] & 0x07) == 6

class APDU:
    def __init__(self, segmented_message: bool = False,
                 more_follows: bool = False,
                 segmented_response_accepted: bool = False,
                 max_segments_accepted: BacnetMaxSegments = BacnetMaxSegments.MAX_SEG0,
                 max_apdu_length_accepted: BacnetMaxAdpu = BacnetMaxAdpu.MAX_APDU1476,
                 invoke_id: int = 0,
                 sequence_number: int = None,
                 proposed_window_size: int = None,
                 service_choice = None,
                 pdu_type:BacnetPduTypes = None):
        self.pdu_type: BacnetPduTypes = pdu_type
        self.segmented_message: bool = segmented_message
        self.more_follows: bool = more_follows
        self.segmented_response_accepted: bool = segmented_response_accepted
        self.max_segments_accepted: int = max_segments_accepted
        self.max_apdu_length_accepted = max_apdu_length_accepted
        self.invoke_id = invoke_id
        self.sequence_number = sequence_number
        self.proposed_window_size = proposed_window_size
        self.service_choice = service_choice

    def encode(self):
        tmp = BitArray("uint:8="+str(int(self.pdu_type)))
        tmp[4] = self.segmented_message
        tmp[5] = self.more_follows
        tmp[6] = self.segmented_response_accepted
        if self.pdu_type == BacnetPduTypes.PDU_TYPE_CONFIRMED_SERVICE_REQUEST:
            buffer = tmp.bytes + struct.pack('!B', (self.max_segments_accepted | self.max_apdu_length_accepted))
            buffer += struct.pack('!B', self.invoke_id)
            if self.segmented_message:
                buffer += struct.pack('!B', self.sequence_number)
                buffer += struct.pack('!B', self.proposed_window_size)
        elif self.pdu_type == BacnetPduTypes.PDU_TYPE_UNCONFIRMED_SERVICE_REQUEST:
            buffer = tmp.bytes
        elif self.pdu_type == BacnetPduTypes.PDU_TYPE_SIMPLE_ACK:
            buffer = tmp.bytes + struct.pack('!B', self.invoke_id)
        elif self.pdu_type == BacnetPduTypes.PDU_TYPE_COMPLEX_ACK:
            buffer = struct.pack('!B', self.invoke_id)
            if self.segmented_message:
                buffer += struct.pack('!B', self.sequence_number)
                buffer += struct.pack('!B', self.proposed_window_size)
        else:
            pass
        buffer += struct.pack('!B', self.service_choice)
        return buffer

    def decode(self, buffer, offset):
        leng = 0
        self.pdu_type = BacnetPduTypes(buffer[offset] & 0xFF)
        tmp = BitArray("uint:8=" + str(buffer[offset]))
        leng += 1
        #todo add all
        if self.pdu_type == BacnetPduTypes.PDU_TYPE_CONFIRMED_SERVICE_REQUEST:
            self.segmented_message = tmp[4]
            self.more_follows = tmp[5]
            self.segmented_response_accepted = tmp[6]
            leng += 1
            self.max_segments_accepted = BacnetMaxSegments(buffer[offset+leng] & 0xF0)
            self.max_apdu_length_accepted = BacnetMaxAdpu(buffer[offset+leng] & 0xF)
            leng += 1
            self.invoke_id = buffer[offset+leng]
            leng += 1
            if self.segmented_message:
                self.sequence_number = buffer[offset+leng]
                leng += 1
                self.proposed_window_size = buffer[offset+leng]
                leng += 1
            self.service_choice = BACnetConfirmedServiceChoice(buffer[offset + leng])
            leng += 1
        elif self.pdu_type == BacnetPduTypes.PDU_TYPE_UNCONFIRMED_SERVICE_REQUEST:
            self.service_choice = BACnetUnconfirmedServiceChoice(buffer[offset + leng])
            leng += 1
        elif self.pdu_type == BacnetPduTypes.PDU_TYPE_SIMPLE_ACK:
            self.invoke_id = buffer[offset+leng]
            leng += 1
            self.service_choice = BACnetConfirmedServiceChoice(buffer[offset + leng])
            leng += 1
        elif self.pdu_type == BacnetPduTypes.PDU_TYPE_COMPLEX_ACK:
            self.segmented_message = tmp[4]
            self.invoke_id = buffer[offset + leng]
            leng += 1
            self.service_choice = BACnetConfirmedServiceChoice(buffer[offset + leng])
            leng += 1
            if self.segmented_message:
                self.sequence_number = buffer[offset+leng]
                leng += 1
                self.proposed_window_size = buffer[offset+leng]
                leng += 1
        elif self.pdu_type == BacnetPduTypes.PDU_TYPE_ERROR:
            self.invoke_id = buffer[offset + leng]
            leng += 1
            self.service_choice = BACnetConfirmedServiceChoice(buffer[offset + leng])
            leng += 1
        else:
            return -1



        return leng

class NPDU:
    def __init__(self, destination: BACnetAddress = None,
                 source: BACnetAddress = None,
                 hop_count: int = 255,
                 vendor_id: int = None):
        self.Version = 1
        self.control: NPDU_ControlInformation = NPDU_ControlInformation()
        self.dnet = None
        self.dlen = None
        self.dadr = None
        self.destination = destination
        if destination != None and destination.network_number > 0:
            self.control.destination_specifier = True
            self.dnet = destination.network_number
            self.dlen = len(destination.mac_address)
            self.dadr = destination.mac_address
            self.hop_count = hop_count
        self.snet = None
        self.slen = None
        self.sadr = None
        self.source = source
        if source != None and source.network_number > 0 and source.network_number < 0xFFFF:
            self.control.source_specifier = True
            self.snet = source.network_number
            self.slen = len(source.mac_address)
            self.sadr = source.mac_address
        self.message_type = None
        self.vendor_id = vendor_id

    def encode(self):
        buffer = struct.pack('!B', self.Version)
        buffer += self.control.encode()

        if self.control.destination_specifier:

            buffer += struct.pack('!H', self.dnet)
            if self.dnet == 0xFFFF:
                buffer += b'\x00'
            else:
                buffer += struct.pack('!B', self.dlen) + self.dadr
        if self.control.source_specifier:
            buffer += struct.pack('!H', self.snet) + struct.pack('!B', self.slen) + self.sadr
        if self.control.destination_specifier:
            buffer += struct.pack('!B', self.hop_count)
        if self.control.network_layer_message:
            buffer += struct.pack('!B', self.message_type)
            if self.message_type >= 0x80 and self.message_type <= 0xFF:
                buffer += struct.pack('!H', self.vendor_id)

        return buffer

    def decode(self, buffer, offset):
        org_offset = offset
        leng = 0
        version = buffer[offset]  # always 1!!!!
        leng += 1
        if version != self.Version:
            logging.debug("Received something else!")
            return -1

        self.control = NPDU_ControlInformation()
        leng += self.control.decode(buffer, offset+leng)

        if self.control.destination_specifier:
            self.dnet = struct.unpack("!H", buffer[offset+leng:offset+leng+2])[0]
            leng += 2
            self.dlen = buffer[offset+leng]
            leng += 1
            self.dadr = buffer[offset+leng:offset+leng+self.dlen]
            leng += self.dlen
            self.destination = BACnetAddress(network_number=self.dnet, mac_address=self.dadr)

        if self.control.source_specifier:
            self.snet = struct.unpack("!H", buffer[offset + leng:offset + leng + 2])[0]
            leng += 2
            self.slen = buffer[offset + leng]
            leng += 1
            self.sadr = buffer[offset + leng:offset + leng + self.slen]
            leng += self.slen
            self.source = BACnetAddress(network_number=self.snet, mac_address=self.sadr)

        if self.control.destination_specifier:

            self.hop_count = buffer[offset+leng]

            leng += 1

        if self.control.network_layer_message:
            self.network_msg_type = BacnetNetworkMessageTypes(buffer[offset+leng])
            leng += 1
            if self.network_msg_type >= 0x80:
                self.vendor_id = struct.unpack("!H", buffer[offset+leng:offset+leng + 2])[0]
                leng += 2

        return leng


class NPDU_ControlInformation:
    def __init__(self):
        self._control = BitArray('0x00')

    @property
    def network_layer_message(self):
        return self._control[0]

    @network_layer_message.setter
    def network_layer_message(self, a: bool):
        self._control[0] = a

    @property
    def destination_specifier(self) ->bool:
        return self._control[2]

    @destination_specifier.setter
    def destination_specifier(self, a: bool):
        self._control[2] = a

    @property
    def source_specifier(self):
        return self._control[4]

    @source_specifier.setter
    def source_specifier(self, a: bool):
        self._control[4] = a

    @property
    def data_expecting_reply(self):
        return self._control[5]

    @data_expecting_reply.setter
    def data_expecting_reply(self, a: bool):
        self._control[5] = a

    @property
    def network_priority(self):
        if self._control[6] == False and self._control[7] == False:
            return Network_Priority.Normal_Message
        if self._control[6] == False and self._control[7] == True:
            return Network_Priority.Urgent_Message
        if self._control[6] == True and self._control[7] == False:
            return Network_Priority.Critical_Equipment_Message
        else:
            return Network_Priority.Life_Safety_Message

    @network_priority.setter
    def network_priority(self, a: Network_Priority):
        if a == Network_Priority.Normal_Message:
            self._control[6] = False
            self._control[7] = False
        elif a == Network_Priority.Urgent_Message:
            self._control[6] = False
            self._control[7] = True
        elif a == Network_Priority.Critical_Equipment_Message:
            self._control[6] = True
            self._control[7] = False
        elif a == Network_Priority.Life_Safety_Message:
            self._control[6] = True
            self._control[7] = True

    def encode(self):
        return self._control.bytes

    def decode(self, buffer, offset):
        self._control = BitArray("uint:8="+str(buffer[offset]))
        return 1
