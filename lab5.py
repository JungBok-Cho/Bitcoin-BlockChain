"""
CPSC 5520-01, Seattle University
This is free and unencumbered software released into the public domain.
:Authors: JungBok Cho
:Version: 1.0
"""
import socket
import time
import random
import hashlib
import struct
from time import gmtime, strftime

HDR_SZ = 24  # Header Size
P2P_PEER_HOST = '46.254.217.169'  # Bitcoin Peer Host
P2P_PEER_PORT = 8333  # Bitcoin Peer Port
TARGET_BLOCK = 2700000 % 650000   # Block number to find
BUFF_SIZE = 2024  # Default socket.recv buffer size
WRONG = 'WRONG'


def compactsize_t(n):
    """
    Encode integer depending on the represented value
    (Variable length integer)

    :param n: Integer to encode
    :return:  Return bytes
    """
    if n < 252:
        return uint8_t(n)
    if n < 0xffff:
        return uint8_t(0xfd) + uint16_t(n)
    if n < 0xffffffff:
        return uint8_t(0xfe) + uint32_t(n)
    return uint8_t(0xff) + uint64_t(n)


def unmarshal_compactsize(b):
    """
    Decode bytes depending on the represented value

    :param b: Bytes to decode
    :return:  Return a tuple (bytes, integer)
    """
    key = b[0]
    if key == 0xff:
        return b[0:9], unmarshal_uint(b[1:9])
    if key == 0xfe:
        return b[0:5], unmarshal_uint(b[1:5])
    if key == 0xfd:
        return b[0:3], unmarshal_uint(b[1:3])
    return b[0:1], unmarshal_uint(b[0:1])


def bool_t(flag):
    """
    Encode bool value

    :param flag: Bool value to encode
    :return: Return bytes
    """
    return uint8_t(1 if flag else 0)


def ipv6_from_ipv4(ipv4_str):
    """
    Convert from IPv4 to IPv6

    :param ipv4_str: IPv4 string to change
    :return: Return IPv6
    """
    pchIPv4 = bytearray([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])
    return pchIPv4 + bytearray((int(x) for x in ipv4_str.split('.')))


def ipv6_to_ipv4(ipv6_str):
    """
    Convert from IPv6 to IPv4

    :param ipv6_str: IPv6 string to change
    :return:  Return IPv4
    """
    return '.'.join([str(b) for b in ipv6_str[12:]])


def uint8_t(n):
    """
    Change to uint8 bytes - Unsigned integer with 8 bit

    :param n: Integer to convert
    :return:  Return bytes in uint8
    """
    return int(n).to_bytes(1, byteorder='little', signed=False)


def uint16_t(n):
    """
    Change to uint16 bytes - Unsigned integer with 16 bit

    :param n: Integer to convert
    :return:  Return bytes in uint16
    """
    return int(n).to_bytes(2, byteorder='little', signed=False)


def int32_t(n):
    """
    Change to int32 bytes - Signed integer with 32 bit

    :param n: Integer to convert
    :return:  Return bytes in int32
    """
    return int(n).to_bytes(4, byteorder='little', signed=True)


def uint32_t(n):
    """
    Change to uint32 bytes - Unsigned integer with 32 bit

    :param n: Integer to convert
    :return:  Return bytes in uint32
    """
    return int(n).to_bytes(4, byteorder='little', signed=False)


def int64_t(n):
    """
    Change to int64 bytes - Signed integer with 64 bit

    :param n: Integer to convert
    :return:  Return bytes in int64
    """
    return int(n).to_bytes(8, byteorder='little', signed=True)


def uint64_t(n):
    """
    Change to int64 bytes - Unsigned integer with 64 bit

    :param n: Integer to convert
    :return:  Return bytes in uint64
    """
    return int(n).to_bytes(8, byteorder='little', signed=False)


def unmarshal_int(b):
    """
    Unmarshal bytes of signed integer

    :param b: Bytes to unmarshal
    :return:  Return signed integer
    """
    return int.from_bytes(b, byteorder='little', signed=True)


def unmarshal_uint(b):
    """
    Unmarshal bytes of unsigned integer

    :param b: Bytes to unmarshal
    :return:  Return unsigned integer
    """
    return int.from_bytes(b, byteorder='little', signed=False)


def checksum(payload):
    """
    Get the first 4 bytes of sha256(sha256(payload))

    :param payload: Bytes to encode
    :return:  Return First 4 bytes
    """
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]


def printable_hash(h):
    """
    Get a string of uint32 bytes in the corresponding hexadecimal form

    :param h:
    :return:
    """
    return int(h).to_bytes(32, byteorder='big', signed=False).hex()


def char32_t(n):
    """
    Convert n to char32 bytes

    :param n: Integer to convert
    :return:  Return char32 bytes
    """
    return int(n).to_bytes(32, byteorder='little', signed=False)


def convertLittleBig(string):
    """
    Helper function to convert from little endian to big endian.
    It can also convert in an inverse way (from big endian to little endian).

    :param string: String of bytes to convert
    :return: Return the converted string of bytes
    """
    t = bytearray.fromhex(string)
    t.reverse()
    return ''.join(format(x, '02x') for x in t)


def print_message(msg, text=None, count=0):
    """
    Report the contents of the given bitcoin message

    :param msg: Bitcoin message including header
    :param text: Check if it is receiving or sending message
    :param count: To count the inventory number (=block height number)
    :return: Return a tuple - (message type, list)
    """
    msgInfo = '\n{}MESSAGE\n'.format('' if text is None else (text + ' '))
    msgInfo += '({}) {}\n'.format(len(msg), msg[:60].hex() + ('' if len(msg) < 60 else '...'))
    payload = msg[HDR_SZ:]

    # Process header
    command = print_header(msg[:HDR_SZ], msgInfo, checksum(payload))

    # Process payload
    if command == 'version':
        print_version_msg(payload)
    elif command == 'inv' and text == 'Receiving':
        return command, print_inv_msg(payload, count)
    elif command == 'block':
        print_block_msg(payload)
    elif command == WRONG:
        return WRONG, []
    return command, []


def print_header(header, msgInfo, expected_cksum=None):
    """
    Report the contents of the given bitcoin message header

    :param header: Bitcoin message header (bytes or bytearray)
    :param msgInfo: Bitcoin message information
    :param expected_cksum: The expected checksum for this version message, if known
    :return: Return message type. If checksum is wrong, return Wrong
    """
    magic, command_hex = header[:4], header[4:16]
    payload_size, cksum = header[16:20], header[20:]

    command = str(bytearray([b for b in command_hex if b != 0]), encoding='utf-8')
    psz = unmarshal_uint(payload_size)
    if expected_cksum is None:
        verified = ''
    elif expected_cksum == cksum:
        verified = '(verified)'
    else:
        verified = '(WRONG!! ' + expected_cksum.hex() + ')'

    # If checksum is verified, process these
    if verified[1:6] != WRONG:
        print(msgInfo)
        prefix = '  '
        print(prefix + 'HEADER')
        print(prefix + '-' * 56)
        prefix *= 2
        print('{}{:32} magic'.format(prefix, magic.hex()))
        print('{}{:32} command: {}'.format(prefix, command_hex.hex(), command))
        print('{}{:32} payload size: {}'.format(prefix, payload_size.hex(), psz))
        print('{}{:32} checksum {}'.format(prefix, cksum.hex(), verified))
    else:
        return WRONG
    return command


def print_version_msg(b):
    """
    Report the contents of the given bitcoin version message (sans the header)

    :param b: Version message contents
    """
    # Pull out fields
    version, my_services = b[:4], b[4:12]
    epoch_time, your_services = b[12:20], b[20:28]
    rec_host, rec_port = b[28:44], b[44:46]
    my_services2, my_host, my_port = b[46:54], b[54:70], b[70:72]
    nonce = b[72:80]
    user_agent_size, uasz = unmarshal_compactsize(b[80:])
    i = 80 + len(user_agent_size)
    user_agent = b[i:i + uasz]
    i += uasz
    start_height, relay = b[i:i + 4], b[i + 4:i + 5]
    extra = b[i + 5:]

    # Print report
    prefix = '  '
    print(prefix + 'VERSION')
    print(prefix + '-' * 56)
    prefix *= 2
    print('{}{:32} version {}'.format(prefix, version.hex(), unmarshal_int(version)))
    print('{}{:32} my services'.format(prefix, my_services.hex()))
    time_str = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime(unmarshal_int(epoch_time)))
    print('{}{:32} epoch time {}'.format(prefix, epoch_time.hex(), time_str))
    print('{}{:32} your services'.format(prefix, your_services.hex()))
    print('{}{:32} your host {}'.format(prefix, rec_host.hex(), ipv6_to_ipv4(rec_host)))
    print('{}{:32} your port {}'.format(prefix, rec_port.hex(), unmarshal_uint(rec_port)))
    print('{}{:32} my services (again)'.format(prefix, my_services2.hex()))
    print('{}{:32} my host {}'.format(prefix, my_host.hex(), ipv6_to_ipv4(my_host)))
    print('{}{:32} my port {}'.format(prefix, my_port.hex(), unmarshal_uint(my_port)))
    print('{}{:32} nonce'.format(prefix, nonce.hex()))
    print('{}{:32} user agent size {}'.format(prefix, user_agent_size.hex(), uasz))
    print('{}{:32} user agent \'{}\''.format(prefix, user_agent.hex(), str(user_agent, encoding='utf-8')))
    print('{}{:32} start height {}'.format(prefix, start_height.hex(), unmarshal_uint(start_height)))
    print('{}{:32} relay {}'.format(prefix, relay.hex(), bytes(relay) != b'\0'))
    if len(extra) > 0:
        print('{}{:32} EXTRA!!'.format(prefix, extra.hex()))


def print_inv_msg(b, invNum=0):
    """
    Report the contents of the given bitcoin inv message (sans the header)

    :param b: Inventory message contents
    :param invNum: Inventory starting number
    :return: Return a list - [Hash of the object, inventory number]
    """
    # Print if the target block is in the range
    if invNum + 500 >= TARGET_BLOCK:
        prefix = '  '
        print(prefix + 'INV')
        print(prefix + '-' * 56)
        print(b[:3].hex(), '  (each hash printed in reverse of '
                           'serialized order for clarity)   count 500')
    count = 1
    target = ["", -1]
    last_block = ''
    n = 36

    # Iterate through the inventory messages
    for i in range(3, len(b), n):
        try:
            block = b[i:i + n].hex()
            objType = block[:8]  # Object type
            hashObj = convertLittleBig(block[8:])  # Hash of the object

            # Keep the information to return if the target block is found
            if invNum + count == TARGET_BLOCK:
                target = [hashObj, invNum + count]

            # Print if the target block is in the range
            if invNum + 500 >= TARGET_BLOCK:
                print(objType, hashObj, 'MSG_BLOCK', 'inventory #'
                      + str(invNum + count))
            count += 1
            last_block = hashObj
        except Exception:
            continue
    # Return the found one if the target block is found
    if target[1] == TARGET_BLOCK:
        return target
    # Return the last block if the target block is not found
    return [last_block, invNum + count - 1]


def print_block_msg(b):
    """
    Report the contents of the given bitcoin block message (sans the header)

    :param b: Block message contents
    """
    # Pull out fields
    version, prev_header, merkle_root = b[:4], b[4:36], b[36:68]
    timestamp, bits, nonce = b[68:72], b[72:76], b[76:80]
    txn_count = b[80:90].split(bytes.fromhex('01000000'))[0]
    txn_count = unmarshal_compactsize(txn_count)

    # Print report
    prefix = '  '
    print(prefix + 'BLOCK TRANSACTION')
    print(prefix + '-' * 56)
    prefix *= 2
    print('{}{:67} Version {}'.format(prefix, version.hex(), unmarshal_int(version)))
    print('{}{:67} Previous Block'.format(prefix, convertLittleBig(prev_header.hex())))
    print('{}{:67} Merkle Root'.format(prefix, convertLittleBig(merkle_root.hex())))
    time_str = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime(unmarshal_int(timestamp)))
    print('{}{:67} Epoch time {}'.format(prefix, timestamp.hex(), time_str))
    print('{}{:67} Bits'.format(prefix, convertLittleBig(bits.hex())))
    print('{}{:67} Nonce'.format(prefix, convertLittleBig(nonce.hex())))
    print('{}{:67} Number of transactions: {}'.format(prefix, txn_count[0].hex(), txn_count[1]))


class Lab5(object):
    """ Using bitcoin peer's address, get a specific block and print the transaction """

    def __init__(self, p2p_address):
        """
        Lab5 constructor

        :param p2p_address: Bitcoin peer address
        """
        self.b2bPeer = (p2p_address[0], int(p2p_address[1]))
        self.listener, self.listener_address = self.start_a_listener()
        self.magic = 'f9beb4d9'
        self.version = 70015

    def run(self):
        """ Start to communicate with the bitcoin peer """
        try:
            self.listener.connect(self.b2bPeer)

            print('\n<1. Version Message>')
            version = self.versionMsg()
            self.messageControl(version)

            print('\n\n<2. Verack Message>')
            verack = self.verackMsg()
            self.messageControl(verack)

            print('\n\n<3. GetBlocks Message> - Get Inventory #{}'.format(TARGET_BLOCK))
            target_block = self.getBlocks()

            print('\n\n<4. GetData Message>')
            get_data = self.getDataMsg(target_block)
            self.largeMessageControl(get_data, 'block')
        except Exception as e:
            print(e)

    def messageControl(self, msg):
        """
        Process short messages

        :param msg: Message to send
        """
        print_message(msg, 'Sending')
        self.listener.send(msg)

        recvMsg = self.listener.recv(BUFF_SIZE)
        parsedMsg = self.parseMsg(recvMsg)
        for x in parsedMsg:  # Iterate through messages
            check, last_locator = print_message(x, 'Receiving')
            while check == WRONG:  # Keep doing if checksum is wrong
                if check != WRONG:
                    break
                else:  # Receive more messages if we have only partial message
                    newMessage = self.listener.recv(BUFF_SIZE)
                    x = x + newMessage
                parsedMsg = self.parseMsg(x)
                for y in parsedMsg:  # Iterate through new messages
                    check, last_locator = print_message(y, 'Receiving')

    def largeMessageControl(self, msg, command='', count=0):
        """
        Process large messages

        :param msg: Message to send
        :param command: Command that it will receive
        :param count: Inventory number
        :return: Return the hash of an object
        """
        print_message(msg, 'Sending')
        self.listener.send(msg)

        check, last_locator = "", []
        while True:
            recvMsg = self.listener.recv(BUFF_SIZE)
            parsedMsg = self.parseMsg(recvMsg)
            for x in parsedMsg:  # Iterate through messages
                check, last_locator = print_message(x, 'Receiving')
                while check == WRONG:  # Keep doing if checksum is wrong
                    if check != WRONG:
                        break
                    else:  # Receive more messages if we have only partial message
                        newMessage = self.listener.recv(BUFF_SIZE)
                        x = x + newMessage
                    parsedMsg = self.parseMsg(x)
                    for y in parsedMsg:  # Iterate through new messages
                        check, last_locator = print_message(y, 'Receiving', count)
                        if command == check:
                            break
            if command == check:
                break
        return last_locator

    def parseMsg(self, recvMsg):
        """
        Parse the received messages

        :param recvMsg: Message to parse
        :return: Return list of parsed message
        """
        splitMsgs = recvMsg.split(bytearray.fromhex(self.magic))
        msgList = []
        for i in range(1, len(splitMsgs), 1):
            msgList.append(bytes.fromhex(self.magic) + splitMsgs[i])
        return msgList

    def addHeaderMsg(self, command, payload):
        """
        Add header message

        :param command: Message command
        :param payload: Message payload
        :return: Return message with header part
        """
        magic = bytes.fromhex(self.magic)
        command = struct.pack('12s', command.encode())
        length = uint32_t(len(payload))
        checkSum = checksum(payload)
        return magic + command + length + checkSum + payload

    def versionMsg(self):
        """
        Create version message

        :return: Return version message
        """
        version = int32_t(self.version)
        services = uint64_t(0)
        timestamp = int64_t(time.time())
        addr_peer_services = uint64_t(0)
        addr_peer_ip = ipv6_from_ipv4(self.b2bPeer[0])
        addr_peer_port = uint16_t(self.b2bPeer[1])
        addr_my_services = uint64_t(0)
        addr_my_ip = ipv6_from_ipv4(self.listener_address[0])
        addr_my_port = uint16_t(self.listener_address[1])
        nonce = uint64_t(random.getrandbits(64))
        user_agent_bytes = compactsize_t(0)
        start_height = int32_t(0)
        relay = bool_t(False)

        payload = version + services + timestamp + addr_peer_services + \
                  addr_peer_ip + addr_peer_port + addr_my_services + \
                  addr_my_ip + addr_my_port + nonce + user_agent_bytes + \
                  start_height + relay
        return self.addHeaderMsg('version', payload)

    def verackMsg(self):
        """
        Create verack message

        :return: Return verack message
        """
        magic = bytearray.fromhex(self.magic)
        command = struct.pack('12s', 'verack'.encode())
        length = uint32_t(0)
        checkSum = bytearray.fromhex('5df6e0e2')
        return magic + command + length + checkSum

    def getBlocksMsg(self, last_locator):
        """
        Create getblocks message

        :param last_locator: Hash of an object
        :return: Return getblocks message
        """
        version = uint32_t(self.version)
        hash_count = compactsize_t(1)
        block_locator_hashses = struct.pack('32s', last_locator)
        hash_stop = struct.pack('32s', b'\x00')
        payload = version + hash_count + block_locator_hashses + hash_stop
        return self.addHeaderMsg('getblocks', payload)

    def getBlocks(self):
        """
        Get the target block

        :return: Return the target block
        """
        blocks = self.getBlocksMsg(b'\x00')
        last_locator = self.largeMessageControl(blocks, 'inv', 0)

        while last_locator[1] < TARGET_BLOCK:
            blocks = self.getBlocksMsg(bytearray.fromhex(convertLittleBig(last_locator[0])))
            last_locator = self.largeMessageControl(blocks, 'inv', last_locator[1])

        print('\nSuccessfully found the Block #{}: {}'.format(TARGET_BLOCK, last_locator[0]))
        return last_locator[0]

    def getDataMsg(self, target_block):
        """
        Create getdata message

        :param target_block: Hash of an object
        :return: Return getdata message
        """
        hash_count = compactsize_t(1)
        obj_type = uint32_t(2)
        payload = hash_count + obj_type + bytes.fromhex(convertLittleBig(target_block))
        return self.addHeaderMsg('getdata', payload)

    @staticmethod
    def start_a_listener():
        """
        Create a listener socket

        :return: Return listener socket and its socket address
        """
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(('', 0))
        return listener, listener.getsockname()


if __name__ == '__main__':
    lab5 = Lab5((P2P_PEER_HOST, P2P_PEER_PORT))
    lab5.run()
