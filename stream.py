from enum import Enum
from pyshn import Shannon
import hmac
import hashlib
from crypto import Crypto
import struct
import socket
import threading

PROTOCOL_VERSION = [0, 4]

MAC_SIZE = 4
HEADER_SIZE = 3

READ_BLOCK_SIZE = 4096

from apserver import SPOTIFY_HOST, SPOTIFY_PORT

class EncryptedStreamDirection(Enum):
    READ = 0
    WRITE = 1

class EncryptedStream(object):
    def __init__(self, sock, key, direction, name=None):
        self.sock = sock
        self.cipher = Shannon(key)
        self.name = name
        self.needs_reset = False

        self.sock_lock = threading.Lock()

        self.payloadbytes = ''
        self.last_header = (None, None)

        # can only read or write from a stream, not both
        if direction == 'w' or direction == EncryptedStreamDirection.WRITE:
            self.direction = EncryptedStreamDirection.WRITE
        elif direction == 'r' or direction == EncryptedStreamDirection.READ:
            self.direction = EncryptedStreamDirection.READ
        else:
            raise ValueError('cannot open stream with given direction' + self.direction)

    def write_packet(self, command, payload):
        assert self.direction == EncryptedStreamDirection.WRITE

        self.sock_lock.acquire()

        # print 'payload len is', len(payload)
        buf = struct.pack('>BH', command, len(payload))
        buf += payload

        # print 'resetting write cipher, current nonce is 0x%x (0x%s)' % (
        #     self.cipher.nonce, struct.pack('>L', self.cipher.nonce).encode('hex'))

        if self.needs_reset and self.cipher.nonce == 0x17:
            print '!!!! RESETING NONCE TO ZERO'
            self.cipher.nonce = 0

        self.cipher.reset()

        buf = self.cipher.encrypt(buf)

        mac = self.cipher.finish(MAC_SIZE)
        buf += mac

        self.cipher.nonce += 1


        # self.sock.sendall(buf)
        sent = 0
        while sent < len(buf):
            remaining = len(buf) - sent
            to_send = min(READ_BLOCK_SIZE, remaining)

            try:
                this_sent = self.sock.send(buf[sent:sent + to_send])
            except socket.error, ex:
                print 'stream %r had socket error while sending' % self
                self.sock = self.reconnect()
                continue
                # raise ex

            if this_sent <= 0:
                print 'failed to send', this_sent

            sent += this_sent

        self.sock_lock.release()

    def read_packet_header(self):
        assert self.direction == EncryptedStreamDirection.READ

        assert self.last_header[0] is None
        self.read_len = 0

        self.sock_lock.acquire()

        hdrbytes = ''
        while len(hdrbytes) < HEADER_SIZE:
            try:
                new = self.sock.recv(HEADER_SIZE - len(hdrbytes))
            except socket.error, ex:
                print '%r had socket error trying to read packet header' % self
                self.sock = self.reconnect()
                continue
                # raise ex

            if new is None:
                print '** failed to receive enc header'
                self.sock_lock.release()
                return (None, None)

            hdrbytes += new

        # print 'resetting read cipher, current nonce is 0x%x (0x%s)' % (
        #     self.cipher.nonce, struct.pack('>L', self.cipher.nonce).encode('hex'))

        self.cipher.reset()

        # print 'have encrypted header 0x%s' % hdrbytes.encode ('hex')
        hdrbytes = self.cipher.decrypt(hdrbytes)
        # print 'have decrypted header 0x%s' % hdrbytes.encode ('hex')

        cmd, size = struct.unpack('>BH', hdrbytes)
        # print 'cmd was 0x%x' % cmd
        # print 'length was', size, 'bytes'

        self.last_header = (cmd, size)
        self.payloadbytes = ''

        self.sock_lock.release()

        return (cmd, size)

    def read_packet_body(self):
        assert self.direction == EncryptedStreamDirection.READ
        
        self.sock_lock.acquire()

        assert self.last_header[0] is not None
        cmd, size = self.last_header

        # now read the payload
        need_len = size + MAC_SIZE
        # self.read_len = 0 -- continue using read_len, as this is not re-entrant
        self.payloadbytes = ''

        while self.read_len < need_len:
            want_read = min(READ_BLOCK_SIZE, need_len - self.read_len)

            # print '\twant %d bytes from sock' % want_read

            try:
                new_bytes = self.sock.recv(want_read)
            except socket.error, ex:
                print '!!!!! %r had socket error trying to read packet header' % self
                self.sock = self.reconnect()
                continue
                # raise ex

            if new_bytes is None:
                return (None, None)

            self.read_len += len(new_bytes)
            self.payloadbytes += new_bytes

            # print '\tenc read %d of %d bytes' % (self.read_len, need_len)

        decrypted_payload = self.cipher.decrypt (self.payloadbytes[:size])

        payload, their_mac = decrypted_payload, self.payloadbytes[size:]
        our_mac = self.cipher.finish(MAC_SIZE)

        if our_mac != their_mac:
            print 'error: invalid mac'
            print "\twe have mac 0x%s" % our_mac.encode('hex')
            print "\tthey have mac 0x%s" % their_mac.encode('hex')
            print '\tnonce is at 0x%x' % self.cipher.nonce
            raise ValueError("invalid mac")

        self.cipher.nonce += 1

        self.last_header = (None, None)
        self.payloadbytes = ''

        self.sock_lock.release()

        return (cmd, payload)

    def reconnect(self):
        raise ValueError('uh oh')
        # upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # upstream_sock.connect((SPOTIFY_HOST, SPOTIFY_PORT))

        # return upstream_sock

    def __repr__(self):
        return self.name

class SpotifyCodec(object):
    def __init__(self, sock, name):
        self.sock = sock
        self.name = name

        self.crypto = Crypto()
        self.crypto.generate_keys()

        self.enc_write_stream = None
        self.enc_read_stream = None

        self.stream_lock = threading.Lock()

    def setup_encrypted_streams(self, client_bytes, server_bytes, swap=False):
        assert self.crypto.shared_key is not None

        # print 'client bytes', client_bytes.encode('hex')
        # print 'server bytes', server_bytes.encode('hex')
        # print 'shared key', self.crypto.shared_key.encode('hex')

        data = bytes()
        for i in xrange(1, 6):
            hm = hmac.new(self.crypto.shared_key, digestmod=hashlib.sha1)
            
            hm.update(client_bytes)
            hm.update(server_bytes)
            hm.update(chr(i))
            data += hm.digest ()

        send_key = data[0x14:0x34]
        recv_key = data[0x34:0x54]

        chm = hmac.new (data[:0x14], client_bytes + server_bytes, digestmod=hashlib.sha1)
        our_challenge = chm.digest()

        if not swap:
            self.enc_write_stream = EncryptedStream(self.sock, recv_key, 'w', name=self.name + ' write')
            self.enc_read_stream = EncryptedStream(self.sock, send_key, 'r', name=self.name + ' read')
        else:
            self.enc_write_stream = EncryptedStream(self.sock, send_key, 'w', name=self.name + ' write')
            self.enc_read_stream = EncryptedStream(self.sock, recv_key, 'r', name=self.name + ' read')

        return our_challenge

    def recv_encrypted_header(self):
        return self.enc_read_stream.read_packet_header()

    def recv_encrypted_body(self, as_obj=None):
        assert self.enc_read_stream.last_header[0] is not None
        cmd, payload = self.enc_read_stream.read_packet_body()
        if cmd is None:
            # socket dead
            return (None, None)

        if as_obj is not None:
            obj = as_obj()
            obj.ParseFromString(payload)
            return (cmd, obj)
        else:
            return (cmd, payload)

    def recv_unencrypted(self, as_obj=None, initial=False):
        if initial:
            proto_ver = self.sock.recv(2, socket.MSG_WAITALL)
            data = proto_ver

            proto_ver = map(ord, proto_ver)
            if proto_ver != PROTOCOL_VERSION:
                raise ValueError('bad protocol version %r, expected %r' % (
                    proto_ver, PROTOCOL_VERSION))
        else:
            data = ''

        length_byte = self.sock.recv(4, socket.MSG_WAITALL)
        if not length_byte:
            return (None, None)

        assert len(length_byte) == 4
        data += length_byte

        length = struct.unpack('>I', length_byte)[0]

        if initial:
            # proto version counts towards length on initial packet
            length -= 2

        # read in at 4KB pages
        did_read = 0
        need_read = length - 4

        while did_read < need_read:
            obj_data = self.sock.recv(min(READ_BLOCK_SIZE, need_read - did_read))
            assert obj_data is not None

            did_read += len(obj_data)
            data += obj_data

            # print '\tread %d of %d bytes' % (did_read, need_read)

        if as_obj is not None:
            obj = as_obj()
            obj.ParseFromString(obj_data)

            return (obj, data)
        else:
            return (obj_data, data)

    def send_encrypted(self, cmd, payload):
        # self.check_wire_empty()
        self.enc_write_stream.write_packet(cmd, payload)

    def send_unencrypted(self, data, initial=False):
        # self.check_wire_empty()

        if initial:
            hdr = ''.join(map(chr, PROTOCOL_VERSION))
            assert len(hdr) == 2
        else:
            hdr = ''

        length = len(hdr) + 4 + len(data)

        buf = hdr + struct.pack('>I', length) + data
        self.sock.sendall(buf)

        return buf

    def check_wire_empty(self):
        self.sock.setblocking(0)
        try:
            assert self.sock.recv(1024) == None
        except socket.error:
            pass

        self.sock.setblocking(1)
        return True