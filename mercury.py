# from librespot (https://github.com/plietar/librespot)
# Licensed under the MIT License.
# Modified by Alex Hixon

from __future__ import absolute_import, division, print_function

import struct
# from hexdump import dump as hexdump
import hexdump

import proto

PROTOCOLS = {
        'vnd.spotify/mercury-mget-request': proto.MercuryMultiGetRequest,
        'vnd.spotify/mercury-mget-reply': proto.MercuryMultiGetReply,
        'vnd.spotify/metadata-track': proto.Track,
        'vnd.spotify/metadata-artist': proto.Artist
}

def find_protocol(mime):
    return PROTOCOLS[mime] if mime and mime in PROTOCOLS else None

def decode_payload(data, mime=None, schema=None):
    proto = schema if schema else find_protocol(mime)
    if proto:
        obj = proto()
        obj.ParseFromString(data)
        return obj
    else:
        return None

class MercuryParser(object):
    def __init__(self):
        self.frames = dict()
        self.data = dict()
    def parse_header(self, data):
        offset = 0
        seq_length, = struct.unpack_from('>H', data, offset)
        offset += 2
        seq = data[offset:offset+seq_length]
        offset += seq_length
        flags, count = struct.unpack_from('>bH', data, offset)
        offset += 3

        return seq, flags, count, data[offset:]

    def parse_frames(self, data, count):
        offset = 0
        frames = []
        for i in range(count):
            length, = struct.unpack_from('>H', data, offset)
            offset += 2
            frames.append(data[offset:offset+length])
            offset += length
        return frames

    def parse_packet(self, data):
        seq, flags, count, data = self.parse_header(data)
        # print('\'%s\' flags=%x count=%x datalen=%x' % (hexdump.dump(seq), flags, count, len(data)))

        self.data.setdefault(seq, bytes())
        self.frames.setdefault(seq, list())

        frames = self.parse_frames(data, count)
        frames[0] = self.data[seq] + frames[0]

        if flags == 2:
            self.frames[seq] += frames[:-1]
            self.data[seq] = frames[-1]
        else:
            self.frames[seq] += frames
            del self.data[seq]

        if flags != 1:
            return seq, None

        frames = self.frames[seq]
        del self.frames[seq]

        return seq, frames

class Mercury(MercuryParser):
    def __init__(self, upstream, downstream):
        super(Mercury, self).__init__()

        self.upstream = upstream
        self.downstream = downstream

        self.callbacks = dict()
        self.subscriptions = dict()
        self.seq = 0

    def request(self, method, url, payload=None, mime=None, callback=None, schema=None):
        if url == 'hm://event-service/v1/events':
            print('** warning: ignoring mercury request to %s' % url)
            print(payload)
            return

        seq, data = self.encode_request(method, url, payload=payload, mime=mime)

        if method == 'SUB':
            cmd = 0xb3
        elif method == 'UNSUB':
            cmd = 0xb4
        else:
            cmd = 0xb2

        self.upstream.send_encrypted(cmd, data)

        if callback:
            self.callbacks[seq] = (callback, schema)

    def get(self, *args, **kwargs):
        self.request('GET', *args, **kwargs)

    def multiget(self, endpoint, urls, callback=None, schema=None):
        def cb(response, payload):
            payloads = map(
                    lambda r: decode_payload(r.body, schema=schema, mime=r.mime),
                    payload.reply)
            callback(payloads)

        payload = proto.MercuryMultiGetRequest()

        for u in urls:
            p = payload.request.add()
            p.url = u

        self.request('GET', endpoint,
                mime='vnd.spotify/mercury-mget-request',
                payload=payload,
                callback=cb)

    def subscribe(self, url, callback=None, schema=None):
        def cb(response, *subs):
            for s in subs:
                self.subscriptions[s.url] = (callback, schema)

        self.request('SUB', url,
                callback=cb,
                schema=proto.MercurySubscribed)

    def encode_request(self, method, url, mime=None, payload=None, seq=None):
        if seq is None:
            seq = struct.pack('>L', self.seq)
            self.seq += 1

        flags = 1 # FINAL
        count = 2 if payload else 1

        header = struct.pack('>H', len(seq)) + \
                seq + \
                struct.pack('>bH', flags, count)

        request = proto.Header()
        request.uri = url
        request.method = method
        if mime:
            request.content_type = mime
        else:
            request.content_type = ""

        data = header + \
                struct.pack('>H', request.ByteSize()) + \
                request.SerializeToString()
        if payload:
            try:
                data += struct.pack('>H', payload.ByteSize()) + \
                        payload.SerializeToString()
            except AttributeError:
                data += payload

        return seq, data

    def handle_packet(self, cmd, data):
        seq, frames = self.parse_packet(data)
        if frames is None:
            return

        response = proto.MercuryReply()
        response.ParseFromString(frames[0])

        if cmd == 0xb5:
            cs = self.subscriptions.get(response.url)
        else:
            cs = self.callbacks.get(seq)

        if not cs:
            return

        callback, schema = cs
        payloads = map(
                lambda f: decode_payload(f, schema=schema, mime=response.mime),
                frames[1:])

        callback(response, *payloads)
        if cmd != 0xb5:
            del self.callbacks[seq]
