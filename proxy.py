from network import Connection
from mercury import MercuryParser
from commands import SpotifyCommand

import hexdump
import os
import zlib
import json

import proto

PRODINFO_FILENAME = 'prodinfo.xml'

class DownstreamConnection(Connection):
    def __init__(self, codec):
        super(DownstreamConnection, self).__init__(codec, 'downstream')
        self.mercury_parser = MercuryParser()
        self.final = True
        self.handlers.update({
            SpotifyCommand.LOGIN: (self.login, proto.ClientResponseEncrypted),
            SpotifyCommand.LOG: (self.log, None),
            SpotifyCommand.PONG: (self.pong, None),
            SpotifyCommand.CLIENT_HASH: (self.client_hash, None),

            # used in 0.8.8 client
            SpotifyCommand.UNK_1: (self.passthrough_from_downstream, None),
            SpotifyCommand.UNK_2: (self.passthrough_from_downstream, None),
            SpotifyCommand.UNK_4: (self.passthrough_from_downstream, None),
            SpotifyCommand.UNK_5: (self.passthrough_from_downstream, None),
            SpotifyCommand.UNK_6: (self.passthrough_from_downstream, None),
            SpotifyCommand.BROWSE: (self.passthrough_from_downstream, None),
            SpotifyCommand.SEARCH: (self.passthrough_from_downstream, None),
            SpotifyCommand.GET_PLAYLIST: (self.passthrough_from_downstream, None),
            SpotifyCommand.CHANGE_PLAYLIST: (self.passthrough_from_downstream, None),
            SpotifyCommand.UNK_7: (self.passthrough_from_downstream, None),
            SpotifyCommand.UNK_8: (self.passthrough_from_downstream, None),

            SpotifyCommand.P2P_SETUP: (self.passthrough_from_downstream, None),

            # used in 0.9.17 client
            SpotifyCommand.UNK_3: (self.passthrough_from_downstream, None),
            SpotifyCommand.PLAYLIST_UNK: (self.passthrough_from_downstream, None),
            SpotifyCommand.IMAGE: (self.passthrough_from_downstream, None),

            SpotifyCommand.CHANNEL_SUBSTREAM: (self.passthrough_from_downstream, None),
            SpotifyCommand.CHANNEL_ABORT: (self.passthrough_from_downstream, None),
            SpotifyCommand.CHANNEL_DATA: (self.passthrough_from_downstream, None),
            SpotifyCommand.CHANNEL_ERROR: (self.passthrough_from_downstream, None),
            SpotifyCommand.TOKEN_NOTIFY: (self.passthrough_from_downstream, None),
            SpotifyCommand.KEY_REQUEST: (self.passthrough_from_downstream, None),
            SpotifyCommand.REQUEST_PLAY: (self.passthrough_from_downstream, None),

            # SpotifyCommand.MERCURY_REQUEST: (self.passthrough_from_downstream_quiet, None),
            # SpotifyCommand.MERCURY_SUB: (self.passthrough_from_downstream_quiet, None),
            # SpotifyCommand.MERCURY_UNSUB: (self.passthrough_from_downstream_quiet, None),

            SpotifyCommand.MERCURY_REQUEST: (self.handle_mercury_downstream, None),
            SpotifyCommand.MERCURY_SUB: (self.handle_mercury_downstream, None),
            SpotifyCommand.MERCURY_UNSUB: (self.handle_mercury_downstream, None),
        })

    def passthrough_from_downstream_quiet(self, cmd, data):
        print 'received command %r len %d downstream' % (cmd, len(data))
        self.remote.send_queue.put((cmd, data))

    def passthrough_from_downstream(self, cmd, data):
        print 'received command %r len %d downstream' % (cmd, len(data))
        hexdump.hexdump(data)

        self.remote.send_queue.put((cmd, data))

    def pong(self, cmd, pong_data):
        print 'Received pong'
        self.remote.send_queue.put((cmd, pong_data))

    def log(self, cmd, log_info):
        # print 'Received log event'
        # hexdump.hexdump(log_info)

        # self.remote.send_queue.put((cmd, log_info))
        pass

    def client_hash(self, cmd, client_hash):
        print 'received client hash downstream'
        hexdump.hexdump(client_hash)
        self.remote.send_queue.put((cmd, client_hash))

    def handle_mercury_downstream(self, cmd, payload):
        seq, flags, count, data = self.mercury_parser.parse_header(payload[:])
        if flags == 1:
            # final
            self.final = True
        else:
            print '!!! not final flag'
            self.final = False

        seq, frames = self.mercury_parser.parse_packet(payload[:])
        print 'had mercury cmd %r downstream' % cmd
        # print 'seq %s, |frames| = %d' % (seq.encode('hex'), len(frames))

        request = proto.Header()
        request.ParseFromString(frames[0])

        print 'request was'
        print request

        payloads = frames[1:]

        # assert len(payloads) <= 1

        if payloads:
            mercury_payload = payloads[0]
        else:
            mercury_payload = None

        if cmd == 0xb3:
            method = 'SUB'
        elif cmd == 0xb4:
            method = 'UNSUB'
        else:
            method = request.method

        if mercury_payload:
            hexdump.hexdump(mercury_payload)

        if request.uri == 'hm://event-service/v1/events':
            if '127.0.0.1' in mercury_payload:
                print '** warning: ignoring mercury request to %s' % request.uri
                return

        # if 'hm://pusher' in request.uri or 'hm://identity/' in request.uri:
        #     print '** warning: ignoring mercury request to %s' % request.uri
        #     return

        # send it off
        # TODO: pass in callback which sends data back to client after inspection
        # self.mercury.request(method, request.uri, mercury_payload, mime=request.content_type)
        self.remote.send_queue.put((cmd, payload))

    def login(self, cmd, client_response_encrypted):
        print 'downstream attempted to login with:'
        print client_response_encrypted

        self.remote.send_queue.put((cmd, client_response_encrypted.SerializeToString()))

class UpstreamConnection(Connection):
    def __init__(self, codec):
        super(UpstreamConnection, self).__init__(codec, 'upstream')
        self.mercury_parser = MercuryParser()
        self.final = True
        self.handlers.update({
            SpotifyCommand.PING: (self.ping, None),
            SpotifyCommand.PONG_ACK: (self.pongack, None),

            SpotifyCommand.LOGIN_SUCCESS: (self.login_success, proto.APWelcome),
            SpotifyCommand.LOGIN_FAILURE: (self.passthrough_from_upstream, None),
            SpotifyCommand.WELCOME: (self.passthrough_from_upstream, None),

            SpotifyCommand.UNK_ZEROES: (self.unk_for_auth, None),
            SpotifyCommand.UNK_0: (self.passthrough_from_upstream, None),

            # from 0.8.8 client
            SpotifyCommand.P2P_INITBLK: (self.passthrough_from_upstream, None),

            # used in 0.9.17 client
            SpotifyCommand.CHANNEL_ABORT: (self.passthrough_from_upstream, None),
            SpotifyCommand.CHANNEL_DATA: (self.passthrough_from_upstream, None),
            SpotifyCommand.CHANNEL_ERROR: (self.passthrough_from_upstream, None),

            SpotifyCommand.KEY_AES_DATA: (self.passthrough_from_upstream, None),
            SpotifyCommand.KEY_AES_ERROR: (self.passthrough_from_upstream, None),

            SpotifyCommand.SHA_HASH: (self.passthrough_from_upstream, None),

            SpotifyCommand.PRODINFO: (self.handle_prodinfo, None),
            SpotifyCommand.SECRET_BLK: (self.handle_secret_blk, None),
            SpotifyCommand.COUNTRY_CODE: (self.handle_country_code, None),

            # SpotifyCommand.MERCURY_REQUEST: (self.passthrough_from_upstream_quiet, None),
            # SpotifyCommand.MERCURY_SUB: (self.passthrough_from_upstream_quiet, None),
            # SpotifyCommand.MERCURY_UNSUB: (self.passthrough_from_upstream_quiet, None),
            # SpotifyCommand.MERCURY_NOTIFY: (self.passthrough_from_upstream_quiet, None),
            # SpotifyCommand.MERCURY_CB: (self.passthrough_from_upstream_quiet, None),

            SpotifyCommand.MERCURY_REQUEST: (self.handle_mercury_upstream, None),
            SpotifyCommand.MERCURY_SUB: (self.handle_mercury_upstream, None),
            SpotifyCommand.MERCURY_UNSUB: (self.handle_mercury_upstream, None),
            SpotifyCommand.MERCURY_NOTIFY: (self.handle_mercury_upstream, None),
            SpotifyCommand.MERCURY_CB: (self.handle_mercury_upstream, None),
        })

    def login_success(self, cmd, resp):
        print 'upstream reports login success!'
        print resp

        self.remote.send_queue.put((cmd, resp.SerializeToString()))

    def passthrough_from_upstream_quiet(self, cmd, data):
        print 'received command %r len %d upstream' % (cmd, len(data))
        self.remote.send_queue.put((cmd, data))

    def passthrough_from_upstream(self, cmd, data):
        print 'received command %r len %d upstream' % (cmd, len(data))
        hexdump.hexdump(data)

        self.remote.send_queue.put((cmd, data))

    def unk_for_auth(self, cmd, data):
        print 'received weird auth cmd %r upstream' % cmd
        hexdump.hexdump(data)

        self.remote.send_queue.put((cmd, data))

    def handle_prodinfo(self, cmd, prodxml):
        if not os.path.exists(PRODINFO_FILENAME):
            print 'saving prodinfo to', PRODINFO_FILENAME
            with open(PRODINFO_FILENAME, 'wb') as f:
                f.write(prodxml)
        else:
            print 'using prodinfo data from', PRODINFO_FILENAME
            with open(PRODINFO_FILENAME, 'rb') as f:
                prodxml = f.read()

        self.remote.send_queue.put((cmd, prodxml))

    def handle_country_code(self, cmd, country_code):
        print 'received country code', country_code, 'from upstream'
        self.remote.send_queue.put((cmd, country_code))

    def handle_secret_blk(self, cmd, secret_data):
        print 'received secret block upstream'
        self.remote.send_queue.put((cmd, secret_data))

        # client uses this to sign their offline key
        # secret_data[16:16 + 128] is rsa public exponent
        # secret_data[16 + 128:] is 144 byte rsa signature?
        # see despotify/src/lib/handlers.c - handle_secret_block()

    def ping(self, cmd, ping_data):
        print 'received ping from upstream'
        self.remote.send_queue.put((cmd, ping_data))

    def pongack(self, cmd, pong_ack_data):
        print 'received pong-ack from upstream'
        self.remote.send_queue.put((cmd, pong_ack_data))

    def handle_mercury_upstream(self, cmd, payload):

        # seq, flags, count, data = self.mercury_parser.parse_header(payload[:])

        seq, frames = self.mercury_parser.parse_packet(payload[:])
        if frames is None:
            print 'received incomplete mercury response with cmd %r upstream' % cmd
            self.remote.send_queue.put((cmd, payload))
            return

        print 'received complete mercury response with cmd %r upstream' % cmd

        response = proto.Header()
        response.ParseFromString(frames[0])

        # if response.uri.startswith('hm://pusher/v1/connections/') or response.uri.startswith('hm://identity/v1/user/'):
        #     print '** skipping'
        #     print 'remaining frames are:', frames
        #     return

        #     split_uri = response.uri.split('/')
        #     prefix = split_uri[:-1]
        #     dest_b64 = split_uri[-1]

        #     pusher_decoded = base64.b64decode(dest_b64)
        #     pusher_fields = pusher_decoded.split('+')

        #     # first field is device_id from login request
        #     # second is AP
        #     # third is 'tcp://gae2-accesspoint-b-mzf1.gae2.spotify.net:5026'
        #     # last is some hash (probably sha256 of something)
        #     pusher_fields[2] = 'tcp://'

        print response

        if len(frames[1:]) > 0:
            # print payload if we have it here
            for payload_frame in frames[1:]:
                kv = {}
                for user_field in response.user_fields:
                    kv[user_field.key.lower()] = user_field.value

                if 'content-encoding' in kv:
                    if kv['content-encoding'] == 'gzip':
                        # decode response first
                        payload_frame = zlib.decompress(payload_frame, 16+zlib.MAX_WBITS)

                if 'application/json' in response.content_type:
                    j = json.loads(payload_frame)
                    print json.dumps(j, indent=2)
                else:
                    hexdump.hexdump(payload_frame)

        self.remote.send_queue.put((cmd, payload))