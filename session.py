import proto

from proxy import UpstreamConnection, DownstreamConnection
from stream import SpotifyCodec
from network import ProxyConnection

from copy import deepcopy
import hexdump

# class ClientManager(object):
#     def __init__(self, upstream_sock):
#         self.upstream = UpstreamConnection(SpotifyCodec(upstream_sock, 'upstream'))
#         self.proxy = ProxyConnection([self.upstream, self.downstream])

#     def run(self):
#         self.proxy.run()

class ProxyManager(object):
    def __init__(self, upstream_sock, downstream_sock):
        self.upstream = UpstreamConnection(SpotifyCodec(upstream_sock, 'upstream'))
        self.downstream = DownstreamConnection(SpotifyCodec(downstream_sock, 'downstream'))

        self.proxy = ProxyConnection([self.upstream, self.downstream])
    
    def run(self):
        self.proxy.run()

    def connect(self):
        # read hello from downstream
        downstream_hello, downstream_client_bytes = self.downstream.codec.recv_unencrypted(proto.ClientHello, initial=True)

        # inject our public key into client's hello
        upstream_hello = deepcopy(downstream_hello)
        upstream_hello.login_crypto_hello.diffie_hellman.gc = self.upstream.codec.crypto.public_key

        # send our hello upstream
        upstream_client_bytes = self.upstream.codec.send_unencrypted(upstream_hello.SerializeToString(), initial=True)

        # assert len(downstream_client_bytes) == len(upstream_client_bytes)

        # read upstream response back
        upstream_ap_resp, upstream_server_bytes = self.upstream.codec.recv_unencrypted(proto.APResponseMessage)

        # compute shared secrets
        self.upstream.codec.crypto.compute_shared_key(upstream_ap_resp.challenge.login_crypto_challenge.diffie_hellman.gs)
        self.downstream.codec.crypto.compute_shared_key(downstream_hello.login_crypto_hello.diffie_hellman.gc)

        # give downstream our (signed) public key
        downstream_ap_resp = deepcopy(upstream_ap_resp)
        downstream_ap_resp.challenge.login_crypto_challenge.diffie_hellman.gs = self.downstream.codec.crypto.public_key
        downstream_ap_resp.challenge.login_crypto_challenge.diffie_hellman.gs_signature = self.downstream.codec.crypto.sign_public_key('ourserver_private_key.pem')
        
        # finally send it
        downstream_server_bytes = self.downstream.codec.send_unencrypted(downstream_ap_resp.SerializeToString())

        # assert len(downstream_server_bytes) == len(upstream_server_bytes)

        # calculate hmac challenges
        downstream_challenge = self.downstream.codec.setup_encrypted_streams(downstream_client_bytes, downstream_server_bytes)
        upstream_challenge = self.upstream.codec.setup_encrypted_streams(upstream_client_bytes, upstream_server_bytes, swap=True)

        # receive downstream's challenge
        downstream_challenge_resp, _ = self.downstream.codec.recv_unencrypted(proto.ClientResponsePlaintext)

        if downstream_challenge != downstream_challenge_resp.login_crypto_response.diffie_hellman.hmac:
            print 'error: challenge differed'
            print '\tdownstream client challenge is 0x%s' % downstream_challenge_resp.login_crypto_response.diffie_hellman.hmac.encode ('hex')
            print '\tdownstream server challenge is 0x%s' % downstream_challenge.encode('hex')
            return

        # send computed challange back upstream
        upstream_challenge_protobuf = deepcopy(downstream_challenge_resp)
        upstream_challenge_protobuf.login_crypto_response.diffie_hellman.hmac = upstream_challenge

        self.upstream.codec.send_unencrypted(upstream_challenge_protobuf.SerializeToString())