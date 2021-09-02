from enum import Enum

class SpotifyCommand(Enum):

    USER_PREF = 0x74

    CLIENT_HASH = 0x0f
    SHA_HASH = 0x10

    UNK_ZEROES = 0x1f # usually all zeros, of len 17
    UNK_0 = 0x76 # from server - usually 00 01 08 31 2E 30 2E 31  2D 55 53 = '...1.0.1-US'

    UNK_1 = 0x5e
    UNK_2 = 0x5a
    UNK_4 = 0x38
    UNK_5 = 0x39
    UNK_6 = 0x79
    UNK_7 = 0x27

    UNK_8 = 0x61

    UNK_3 = 0xb7
    PLAYLIST_UNK = 0x5c

    PING = 0x04
    unk_maybe_error = 0x05 # 00 FB 00 00 00 00 00 05  6C 6F 67 69 6E = ' ........login', or older protocol proxy?

    query = 0x57
    # query_resp = 0x58 - maybe

    PONG = 0x49
    PONG_ACK = 0x4a
    LOG  = 0x48
    LOGIN = 0xab
    LOGIN_SUCCESS = 0xac
    LOGIN_FAILURE = 0xad
    UPGRADE = 0xa4 # after WELCOME

    # from server
    SECRET_BLK = 0x02
    COUNTRY_CODE = 0x1b
    WELCOME = 0x69
    PRODINFO = 0x50

    # mercury
    MERCURY_REQUEST = 0xb2
    MERCURY_SUB = 0xb3
    MERCURY_UNSUB = 0xb4

    MERCURY_NOTIFY = 0xb5
    MERCURY_CB = 0xb6

    # older protocol
    BROWSE = 0x30
    SEARCH = 0x31
    GET_PLAYLIST = 0x35
    CHANGE_PLAYLIST = 0x36

    # p2p
    P2P_SETUP = 0x20
    P2P_INITBLK = 0x21

    CHANNEL_SUBSTREAM = 0x08
    CHANNEL_DATA = 0x09
    CHANNEL_ERROR = 0x0a
    CHANNEL_ABORT = 0x0b

    KEY_REQUEST = 0x0c
    KEY_AES_DATA = 0x0d
    KEY_AES_ERROR = 0x0e

    IMAGE = 0x19
    TOKEN_NOTIFY = 0x4f

    notify = 0x42
    pause = 0x4b
    request_ad = 0x4e
    REQUEST_PLAY = 0x4f