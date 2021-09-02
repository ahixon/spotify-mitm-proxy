# Spotify MITM proxy

Lets you analyze the protocols used by the Spotify protocol, and dumps the traffic in real time.

It targets V4 of the wire protocol.

# Server

First, install the dependencies:

    # see https://grpc.io/docs/protoc-installation/ for other platforms
    brew install protobuf
    easy_install hexdump protobuf cython

    cd pyshn
    sudo python setup.py install

    # build the protobuf modules
    make

Don't forget to point Spotify to our localhost server:

    sudo bash -c 'echo "127.0.0.1       apresolve.spotify.com ap.spotify.com" >> /etc/hosts' 

## AP resolve server

Older Spotify clients would do a GET to `http://apresolve.spotify.com`, which would return a JSON reponse containing a list of access points to connect to. 

These days, the client just does a DNS lookup on `ap.spotify.com`, and uses the A records to select an access point instead, so you can probably skip this step.

If you still need the resolver, you can run (with root privileges):

    python apresolve.py

to run a simple HTTP server that just points to a single localhost AP.

## Starting the proxy server

Start the proxy server with:

    python apserver.py

It starts a local AP server, proxying all data to the upstream server + port combination hard-coded at the top of the file.

To kill the server, `Ctrl + C` won't do anything -- find the PID and just do a `kill`; no need to `-9` (at least on OS X, anyway).

## Controlling what's logged

In `proxy.py`, you can change the callback to something less (or more) noisy.

## prodinfo.xml

During sign-on, `prodinfo.xml` will be created and cached. You can change it, and next time the client is run, it will be sourced from the local filesystem.

You can use this to change your status in A/B experiments, change your catalogue, and so on.

# Client

When logging in, the Spotify client verifies that the login response was actually from a Spotify server, by checking that the `gs_signature` field is the session's public key signed by the server's private key. See "Auth process" below for the algorithm.

We can't naively pass through the login response from upstream, since the signature field won't match -- it would be signed against a different public key compared to the downstream session.

One way would be to modify the client binary so it skips the signature check (`ap_signature`). This is fairly brittle, though, and, plus, I wasn't sure if it was used for anything else in the protocol.

Instead, we can change or add our own public key to the list of valid signing keys. I've written a tool that does this for you (this should work on **all platforms**, though I'm using OS X here for consistency):

    # get a copy of the client from somewhere; lets use the locally installed copy
    mkdir binaries
    cp -R /Applications/Spotify.app binaries

    # patch the public key with our server's one
    # this automatically creates a backup for you
    python replace_pubkey.py binaries/Spotify.app/Contents/MacOS/Spotify

Hooray! You can now start the Spotify app, and it should "just work":

    ./binaries/Spotify.app/Contents/MacOS/Spotify --show-console --mu=new-profile

The Spotify client will attempt to connect to one the servers after looking up `ap.spotify.com` (which should just resolve to localhost now), and tries with the following ports (not in this order):

* 4070 -- the Spotify protocol port
* 80 - HTTP
* 443 - HTTPS

Our server only handles the first one, with the client timing out on the other ports.

# Auth process

## Login process

`session.py` provides an annotated copy of how the login challenge process works, both from a client's perspective (communicating upstream) and from a server's perspective (communicating downstream).

## gs_signature

This was the main driver for this project -- [what the heck does the gs_signature field do](https://github.com/librespot-org/librespot/issues/36)?!

As described in the linked ticket title, it's to prevent MITM attacks on the Spotify client by ensuring the login response is signed by one of the valid keys shipped with the client.

After reversing the client, this is how it's calculated:

### Client side

    server_hash = \0 + sha1_prefix + sha1(server_pub)
    gs_signature_decrypted = gs_signature ^ pub_exponent % pubkey_modulus

    success = (gs_signature_decrypted == server_hash) ? ok : not_ok

### Server side

    server_hash = \0 + sha1_prefix + sha1(pub)
    gs_signature = pub_exponent ^ privkey % server_hash

# Improvements

CPU usage is a bit nuts, and not being able to kill the server with Ctrl + C is a bit annoying.

# Example log

    Ready to go...
    Making proxy connection to guc3-accesspoint-a-zk36.ap.spotify.com 4070

    starting select thread for upstream connection
    starting select thread for downstream connection
    joining on network threads
    downstream attempted to login with:
    login_credentials {
    username: "1234567890"
    typ: AUTHENTICATION_STORED_SPOTIFY_CREDENTIALS
    auth_data: "AQAD_mdQZIw2SWr6FgqifdU07yinIpSaX32RpAMA_VVt_gjah7cJtf86L8Jrd8Jq6a1r7k7k8pIn8jA9CXCK5CXyExmHaIzQgipLQQ9YbswDp2P0yGYOjkzaXi6rSIOY99Ax76enRwQ"
    }
    account_creation: ACCOUNT_CREATION_ALWAYS_PROMPT
    fingerprint_response {
    grain {
        encrypted_key: "\375\020n\002\371QYp+\374\376_\331+.\207"
    }
    }
    system_info {
    cpu_family: CPU_X86
    cpu_subtype: 8
    cpu_ext: 0
    brand: BRAND_UNBRANDED
    brand_flags: 0
    os: OS_OSX
    os_version: 111
    os_ext: 0
    system_information_string: "OS X 11.1.0 [x86 8]"
    device_id: "5514F273-1389-5BDD-3154-FB5E0E46269Dlocal2"
    }
    platform_model: "MacBookAir8,1"
    version_string: "1.1.66.580.gbd43cbc9"
    client_info {
    limited: false
    language: "en"
    }

    upstream reports login success!
    canonical_username: "1234567890"
    account_type_logged_in: Facebook
    credentials_type_logged_in: Spotify
    reusable_auth_credentials_type: AUTHENTICATION_STORED_SPOTIFY_CREDENTIALS
    reusable_auth_credentials: "AQAD_mdQZIw2SWr6FgqifdU07yinIpSaX32RpAMA_VVt_gjah7cJtf86L8Jrd8Jq6a1r7k7k8pIn8jA9CXCK5CXyExmHaIzQgipLQQ9YbswDp2P0yGYOjkzaXi6rSIOY99Ax76enRwQ"
    lfs_secret: "=\316U\341\624km\204\205\338\2676Pe\007\263w\343\"\225"
    account_info {
    facebook {
    }
    }

    received ping from upstream
    received secret block upstream
    received command <SpotifyCommand.UNK_0: 118> len 2 upstream
    00000000: 00 00                                             ..
    received country code US from upstream
    received client hash downstream
    00000000: 7B E5 E5 1D 5E 05 FA 74  53 9B F1 64 BF 20 06 2C  {...^..tS..d. .,
    00000010: 2A 9C 52 E8                                       *.R.
    using prodinfo data from prodinfo.xml
    received command <SpotifyCommand.WELCOME: 105> len 0 upstream
    upstream connection received unknown cmd <SpotifyCommand.UPGRADE: 164>
    contained the following payload:
    00000000: 52 8B 01 08 09 10 01 18  A9 EB D2 37 20 AA EB D2  R..........7 ...
    00000010: 37 2A 60 68 74 74 70 73  3A 2F 2F 75 70 67 72 61  7*`https://upgra
    00000020: 64 65 2E 73 63 64 6E 2E  63 6F 2F 75 70 67 72 61  de.scdn.co/upgra
    00000030: 64 65 2F 63 6C 69 65 6E  74 2F 6F 73 78 2D 78 38  de/client/osx-x8
    00000040: 36 5F 36 34 2F 73 70 6F  74 69 66 79 2D 61 75 74  6_64/spotify-aut
    00000050: 6F 75 70 64 61 74 65 2D  31 2E 31 2E 36 37 2E 35  oupdate-1.1.67.5
    00000060: 38 36 2E 67 62 62 35 65  66 36 34 65 2D 32 32 2E  86.gbb5ef64e-22.
    00000070: 74 62 7A 32 14 8D 3F BC  B9 CF 1B 5B C6 8C 42 42  tbz2..?....[..BB
    00000080: 96 D7 64 B2 1D 0C 79 8E  7A 38 02 48 90 1C A2 01  ..d...y.z8.H....
    00000090: 80 02 96 93 D8 55 66 DD  13 67 6F 77 EE 53 1F 5C  .....Uf..gow.S.\
    000000A0: 67 C2 D4 88 6E 57 6F 4B  BB 61 47 19 DA 11 82 6F  g...nWoK.aG....o
    000000B0: 64 00 D3 21 86 49 F6 F5  C4 C2 B4 58 17 7C 15 37  d..!.I.....X.|.7
    000000C0: 3F AA AA 14 B7 E7 66 E9  C2 4A 1B C7 6E 0C 0E 52  ?.....f..J..n..R
    000000D0: C4 52 90 A3 A3 ED DA D9  FA 20 7C 87 59 67 65 67  .R....... |.Ygeg
    000000E0: 81 07 A9 05 80 0B CA 6B  DA 1E D1 0C 7E 61 4F 35  .......k....~aO5
    000000F0: E4 49 52 EC 14 80 CC E5  21 77 B5 B7 EA C6 BB D5  .IR.....!w......
    00000100: 7D CC 97 88 97 7B 52 71  DB 33 2A D7 7C 85 40 91  }....{Rq.3*.|.@.
    00000110: 9C 2D DB 42 B3 E8 1C FF  92 A5 AF 5A 69 19 E4 B4  .-.B.......Zi...
    00000120: A6 02 3E 90 50 72 56 5D  B4 6E 74 A8 88 92 12 E8  ..>.PrV].nt.....
    00000130: 7C E4 52 C1 21 89 80 32  D9 68 AC 65 6D DB D0 AF  |.R.!..2.h.em...
    00000140: DC CD 2B 7D A9 07 0E E2  8D 47 A7 8A A5 D5 60 11  ..+}.....G....`.
    00000150: 99 8B EA 24 B0 D0 3B A5  05 DB 54 C5 FF 21 DC 2C  ...$..;...T..!.,
    00000160: EE D5 39 1B DC B3 B6 43  6B F0 75 99 CF 2E 9A 9A  ..9....Ck.u.....
    00000170: 04 B9 16 4B 89 11 A7 C4  57 8C 18 F8 A9 FE D8 A5  ...K....W.......
    00000180: EA ED 9F 89 03 FB AA FA  D5 70 7A 44 DC 1B 72 BF  .........pzD..r.
    00000190: B0 BF F2 01 37 3F 68 6F  73 74 3D 67 75 63 33 2D  ....7?host=guc3-
    000001A0: 61 63 63 65 73 73 70 6F  69 6E 74 2D 61 2D 7A 6B  accesspoint-a-zk
    000001B0: 33 36 2E 67 75 63 33 2E  73 70 6F 74 69 66 79 2E  36.guc3.spotify.
    000001C0: 6E 65 74 26 70 69 64 3D  32 34 34 39              net&pid=2449
    None
    received weird auth cmd <SpotifyCommand.UNK_ZEROES: 31> upstream
    00000000: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
    00000010: 00                                                .
    received complete mercury response with cmd <SpotifyCommand.MERCURY_NOTIFY: 181> upstream
    uri: "hm://pusher/v1/connections/MzUxMUIyNzYtMTVCOS01QkRELTgwNTQtRkI1RTBFNDc3NjlEbG9jYWwyK0FQK3RjcDovL2d1YzMtYWNjZXNzcG9pbnQtYS16azM2Lmd1YzMuc3BvdGlmeS6uZXQ5NTAwOCs3RTk5QkY4NEQ5MUI5MEFEREJCQ0I2MjYyMUUwOTBCODREREVBNTZBNDM5QTYyQkQ3MjFGQjlGMjVFNTE1NEM0"
    status_code: 200
    user_fields {
    key: "Spotify-Connection-Id"
    value: "MzUxMUIyNzYtMTVCOS01QkRELTgwNTQtRkI1RTBFNDc3NjlEbG9jYWwyK0FQK3RjcDovL2d1YzMtYWNjZXNzcG9pbnQtYS16azM2Lmd1YzMuc3BvdGlmeS6uZXQ5NTAwOCs3RTk5QkY4NEQ5MUI5MEFEREJCQ0I2MjYyMUUwOTBCODREREVBNTZBNDM5QTYyQkQ3MjFGQjlGMjVFNTE1NEM0"
    }