# tapfwd

Command-line tool for secure forwarding through a tap device to create reverse a proxy or VPN.

    |    
    |    Usage:
    |      tapfwd  -c <remoteaddress> -ip <localprivateaddress> -n <clientname>
    |          [-p <port>] [-tun <dev>] [-auth]
    |      tapfwd  -l <listenaddress> -allow <addr>/<mask>[,<addr>/<mask>]... -ip <localprivateaddress>
    |          [-p <port>] [-tun <dev>] [-noauth] [-nostore]
    |      tapfwd  -pubkey
    |    
    |    Options:
    |      -l <listenaddress>       Server mode. Listens for incoming connections on <listenaddress>.
    |                               -auth is enabled by default for server mode to prevent non-authorized
    |                               clients from connecting.
    |      -c <remoteaddress>       Client mode. argument is an IP address.
    |      -n <clientname>          An arbitrary user name to identify the client machine to the server.
    |      -ip <localpriv>          VPN local gateway IP address. This address will be private. You will
    |                               need to set up routes to this address.
    |      -allow <addr>/<mask>[,<addr>/<mask>]...
    |                               Restrict incoming connections to clients that match.
    |      -p <port>                Preferred TCP port over which to tunnel traffic. Default 27683
    |      -tun <dev>               Preferred tun device. Default tun0
    |      -auth                    Indicates that a remote must already have its own line within
    |                               tapfwd-ecurve-remote-public-key.dat or else the handshake will
    |                               be rejected. That is, new public keys will not be stored. This
    |                               is the default for server mode.
    |      -noauth                  For server mode, allow clients with new (unknown) public keys to connect.
    |      -nostore                 For server mode, like -noauth but don't store any client public keys.
    |                               This is useful if you think your clients might be resetting their public
    |                               keys and thus are unable to connect.
    |      -pubkey                  Print out the public key for copying to another host.
    |    
    |    Example:
    |      remote@root$> tapfwd -l 0.0.0.0 -allow 123.4.5.0/24 -ip 172.16.1.6 -noauth
    |      local@root$> tapfwd -c 99.1.2.3 -ip 172.16.1.5 -n bill@microsoft.com
    |    
    |    You can then do something useful like display an X Window System program back through a NATed
    |    firewall as follows. (You will need to configure your X Server to accept TCP connections):
    |      remote@root$> DISPLAY=172.16.1.5:0.0 xterm
    |    
    |    Tapfwd is a virtual private network (VPN) tool to create an IP tunnel between two machines,
    |    with strong security in mind. The protocol of tapfwd involves curve446 and curve25519 elliptic
    |    curves for key exchange and AES256 CBC for encryption and authentication. The protocol combines
    |    both EC curves to mitigate against a weakness in either one. Public keys of remote hosts are
    |    stored on the file-system for future authentication.
    |    
    |    Files:
    |      /var/lib/tapfwd/tapfwd-ecurve-private-key.dat           Stores the private key. Keep this secret.
    |      /var/lib/tapfwd/tapfwd-ecurve-public-key.dat            Stores public key of local host.
    |      /var/lib/tapfwd/tapfwd-ecurve-remote-public-key.dat     Stores public keys of remote hosts.
    |    
    |    If the remote changes its public key, or if a 'man-in-the-middle-attack' is attempted,
    |    then tapfwd will output an error message,
    |    
    |        error: /var/lib/tapfwd/tapfwd-ecurve-remote-public-key.dat:N: public key for remote 'V' does not match
    |    
    |    where N is the line number of the expected key and V is <clientname> or <remoteaddress>.
    |    
    |    Perfect security can be obtained by running tapfwd -pubkey on the remote machine and placing
    |    the output into a new line in tapfwd-ecurve-remote-public-key.dat on the local machine,
    |    and visa-versa. For example the file root@123.4.5.6:/var/lib/tapfwd/tapfwd-ecurve-remote-public-key.dat
    |    contains:
    |    
    |       99.1.2.3     5c76b317abbb1c2617c53480a96eac9fdee47d01989bcd7fd003714c7dc53f004e
    |    
    |    and the file root@99.1.2.3:/var/lib/tapfwd/tapfwd-ecurve-remote-public-key.dat contains:
    |    
    |       bill@microsoft.com     169db5a12a3167b12af96d3fc0f243fd3f22e88ea73bf3a1c69481365ec9340123
    |    
    |    Be sure to use the -auth option.
    |    
    |    Notes:
    |      Root privileges are dropped after startup. IPv6 is supported. Intel AES-NI (hardware AES
    |      encryption) and 128-bit hardware arithmetic is used on 64-bit CPUs. Key exchanges take in the
    |      order of milliseconds. The 32-bit version is software-only and takes approximate 10X longer to
    |      perform a key exchange.
    |    
    |    
    |    
    |    The symmetric encryption algorithm is as follows:
    |    
    |    Definitions
    |        P => plaintext
    |        M => ciphertext
    |        K1, k2 => key
    |        V => IV
    |        I => nonce
    |    
    |        V, S, s, A1, A2, I, Q are 128 bits
    |        P, C, D are n * 128 bits, n > 0
    |        D is discarded
    |    
    |        AES_CBC_ENC(key, IV, plaintext) => (newIV, ciphertext)
    |        SHA256(...) => (128bit, 128bit)
    |    
    |    Encryption
    |        (C, Q) <= AES_CBC_ENC(K1, V, (I, P))
    |        (A1, A2) <= SHA256(V, C(firstblock), Q, AES_ECB_ENC(K2, V))
    |        (D, S) <= AES_CBC_ENC(K2, A1, C)
    |        (D, S) <= AES_CBC_ENC(K2, S, A2)
    |        M <= (V, C, S)
    |    
    |    Decryption
    |        (V, C, s) <= M
    |        (A1, A2) <= SHA256(V, C(firstblock), C(lastblock), AES_ECB_ENC(K2, V))
    |        (D, S) <= AES_CBC_ENC(K2, A, C)
    |        (D, S) <= AES_CBC_ENC(K2, S, A2)
    |        S ?= s
    |        ((I, P), Q) <= AES_CBC_DEC(K1, V, C)
    |    
    |    
    |    
    |    The asymmetric encryption algorithm is as follows:
    |    
    |    Nomenclature:
    |    
    |        D → permanent local storage Database
    |        random() → strong random number generator
    |        Priv → private EC key
    |        Pub → public EC key
    |        TPriv → private EC key for this session only
    |        TPub → public EC key for this session only
    |        C2 → client EC key curv25519
    |        C4 → client EC key curv448
    |        S1 → server EC key curv25519
    |        S2 → server EC key curv448
    |        B1 → base point for curv25519
    |        B2 → base point for curv448
    |        Ke → shared secret encryption key result
    |        Kd → shared secret decryption key result
    |        CN → client common name
    |        SN → server common name
    |    
    |        AES_ECB(k,p) → encrypt plaintext p with key k using AES ECB
    |        ⊕ → Exclusive OR
    |        ⇨ → Finate state machine state transition
    |    
    |        (Notes: PrivC2,S2    byte[0] &= 248,  byte[31] &= 127,  byte[31] |= 64,   as required)
    |    
    |    
    |    Client:
    |    
    |        Initialization → {
    |                PrivC2 ← random()
    |                PubC2 ← curve25519(PrivC2, B1)
    |                PrivC4 ← random()
    |                PubC4 ← curve448(PrivC4, B2)
    |                D ← (PrivC2, PubC2, PrivC4, PubC4)
    |                share to public ← (CN, PubC2, PubC4)
    |    
    |                state ← [IDLE]
    |        }
    |    
    |        state: [IDLE] ⇨ [SENT_MSG] {
    |                (PrivC2, PubC2, PrivC4, PubC4) < D
    |    
    |                TPrivC2 ← random()
    |                TPubC2 ← curve25519(TPrivC2, B1)
    |                TPrivC4 ← random()
    |                TPubC4 ← curve448(TPrivC4, B2)
    |    
    |                send(CN, TPubC2, PubC2, TPubC4, PubC4)
    |        }
    |    
    |        state: [SENT_MSG] ⇨ [VERIFY_SERVER] {
    |                (SN, TPubS1, PubS1, TPubS2, PubS2) ← recv()
    |        }
    |    
    |        state: [VERIFY_SERVER] ⇨ [DO_MATH] {
    |                verify SN is a match for PubS1,2 against public data
    |        }
    |    
    |        state: [DO_MATH] ⇨ [CONNECTED] {
    |                K2a ← curve25519(PrivC2, PubS1)
    |                K4a ← curve448(PrivC4, PubS2)
    |                K2b ← curve25519(TPrivC2, TPubS1)
    |                K4b ← curve448(TPrivC4, TPubS2)
    |    
    |                (Ke, Kd) < (AES_ECB(K2a, K4a)  ⊕  AES_ECB(K2b, K4b))
    |                discard K2a, K4a, K2b, K4b
    |        }
    |    
    |    
    |    Server:
    |    
    |        Initialization → {
    |                PrivS1 ← random()
    |                PubS1 ← curve25519(PrivS1, B1)
    |                PrivS2 ← random()
    |                PubS2 ← curve448(PrivS2, B2)
    |                share to public ← (SN, PubS1, PubS2)
    |                D ← (PrivS1, PubS1, PrivS2, PubS2)
    |    
    |                state ← [IDLE]
    |        }
    |    
    |        state: [IDLE] ⇨ [VERIFY_CLIENT] {
    |                (CN, TPubC2, PubC2, TPubC4, PubC4) ← recv()
    |        }
    |    
    |        state: [VERIFY_CLIENT] ⇨ [DO_MATH] {
    |                verify CN is a match for PubC1,2 against public data
    |        }
    |    
    |        state: [RECEIVED_MSG] ⇨ [DO_MATH] {
    |                (PrivS1, PubS1, PrivS2, PubS2) < D
    |    
    |                TPrivS1 ← random()
    |                TPubS1 ← curve25519(TPrivS1, B1)
    |                TPrivS2 ← random()
    |                TPubS2 ← curve448(TPrivS2, B2)
    |    
    |                send(SN, TPubS1, PubS1, TPubS2, PubS2)
    |        }
    |    
    |        state: [DO_MATH] ⇨ [CONNECTED] {
    |                K2a ← curve25519(PrivS1, PubC2)
    |                K4a ← curve448(PrivS2, PubC4)
    |                K2b ← curve25519(TPrivS1, TPubC2)
    |                K4b ← curve448(TPrivS2, TPubC4)
    |    
    |                (Kd, Ke) < (AES_ECB(K2a, K4a)  ⊕  AES_ECB(K2b, K4b))
    |                discard K2a, K4a, K2b, K4b
    |        }
    |    
    |    
