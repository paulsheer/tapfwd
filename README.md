# tapfwd

Command-line tool for secure forwarding through a tap device to create reverse a proxy or VPN.



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
    |      /var/tmp/tapfwd-ecurve-private-key.dat           Stores the private key. Keep this secret.
    |      /var/tmp/tapfwd-ecurve-public-key.dat            Stores public key of local host.
    |      /var/tmp/tapfwd-ecurve-remote-public-key.dat     Stores public keys of remote hosts.
    |    
    |    If the remote changes its public key, or if a 'man-in-the-middle-attack' is attempted,
    |    then tapfwd will output an error message,
    |    
    |        error: /var/tmp/tapfwd-ecurve-remote-public-key.dat:N: public key for remote 'V' does not match
    |    
    |    where N is the line number of the expected key and V is <clientname> or <remoteaddress>.
    |    
    |    Perfect security can be obtained by running tapfwd -pubkey on the remote machine and placing
    |    the output into a new line in tapfwd-ecurve-remote-public-key.dat on the local machine,
    |    and visa-versa. For example the file root@123.4.5.6:/var/tmp/tapfwd-ecurve-remote-public-key.dat
    |    contains:
    |    
    |       99.1.2.3     5c76b317abbb1c2617c53480a96eac9fdee47d01989bcd7fd003714c7dc53f004e
    |    
    |    and the file root@99.1.2.3:/var/tmp/tapfwd-ecurve-remote-public-key.dat contains:
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
