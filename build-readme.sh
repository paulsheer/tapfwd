
echo '# tapfwd'
echo
echo 'Command-line tool for secure forwarding through a tap device to create reverse a proxy or VPN.'
echo
./tapfwd -h | sed -e 's/^/    |    /'
echo '    |    '
cat README.encryption | sed -e 's/^/    |    /'



