/system identity
set name=BRANCH-MT
/interface ethernet
set [ find default-name=ether1 ] comment="WAN"
/ip address
add address=10.20.20.1/24 interface=ether2
add address=198.51.100.2/30 interface=ether1
/ip service
set telnet disabled=yes
set ssh disabled=no address=10.20.20.0/24
/user
add name=engineer group=full password=SANITIZED_DEMO_PASSWORD
