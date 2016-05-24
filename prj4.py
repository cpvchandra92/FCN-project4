import socket, sys, random
from struct import *
from urlparse import urlparse 

#Parse the URL to get path and file name
host_name = ''
try:
    URL=sys.argv[1]
    parsed_uri = urlparse(URL)
    host_name='{uri.netloc}'.format(uri=parsed_uri)
    if("http:" in URL):
        path='{uri.path}'.format(uri=parsed_uri)
        if(path=='' or path=='/'):
            path='/'
            file_name = 'index.html'
        else:
            end=path.find("/",-1)
            if(end>0):
                splitter=path.split("/")
                file_name="index.html"
            else:
                splitter=path.split("/")
                file_name=splitter[-1]
    else:
        sys.exit(0)

except:
    sys.exit(0)
 
# calculate checksum for packets to be sent
def checksum(msg):
    s = 0
    length=len(msg)
    i=0
    while length>1 :
        w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
        s = s + w
        i+=2
        length-= 2
    if length==1:
        s=s+ord(msg[i])
    s = (s>>16) + (s & 0xffff);
    s = s + (s >> 16);
    s = ~s & 0xffff
    return s

#calculate check sum for received packets
def checksumrec(msg):
    s = 0
    length=len(msg)
    i=0
    while length>1 :
        w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
        s = s + w
        i+=2
        length-= 2
    if length==1:
        s=s+ord(msg[i])
    s = (s>>16) + (s & 0xffff);
    s = s + (s >> 16);
    s = ~s & 0xffff
    s = s >> 8 | ((s & 0xff) << 8)
    return s

#get local IP address
def get_src_ip():
    src_s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    src_s.connect(("www.google.com",80))
    src_ip=(src_s.getsockname()[0])
    return src_ip

#create a raw socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

except socket.error , msg:
    sys.exit()

#resolve IP address of the server
try:   
    packet = '';
    source_ip = get_src_ip();
    dest_ip = socket.gethostbyname(host_name)
except:
    sys.exit(0)

#create IP headers for packets to be sent
def ipheader(ip_ihl,ip_ver,ip_tos,ip_tot_len,ip_id,ip_frag_off): 

    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0   
    ip_saddr = socket.inet_aton ( source_ip ) 
    ip_daddr = socket.inet_aton ( dest_ip )
    ip_ihl_ver = (ip_ver << 4) + ip_ihl 
    return pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

#select a random port number
tcp_source = random.randrange(10000,50000,1)
tcp_dest = 80
tcp_seq = 1
tcp_ack_seq = 0

#create TCP header for the packets to be sent
def tcpheader(tcp_seq,tcp_ack_seq,tcp_fin,tcp_syn,tcp_rst,tcp_psh,tcp_ack,tcp_urg,user_data):

    tcp_doff = 5   
    tcp_window = socket.htons (5840)
    tcp_check = 0
    tcp_urg_ptr = 0
    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)
    tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)
    source_address = socket.inet_aton( source_ip )
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) + len(user_data)
    psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
    psh = psh + tcp_header + user_data;
    tcp_check = checksum(psh)
    return pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + pack('H' , tcp_check) + pack('!H' , tcp_urg_ptr)

#function for calculating check sum for received packets
def calc_ser_csum(iph,tcph,user_data):

    tcp_window = socket.htons (5840)
    tcp_check = 0
    tcp_header = pack('!HHLLBBHHH' , tcph[0], tcph[1], tcph[2], tcph[3], tcph[4], tcph[5], tcph[6], 0, 0)
    source_address = socket.inet_aton(dest_ip)
    dest_address = socket.inet_aton(source_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) + len(user_data)
    psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
    psh = psh + tcp_header + user_data;
    tcp_check = checksumrec(psh)
    return tcp_check

#create packet from headers and data
def create_packet(ip_header,tcp_header,user_data):
    return ip_header + tcp_header + user_data

try:
    s1 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

except socket.error , msg:
    sys.exit()

server_tcp_sequence = 0
prev_seq = 0
payload = 0
FIN = '0'

#recieve packets during handshakes
def recpacket():
    while True:
        packet = s1.recvfrom(65535)
        packet = packet[0]
        ip_header = packet[0:20]
        iph = unpack('!BBHHHBBH4s4s' , ip_header)
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4     
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);
        if(s_addr == dest_ip and d_addr ==  source_ip) :
            tcp_header = packet[iph_length:iph_length+20]
            tcph = unpack('!HHLLBBHHH' , tcp_header)
            source_port = tcph[0]
            dest_port = tcph[1]
            global server_tcp_sequence
            global prev_seq
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4
            rec_flags = tcph[5]
            rec_flags = tcph[5]
            rec_flags = str( bin (rec_flags))
            global FIN
            FIN = rec_flags[-1]
            global payload
            if(source_port == 80 and dest_port == tcp_source):
                prev_seq = server_tcp_sequence
                server_tcp_sequence = tcph[2]
                h_size = iph_length + tcph_length * 4
                data_size = len(packet) - h_size
                data = packet[h_size:]
                break

#create a file
try:
    data_size = 0
    data = ''
    f=''
    f=open(file_name,"a")
except:
    sys.exit(0)

#receive packets during data transfer
def recpacket1(payload):
    while True:
        global data_size
        global prev_seq
        global server_tcp_sequence
        global prev_data

        packet = s1.recvfrom(65535)
        packet = packet[0]
        ip_header = packet[0:20]
        iph = unpack('!BBHHHBBH4s4s' , ip_header)
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);
        if(s_addr == dest_ip and d_addr ==  source_ip) :
            tcp_header = packet[iph_length:iph_length+20]
            tcph = unpack('!HHLLBBHHH' , tcp_header)
            source_port = tcph[0]
            dest_port = tcph[1]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4
            rec_flags = tcph[5]  
            rec_flags = str(bin(rec_flags))
            if((source_port == 80) and (dest_port == tcp_source) and (acknowledgement == tcp_seq)):
                server_tcp_sequence = tcph[2]                    
                h_size = iph_length + tcph_length * 4
                data_size = len(packet) - h_size
                global data
                global FIN
                FIN = rec_flags[-1]
                if ((server_tcp_sequence == prev_seq + len(data))):
                    data = packet[h_size:]
                    prev_seq = server_tcp_sequence
                    if (("HTTP/1.1" in data) or ("HTTP/1.0" in data)):
                        if(not ("200 OK" in data)):
                            print "HTTP Status other than 200"
                            sys.exit(0)
                            break
                    global f
                    f.write(data)
                    break
                else:
                    server_tcp_sequence = prev_seq
                    FIN='0'
                    break

#three way handshake to establish connection
def handshake():

    global tcp_seq
    global tcp_ack_seq
    global server_tcp_sequence

    #SYN
    ip_header = ipheader(5,4,0,0,54322,0)
    tcp_header = tcpheader(tcp_seq, tcp_ack_seq, 0, 1, 0, 0, 0, 0,'')
    packet = create_packet (ip_header, tcp_header, '')
    s.sendto(packet, (dest_ip , 0 ))
    tcp_seq+=1
    
    # SYN-ACK
    recpacket()

    # ACK
    ip_header = ipheader(5,4,0,0,54321,0)
    req=''
    tcp_header = tcpheader(tcp_seq, server_tcp_sequence + 1 , 0, 0, 0, 0, 1, 0,req)
    packet = create_packet (ip_header, tcp_header, req)
    s.sendto(packet, (dest_ip , 0 ))

#data transfer
def datatransfer():
    global tcp_seq
    global tcp_ack_seq
    global FIN
    global server_tcp_sequence
    global data
    data = ' '
    # ACK and HTTP-Request
    ip_header = ipheader(5,4,0,0,54321,0)
    #req = "GET / HTTP/1.0\n" + "Host: cs5700f14.ccs.neu.edu\n\n"
    req = "GET " + path + " HTTP/1.0\n" + "Host: "+ host_name +"\n\n"
    tcp_header = tcpheader(tcp_seq, server_tcp_sequence + 1, 0, 0, 0, 0, 1, 0,req)
    packet = create_packet (ip_header, tcp_header, req)
    s.sendto(packet, (dest_ip , 0 ))
    payload = (len(req))
    tcp_seq += payload

    #ACK and HTTP Data
    recpacket()
    recpacket1(payload)
    #ACK for continuing incoming packets
    while FIN=='0':
        ip_header = ipheader(5,4,0,0,54321,0)
        req = ''
        tcp_header = tcpheader(tcp_seq, server_tcp_sequence + len(data) , 0, 0, 0, 0, 1, 0,req)
        packet = create_packet (ip_header, tcp_header, req)
        s.sendto(packet, (dest_ip , 0 ))
        recpacket1(0)
    f.close()

#close the connection
def teardown():

    global tcp_seq
    global tcp_ack_seq
    # FIN-ACK
    ip_header = ipheader(5,4,0,0,54321,0)
    req = ''
    tcp_header = tcpheader(tcp_seq, server_tcp_sequence + len(data) , 1, 0, 0, 0, 1, 0,req)
    packet = create_packet (ip_header, tcp_header, req)
    s.sendto(packet, (dest_ip , 0 ))
    payload = (len(req))
    if (payload == 0):
        payload += 1    
    tcp_seq += payload

    # SERVER-ACK
    recpacket()
    recpacket()

    # CLIENT-ACK
    ip_header = ipheader(5,4,0,0,54321,0)
    req=''
    tcp_header = tcpheader(tcp_seq, server_tcp_sequence + 1 , 0, 0, 0, 0, 1, 0,req)
    packet = create_packet (ip_header, tcp_header, req)
    s.sendto(packet, (dest_ip , 0 ))

try:
    handshake()
    datatransfer()
    teardown()
except:
    sys.exit(0)

#remove header from the file
try:
    download = open(file_name, 'rt').read()
    header, body = download.split('\r\n\r\n',1)
    open(file_name, 'wt').write(body)
except:
    sys.exit(0)
