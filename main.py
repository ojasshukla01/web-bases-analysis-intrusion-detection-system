import os
import sys
import socket
import textwrap
import playsound
import pandas


from datetime import datetime
from termcolor import colored
from scapy.utils import PcapWriter

import unpack

from syn_flood_attack_detection import SYN_Flood_Detection
from rules import read_rules


# Just for formating pourpses.
TAB_1 = '\t '
TAB_2 = '\t\t '
TAB_3 = '\t\t\t '
TAB_4 = '\t\t\t\t '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '


############## This code has been made and tasted to work on Linux OS. ###############


# destnation_port : protocol on Linux.
PROTOCOOLS_ON_LINUX = {1: 'tcpmux', 2: 'nbp', 4: 'echo', 6: 'zip', 7: 'echo', 9: 'discard', 11:
'systat', 13: 'daytime', 15: 'netstat', 17: 'qotd', 18: 'msp', 19: 'chargen',
20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 37: 'time', 39:
'rlp', 42: 'nameserver', 43: 'whois', 49: 'tacacs', 50: 're-mail-ck', 53:
'domain', 65: 'tacacs-ds', 67: 'bootps', 68: 'bootpc', 69: 'tftp', 70: 'gopher',
79: 'finger', 80: 'http', 87: 'link', 88: 'kerberos', 95: 'supdup', 98:
'linuxconf', 101: 'hostnames', 102: 'iso-tsap', 104: 'acr-nema', 105: 
'csnet-ns', 106: 'poppassd', 107: 'rtelnet', 110: 'pop3', 111: 'sunrpc', 113: 'auth',
115: 'sftp', 119: 'nntp', 123: 'ntp', 129: 'pwdgen', 135: 'loc-srv', 137:
'netbios-ns', 138: 'netbios-dgm', 139: 'netbios-ssn', 143: 'imap2', 161: 'snmp',
162: 'snmp-trap', 163: 'cmip-man', 164: 'cmip-agent', 174: 'mailq', 177:
'xdmcp', 178: 'nextstep', 179: 'bgp', 194: 'irc', 199: 'smux', 201: 'at-rtmp',
202: 'at-nbp', 204: 'at-echo', 206: 'at-zis', 209: 'qmtp', 210: 'z3950', 213:
'ipx', 345: 'pawserv', 346: 'zserv', 347: 'fatserv', 369: 'rpc2portmap', 370:
'codaauth2', 371: 'clearcase', 372: 'ulistserv', 389: 'ldap', 406: 'imsp', 427:
'svrloc', 443: 'https', 444: 'snpp', 445: 'microsoft-ds', 464: 'kpasswd', 465:
'urd', 487: 'saft', 500: 'isakmp', 512: 'exec', 513: 'login', 514: 'shell', 515:
'printer', 517: 'talk', 518: 'ntalk', 520: 'route', 525: 'timed', 526: 'tempo',
530: 'courier', 531: 'conference', 532: 'netnews', 533: 'netwall', 538:
'gdomap', 540: 'uucp', 543: 'klogin', 544: 'kshell', 546: 'dhcpv6-client', 547:
'dhcpv6-server', 548: 'afpovertcp', 549: 'idfp', 554: 'rtsp', 556: 'remotefs',
563: 'nntps', 587: 'submission', 607: 'nqs', 610: 'npmp-local', 611: 'npmp-gui',
612: 'hmmp-ind', 623: 'asf-rmcp', 628: 'qmqp', 631: 'ipp', 636: 'ldaps', 655:
'tinc', 706: 'silc', 749: 'kerberos-adm', 750: 'kerberos4', 751: 
'kerberos-master', 752: 'passwd-server', 754: 'krb-prop', 760: 'krbupdate', 765:
'webster', 775: 'moira-db', 777: 'moira-update', 779: 'moira-ureg', 783:
'spamd', 808: 'omirr', 871: 'supfilesrv', 873: 'rsync', 901: 'swat', 989: 
'ftps-data', 990: 'ftps', 992: 'telnets', 993: 'imaps', 995: 'pop3s', 1001: 'customs',
1080: 'socks', 1093: 'proofd', 1094: 'rootd', 1099: 'rmiregistry', 1109: 'kpop',
1127: 'supfiledbg', 1178: 'skkserv', 1194: 'openvpn', 1210: 'predict', 1214:
'kazaa', 1236: 'rmtcfg', 1241: 'nessus', 1300: 'wipld', 1313: 'xtel', 1314:
'xtelw', 1352: 'lotusnote', 1433: 'ms-sql-s', 1434: 'ms-sql-m', 1524:
'ingreslock', 1529: 'support', 1645: 'datametrics', 1646: 'sa-msg-port', 1649:
'kermit', 1677: 'groupwise', 1701: 'l2f', 1812: 'radius', 1813: 'radius-acct',
1863: 'msnp', 1957: 'unix-status', 1958: 'log-server', 1959: 'remoteping', 2000:
'cisco-sccp', 2003: 'cfinger', 2010: 'search', 2049: 'nfs', 2053: 'knetd', 2086:
'gnunet', 2101: 'rtcm-sc104', 2102: 'zephyr-srv', 2103: 'zephyr-clt', 2104:
'zephyr-hm', 2105: 'eklogin', 2111: 'kx', 2119: 'gsigatekeeper', 2121: 'iprop',
2135: 'gris', 2150: 'ninstall', 2401: 'cvspserver', 2430: 'venus', 2431: 
'venus-se', 2432: 'codasrv', 2433: 'codasrv-se', 2583: 'mon', 2600: 'zebrasrv', 2601:
'zebra', 2602: 'ripd', 2603: 'ripngd', 2604: 'ospfd', 2605: 'bgpd', 2606:
'ospf6d', 2607: 'ospfapi', 2608: 'isisd', 2628: 'dict', 2792: 'f5-globalsite',
2811: 'gsiftp', 2947: 'gpsd', 2988: 'afbackup', 2989: 'afmbackup', 3050: 'gds-db',
3130: 'icpv2', 3205: 'isns', 3260: 'iscsi-target', 3306: 'mysql', 3493:
'nut', 3632: 'distcc', 3689: 'daap', 3690: 'svn', 4031: 'suucp', 4094: 'sysrqd',
4190: 'sieve', 4224: 'xtell', 4353: 'f5-iquery', 4369: 'epmd', 4373: 'remctl',
4500: 'ipsec-nat-t', 4557: 'fax', 4559: 'hylafax', 4569: 'iax', 4600: 'distmp3',
4691: 'mtn', 4899: 'radmin-port', 4949: 'munin', 5002: 'rfe', 5050: 'mmcc',
5051: 'enbd-cstatd', 5052: 'enbd-sstatd', 5060: 'sip', 5061: 'sip-tls', 5151:
'pcrd', 5190: 'aol', 5222: 'xmpp-client', 5269: 'xmpp-server', 5308: 'cfengine',
5353: 'mdns', 5354: 'noclog', 5355: 'hostmon', 5432: 'postgresql', 5555:
'rplay', 5556: 'freeciv', 5666: 'nrpe', 5667: 'nsca', 5671: 'amqps', 5672:
'amqp', 5674: 'mrtd', 5675: 'bgpsim', 5680: 'canna', 5688: 'ggz', 6000: 'x11',
6001: 'x11-1', 6002: 'x11-2', 6003: 'x11-3', 6004: 'x11-4', 6005: 'x11-5', 6006:
'x11-6', 6007: 'x11-7', 6346: 'gnutella-svc', 6347: 'gnutella-rtr', 6444: 'sge-qmaster',
6445: 'sge-execd', 6446: 'mysql-proxy', 6514: 'syslog-tls', 6566:
'sane-port', 6667: 'ircd', 6696: 'babel', 6697: 'ircs-u', 7000:
'afs3-fileserver', 7001: 'afs3-callback', 7002: 'afs3-prserver', 7003:
'afs3-vlserver', 7004: 'afs3-kaserver', 7005: 'afs3-volser', 7006:
'afs3-errors', 7007: 'afs3-bos', 7008: 'afs3-update', 7009: 'afs3-rmtsys', 7100:
'font-service', 8021: 'zope-ftp', 8080: 'http-alt', 8081: 'tproxy', 8088:
'omniorb', 8140: 'puppet', 8990: 'clc-build-daemon', 9098: 'xinetd', 9101:
'bacula-dir', 9102: 'bacula-fd', 9103: 'bacula-sd', 9359: 'mandelspawn', 9418:
'git', 9667: 'xmms2', 9673: 'zope', 10000: 'webmin', 10050: 'zabbix-agent',
10051: 'zabbix-trapper', 10080: 'amanda', 10081: 'kamanda', 10082: 'amandaidx',
10083: 'amidxtape', 10809: 'nbd', 11112: 'dicom', 11201: 'smsqp', 11371: 'hkp',
13720: 'bprd', 13721: 'bpdbm', 13722: 'bpjava-msvc', 13724: 'vnetd', 13782:
'bpcd', 13783: 'vopied', 15345: 'xpilot', 17001: 'sgi-cmsd', 17002: 'sgi-crsd',
17003: 'sgi-gcd', 17004: 'sgi-cad', 17500: 'db-lsp', 20011: 'isdnlog', 20012:
'vboxd', 22125: 'dcap', 22128: 'gsidcap', 22273: 'wnn6', 24554: 'binkp', 27374:
'asp', 30865: 'csync2', 57000: 'dircproxy', 60177: 'tfido', 60179: 'fido'}




class Sniffer:
    def __init__(self,SYN_packets_limit):
        print("You can stop the IDS by clickiing Ctrl+C")

        connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        syn_flood_detaction_rule = SYN_Flood_Detection(SYN_packets_limit)
        
        all_TCP_rules = read_rules().all_TCP_rules
        all_UDP_rules = read_rules().all_UDP_rules
        all_ICMP_rules = read_rules().all_ICMP_rules

        print(f'\n{len(all_TCP_rules) + len(all_UDP_rules) + len(all_ICMP_rules)} rules installed TCP: {len(all_TCP_rules)} UDP: {len(all_UDP_rules)} ICMP: {len(all_ICMP_rules)}.\n')

        while True:
            # recvfrom function takes buffer size as an argument and here we are using the maimum buffer size.
            raw_data, addresses = connection.recvfrom(65536)
            pktdump = PcapWriter(str(datetime.now().date())+ ' ' + str(datetime.today().hour) + '.pcap', append=True, sync=True)
            pktdump.write(raw_data)

            dest_mac, src_mac, eth_protocol, data = unpack.ethernet_frame(data=raw_data)
            print ('\nEthernet Frame:')
            print(TAB_1 + 'Destination: {}, Source: {}, protocolcol: {}'.format(dest_mac, src_mac, eth_protocol))

            # 8 for IPv4
            if eth_protocol == 8:
                (version, header_length, ttl, protocol, source_ip, destnation_ip, data) = unpack.ipv4_packet(data)
                print(TAB_1 + 'IPv4 Packet:')
                print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
                print(TAB_2 + 'protocolcol: {}, Source: {}, Target: {}'.format(protocol, source_ip, destnation_ip))

                # ICMP
                if protocol == 1:
                    icmp_type, code, checksum, data = unpack.unpack_icmp_packet(data)
                    print(TAB_1 + 'ICMP Packet:')
                    print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                    print(TAB_2 + 'Data:')
                    print(self.format_multi_line(DATA_TAB_3, data))

                    # We will start recording the packet in a diffrent CPU Thread so we don't slow down and effact the sniffing process.
                    self.statistics(
                                    source_ip,
                                    destnation_ip,
                                    None,
                                    "ICMP"
                                )

                    for rule in all_ICMP_rules:
                        if source_ip == rule.source_IP or 'any' == rule.source_IP and destnation_ip == rule.destnation_IP or 'any' == rule.destnation_IP and rule.protocol == 'ICMP':
                               if rule.rule_category == 'alert':
                                   print(colored('Alert, ' + rule.message,'yellow'))
                               elif rule.rule_category == 'warning':
                                   print(colored(f'''----------------------------------------
Warning, {rule.message} 
----------------------------------------

''','red'))
                                   try:
                                       playsound.playsound('warning_sound.mp3')
                                   except playsound.PlaysoundException:
                                       pass

                                   input('Press any key to continue: ')
                                   continue
               
                # TCP
                elif protocol == 6:
                    (source_port, destnation_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = unpack.unpack_TCP_segment(data)
                    
                    try:
                        used_protocol = PROTOCOOLS_ON_LINUX[destnation_port]
                    except KeyError:
                        used_protocol = ''
                    
                    print(TAB_1 + 'TCP Segment:')
                    print(TAB_2 + 'Source Port: {}, Destination Port: {} ({})'.format(source_port, destnation_port, used_protocol))
                    print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
                    print(TAB_2 + 'Flags:')
                    print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN:{}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                    print(TAB_2 + 'Data:')
                    print(self.format_multi_line(DATA_TAB_3, data))

                    self.statistics(
                                    source_ip,
                                    destnation_ip,
                                    None,
                                    "ICMP"
                                )            

                    for rule in all_TCP_rules:
                
                        if source_ip == rule.source_IP or 'any' == rule.source_IP and destnation_ip == rule.destnation_IP or 'any' == rule.destnation_IP and rule.protocol == 'TCP':
                            if rule.source_port == source_port or rule.source_port =='any' and rule.destnation_port == destnation_port or rule.destnation_port =='any':

                               if rule.rule_category == 'alert':
                                   print(colored('\n\nAlert, ' + rule.message +'\n\n','yellow'))
                               elif rule.rule_category == 'warning':
                                   print(colored(f'''----------------------------------------
Warning, {rule.message} 
----------------------------------------

''','red'))
                                   try:
                                       playsound.playsound('warning_sound.mp3')
                                   except playsound.PlaysoundException:
                                       pass

                                   input('Press any key to continue: ')
                                   continue

                    # SYN-flood detaction.
                    if flag_urg == 0 and flag_ack == 0 and flag_psh == 0 and flag_rst == 0 and flag_syn == 1 and flag_fin == 0:
                        syn_flood_detaction_rule.ack_packets_counter += 1
                        if syn_flood_detaction_rule.ack_flood_attack_detected():
                            print(colored('''---------------------------------------------
Attack detected.
syn flood attack has been detected.
---------------------------------------------''','red'))
                            try:
                                playsound.playsound('warning_sound.mp3')
                            except playsound.PlaysoundException:
                                pass 
                            syn_flood_detaction_rule.reset_counter()
                            input() # To Stop the sniffer
                            continue
                        if flag_ack == 1 and flag_syn == 0: # If a full conecation established.
                            syn_flood_detaction_rule.reset_counter()
                   
                    if flag_urg == 1 and flag_ack == 0 and flag_psh == 1 and flag_rst == 0 and flag_syn == 0 and flag_fin == 1:
                        # TCP Xmas Scan attack detecation.
                        print(colored('''---------------------------------------------
Attack detected.
TCP Xmas Scan attack has been detected.
---------------------------------------------''','red'))
                        try:
                            playsound.playsound('warning_sound.mp3')
                        except playsound.PlaysoundException:
                            pass 
                        syn_flood_detaction_rule.reset_counter()
                        input() # To Stop the sniffer
                        continue
                    if flag_urg == 0 and flag_ack == 0 and flag_psh == 0 and flag_rst == 0 and flag_syn == 0 and flag_fin == 0:
                        # TCP Null Scan attack detecation.
                        print(colored('''---------------------------------------------
Attack detected.
TCP Null Scan attack has been detected.
---------------------------------------------''','red'))
                        try:
                            playsound.playsound('warning_sound.mp3')
                        except playsound.PlaysoundException:
                            pass 
                        syn_flood_detaction_rule.reset_counter()
                        input() # To Stop the sniffer
                        continue
                # UDP
                elif protocol == 17:
                    source_port, destnation_port, length, data = unpack.unpack_UDP_segment(data)
                    try:
                        used_protocol = PROTOCOOLS_ON_LINUX[destnation_port]
                    except KeyError:
                        used_protocol = ''
                    print(TAB_1 + 'UDP Segment:')
                    print(TAB_2 + 'Source Port: {}, Destination Port: {} ({}), Length: {}'.format(source_port, destnation_port, used_protocol, length))
  
                    self.statistics(
                                    source_ip,
                                    destnation_ip,
                                    None,
                                    "ICMP"
                                )

                    for rule in all_UDP_rules:
                        if source_ip == rule.source_IP or 'any' == rule.source_IP and destnation_ip == rule.destnation_IP or 'any' == rule.destnation_IP and rule.protocol == 'UDP':
                            if rule.source_port == source_port or rule.source_port =='any' and rule.destnation_port == destnation_port or rule.destnation_port =='any':
                               if rule.rule_category == 'alert':
                                   print(colored('Alert, ' + rule.message +'\n\n','yellow'))
                               elif rule.rule_category == 'warning':
                                   print(colored(f'''----------------------------------------
Warning, {rule.message} 
----------------------------------------

''','red'))
                                   try:
                                       playsound.playsound('warning_sound.mp3')
                                   except playsound.PlaysoundException:
                                       pass

                                   input('Press any key to continue: ')
                                   continue
                # Other
                else:
                    print(TAB_1 + 'Data:')
                    print(TAB_2 + self.format_multi_line(DATA_TAB_2, data))

            else:
                print('Data:')
                print(self.format_multi_line(DATA_TAB_1, data))




    # Formats multi-line data (Just for formating pourpses)
    def format_multi_line(self,prefix, string, size=80):
        size -= len(prefix)
        if isinstance(string, bytes):
            string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
            if size % 2:
                size -= 1
        return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

    def statistics(self,source_ip,destnation_ip,destnation_port,protocol):
        # Tops source IPs statistics.
        top_source_IPs_file = pandas.read_csv('statistics/top_source_IPs.csv')
        
        if source_ip not in list(top_source_IPs_file.IP): # If this is a new IP that we have no recrdes for.
            new_ip = pandas.DataFrame({
                'IP' : source_ip,
                'packets' : [1]
            })
            new_ip.to_csv('statistics/top_source_IPs.csv', mode='a', index=False,header=False)

        else: # If we have this IP , we will find its place and add a packet to its total packets number.
            for ip in range(len(top_source_IPs_file)): # len function with pandas DataFrame returns how many rows.
                if top_source_IPs_file.iloc[ip,0] == source_ip: # iloc fuction takes row and colum's number as arguments. 
                    top_source_IPs_file.iloc[ip,1] = int(top_source_IPs_file.iloc[ip,1]) + 1  # Add 1 to the IP's recived packets.


            top_source_IPs_file.to_csv('statistics/top_source_IPs.csv',index=False)

        # Top destnation IPs statistics.
        top_destnation_IPs_file = pandas.read_csv('statistics/top_destnation_IPs.csv')
        
        if destnation_ip not in list(top_destnation_IPs_file.IP): # If this is a new IP that we have no recrdes for.
            new_ip = pandas.DataFrame({
                'IP' : destnation_ip,
                'packets' : [1]
            })
            new_ip.to_csv('statistics/top_destnation_IPs.csv', mode='a', index=False,header=False)

        else: # If we have this IP , we will find its place and add a packet to its total packets number.
            for ip in range(len(top_destnation_IPs_file)): # len function with pandas DataFrame returns how many rows.
                if top_destnation_IPs_file.iloc[ip,0] == destnation_ip: # iloc fuction takes row and colum's number as arguments. 
                    top_destnation_IPs_file.iloc[ip,1] = int(top_destnation_IPs_file.iloc[ip,1])  + 1 # Add 1 to the IP's recived packets.
                    
            top_destnation_IPs_file.to_csv('statistics/top_destnation_IPs.csv',index=False)


        # Top destnation ports statistics.
        if destnation_port == None:
            pass
        else:
            top_destnation_ports_file = pandas.read_csv('statistics/top_destnation_ports.csv')
            
            if destnation_port not in list(top_destnation_ports_file.Port): # If this is a new IP that we have no recrdes for.
                new_ip = pandas.DataFrame({
                    'Port' : destnation_port,
                    'packets' : [1]
                })
                new_ip.to_csv('statistics/top_destnation_ports.csv', mode='a', index=False,header=False)

            for port in range(len(top_destnation_ports_file)): # len function with pandas DataFrame returns how many rows.
                if top_destnation_ports_file.iloc[port,0] == f'{destnation_port}': # iloc fuction takes row and colum's number as arguments. 
                    top_destnation_ports_file.iloc[port,1] = int(top_destnation_ports_file.iloc[port,1]) + 1 # Add 1 to the port's recived packets.

                top_destnation_ports_file.to_csv('statistics/top_destnation_ports.csv',index=False)

        # Top protocols.
        top_protocols_file = pandas.read_csv('statistics/top_protocols.csv')
        
        if protocol not in list(top_protocols_file.Protocol): # If this is a new IP that we have no recrdes for.
            new_ip = pandas.DataFrame({
                'Protocol' : protocol,
                'packets' : [1]
            })
            new_ip.to_csv('statistics/top_protocols.csv', mode='a', index=False,header=False)

        for find_protocol in range(len(top_protocols_file)): # len function with pandas DataFrame returns how many rows.
            if top_protocols_file.iloc[find_protocol,0] == protocol: # iloc fuction takes row and colum's number as arguments. 
                top_protocols_file.iloc[find_protocol,1] = int(top_protocols_file.iloc[find_protocol,1]) +  1 # Add 1 to the portocol's recived packets.

            top_protocols_file.to_csv('statistics/top_protocols.csv',index=False)



if __name__ == '__main__':
    # check if there is any missing file and if there is ,it will create it.
    if not os.path.exists(r'statistics'):
        os.makedirs(r'statistics')

    ## top_source_IPs.csv file.
    try:
        with open('statistics/top_source_IPs.csv','r'):
            pass
    except FileNotFoundError:
        new_top_source_IPs_file = pandas.DataFrame({'IP':[],'packets':[]})
        new_top_source_IPs_file.to_csv(path_or_buf='statistics/top_source_IPs.csv',index=False)

    ## top_destnation_IPs.csv file.
    try:
        with open('statistics/top_destnation_IPs.csv','r'):
            pass
    except FileNotFoundError:
        new_top_destnation_IPs_file = pandas.DataFrame({'IP':[],'packets':[]})
        new_top_destnation_IPs_file.to_csv(path_or_buf='statistics/top_destnation_IPs.csv',index=False)


    ## top_destnation_ports.csv file.
    try:
        with open('statistics/top_destnation_ports.csv','r'):
            pass
    except FileNotFoundError:
        new_top_destnation_ports_file = pandas.DataFrame({'Port':[],'packets':[]})
        new_top_destnation_ports_file.to_csv(path_or_buf='statistics/top_destnation_ports.csv',index=False)


    ## top_protocols.csv file.
    try:
        with open('statistics/top_protocols.csv','r'):
            pass
    except FileNotFoundError:
        new_top_protocols_file = pandas.DataFrame({'Protocol':[],'packets':[]})
        new_top_protocols_file.to_csv(path_or_buf='statistics/top_protocols.csv',index=False)



    try:
        SYN_packets_limit =  int(sys.argv[1])
    except (IndexError,ValueError):
        print('Select SYN packets limit parameter as follows: >> sudo main.py 25')
        exit()

    start_sniffing = Sniffer(SYN_packets_limit=SYN_packets_limit)