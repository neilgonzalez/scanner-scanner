#! /usr/bin/env python
from scapy.all import *
import time
import datetime

old_time = datetime.datetime.now()
old_time_udp = datetime.datetime.now()
arp_counter = 0
counter = 0
old_port = 0
udp_count = 0
def arp_monitor_callback(pkt):
	#if an arp packet is found
	global old_time, arp_counter, counter, old_time_udp, old_port, udp_count
	if TCP in pkt and pkt[TCP].sport > 40000:
		if counter > 400:
			print "port scanner found on"
			print pkt.sprintf("%IP.src%")
			print "at: " + time.strftime('%X %x %Z')
			counter = 0
		else:
			counter += 1

	elif ARP in pkt and pkt[ARP].op in (1,2):
		new_time = datetime.datetime.now()
		elapsed = new_time - old_time
		elapsed = elapsed.total_seconds()
		if elapsed > 00.000000 and elapsed < 01.000000:
            		arp_counter = arp_counter + 1
        	elif elapsed > 01.000000:
            		#reset in the event of regular arp traffic
            		arp_counter = 0
        		#check the counter for an arp-scanner
        	if arp_counter >= 200:
               		print "ARP scanner found on:"
                	print pkt.sprintf("%ARP.hwsrc% %ARP.psrc%")
			print 'at: ' + time.strftime('%X %x %Z') 
                	arp_counter=0
        	old_time = new_time

	#UDP can look like regular packet streaming except it checks other dst ports
	#store the previous port and look for a change
	elif UDP in pkt and pkt[UDP].sport > 30000:
		if old_port != pkt[UDP].dport:
			new_time_udp = datetime.datetime.now()
			elapsed_udp = new_time_udp - old_time_udp
			elapsed_udp = elapsed_udp.total_seconds() 
			old_port = pkt[UDP].dport
			if elapsed_udp > 00.000000 and elapsed_udp < 01.000000:
				udp_count += 1
		elif old_port == pkt[UDP].dport or elapsed_udp > 01.000000:
			udp_count = 0
			new_time_udp = datetime.datetime.now()
		if udp_count >= 20:
			print "UDP scanner found on:"
			print pkt.sprintf("%IP.src%")
			print 'at: ' + time.strftime('%X %x %Z')
			udp_count = 0
		old_time_udp = new_time_udp

sniff(prn=arp_monitor_callback, filter="arp, tcp, udp", store=0)
