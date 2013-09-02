#!/usr/bin/env python
#
# Execute with sudo python defendARP.py
#
#
import time
import sys
import socket
import os
#from scapy.all import *
from optparse import OptionParser

def startDefense(ipAddress):
	# Remove given IP Address from local ARP table
	print("INITIALIZING...")
	print("Removing %s from the ARP table.") % (ipAddress)
	os.system("arp -d " + ipAddress)
	print("OK.\n")

	# Ping the IP to establish it's correct MAC address.
	# NOTE: The ARP could still be poisoned if an attacker sends poison packets while we are pinging.
	# Does not surpress output right now.
	print("Obtainting MAC address.")
	os.system("ping -n 1 " + ipAddress)

	



def printHeader():
	print("SUMMARY")
	print("\tDeletes the specified IP from the ARP table, then pings the IP to")
	print("\textablish the correct Physical Address.")
	print("\tThe script will then continually monitor the specified IP's entry in")
	print("\tthe ARP table. If the IP's ARP table ever changes or is removed, the")
	print("\tscript will BEEP and set the Physical Address back to the correct value.")	
	print("AUTHORS")
	print("\tAlan Reed, Sam Cappella")
	print("\tPlease contact the authors with any questions, comments, or concerns.")
	print("\tat al.reed13@gmail.com OR sjcappella@gmail.com")
	print("LICENSE")
	print("\tCopyright 2013. This script is free to use, modify, and redistribute")
	print("\tso long as you give credit to the original author.")
	print("SYNTAX")
	print("\tUse: python defendARP.py -h for help.")
	

def main(argv):
	# Create option parser
	parser = OptionParser()
	# Define options
	parser.add_option("-a", "--address", dest="addressToMon", help="IP address to monitor.")
	parser.add_option('-i', "--info", dest="showInfo", help="Show the copyright and about information.")
	#parser.add_option("-s", "--spoof", dest="spoof", help="Gateway's IP address.")
	#parser.add_option("-m", "--mac", dest="mac", help="Attacker's phyisical address.")
	(options, args) = parser.parse_args()
	

	# Validate arguments
	if options.showInfo == "True" or options.showInfo == "true":
		printHeader()
	if options.addressToMon == None:
		print("No IP address to monitor given. Qutting.")
		sys.exit()
	else:
		for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
			# May want to have a 'starts with' 127. instead of just 127.0.0.1
			if options.addressToMon == ip or options.addressToMon == "127.0.0.1":
				print("Error: Cannot protect your own IP Address -- Try using the Default Gateway or Router's IP Address.")
				sys.exit()
	

	startDefense(options.addressToMon)

	'''
	if options.victim == None:
		print("No victim IP given. Quitting.")
		sys.exit()
	if options.spoof == None:
		print("No gateway IP address given. Quitting.")
		sys.exit()
	if options.mac == None:
		print("No attacker MAC address given. Quitting.")
		'''

	

# Main function called upon script entry
if __name__ == "__main__":
	main(sys.argv)