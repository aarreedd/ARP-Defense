#!/usr/bin/env python
#
# Execute with sudo python defendARP.py
#
#
import time
import sys
import socket
import os
import re
import time
from scapy.all import *
from optparse import OptionParser
from subprocess import Popen, PIPE

# Main defense function
def startDefense(ipAddress):
	# Remove given IP Address from local ARP table
	print("INITIALIZING...")
	print("Removing %s from the ARP table.") % (ipAddress)
	os.system("arp -d " + ipAddress)
	print("OK.\n")

	# Ping the IP to establish it's correct MAC address.
	# NOTE: The ARP could still be poisoned if an attacker sends poison packets while we are pinging.
	print("Obtainting MAC address.")
	e = Ether()
	i = IP()
	i.dst = ipAddress
	packet = e/i/ICMP()
	
	targetMac = packet[Ether].dst
	print("MAC address found: %s") % (targetMac)

	# Find the specified IP in the ARP table
	print("Gathering IP address from ARP table.")
	process = Popen(['arp', '-a'], stdout=PIPE)
	#stdout, stderr = process.communicate()
	for line in iter(process.stdout.readline, ''):
		#print(line.rstrip())
		tokens = line.split()
		#print(tokens)
		for index in range(len(tokens)):
			if targetMac == tokens[index]:
				print("Found MAC address in ARP table for target IP address.")
				# Save IP address and MAC address get rid of surrounding '()'s
				tempAddr = tokens[1][1:-1]
				tempMac = tokens[3]
				tempLine = tokens
	
	# Confirm the physical address of target
	print("Is %s the correct MAC address for %s (Y/N)?") % (tempMac, ipAddress)
	valid = False
	while valid != True:
		answer = str(raw_input("> "))
		print(answer)
		if answer == "N" or answer == "n":
			print("If this is not the correct MAC then you have already been poisoned")
			print("You must start this script in a 'safe' state.")
			sys.exit()
		elif answer == "Y" or answer == "y":
			print("OK.\n")
			print("Monitoring your ARP table...\n")
			goodMac = tempMac
			valid = True
		else:
			print("Invalid Answer. Try again.")

	# Set monitor loop
	monitor = True
	while monitor == True:
		process = Popen(['arp', '-a'], stdout=PIPE)
		#stdout, stderr = process.communicate()
		for line in iter(process.stdout.readline, ''):
			#print(line.rstrip())
			tokens = line.split()
			#print(tokens)
			for index in range(len(tokens)):
				if targetMac == tokens[index]:
					# Save IP address and MAC address get rid of surrounding '()'s
					tempAddr = tokens[1][1:-1]
					tempMac = tokens[3]
					tempLine = tokens

		# Check to make sure our good MAC address matches the one in the ARP table
		if goodMac != tempMac:
			# Implement some BEEP sound here for cross platform
			print("ARP POISONED!")
			print("Spoofed IP: %s") % (tempAddr)
			print("%s actual Physical Address: %s") % (goodMac)
			print("Attacker's Physical Address: %s") % (tempMac)
			print("Attempting to reset the correct Physical Address...")

			# Attempt to reset the ARP table. This will not work if we are continually being poisoned
			process = Popen(['arp', '-d', tempAddr], stdout=PIPE)
			# Re-ping the target
			e = Ether()
			i = IP()
			i.dst = ipAddress
			packet = e/i/ICMP()
			print("ARP Table reset.")
			print("Monitoring your ARP table...")

		# Wait for 5 seconds
		time.sleep(5)

# Print the header information
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
	

# Main function
def main(argv):
	# Create option parser
	parser = OptionParser()
	# Define options
	parser.add_option("-a", "--address", dest="addressToMon", help="IP address to monitor.")
	parser.add_option("-i", action="store_true", dest="showInfo")
	parser.add_option("--info", action="store_true", dest="showInfo", help="Show the copyright and about information.")
	(options, args) = parser.parse_args()
	

	# Validate arguments
	if options.showInfo == True:
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
	
	# Report Errors in the command line options
	# TODO

	# Call the main defense logic
	startDefense(options.addressToMon)

		
# Main function called upon script entry
if __name__ == "__main__":
	main(sys.argv)