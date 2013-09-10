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
import logging

# Import scapy while suppressing warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) 
import scapy.all
logging.getLogger("scapy.runtime").setLevel(logging.WARNING)

from optparse import OptionParser
import subprocess

# Main defense function
def startDefense(ipAddress, my_ip, interface):
	# ipAddress = IP to defend.
	# my_ip = IP on the device running the script.
	# interface = Network interface we are defending.

	# Remove given IP Address from local ARP table.
	print("INITIALIZING...")
	ping(ipAddress)
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

def getMyIp(interface):
	# This is ok because we validate the output (check to make sure it is an IP address). But could be used to exfultrate info. 
	p = subprocess.Popen("ifconfig " + interface + " | grep 'inet addr' | awk -F: '{print $2}' | awk '{print $1}'", shell=True, stdout=subprocess.PIPE)
	output = p.communicate()[0].rstrip()

	try:
	    socket.inet_aton(output)
	    return output
	except socket.error:
	    return ''

def getInterface():
	# This is ok because there is not user input. Do NOT trust user input in this function. Use call() instead.
	p = subprocess.Popen("ifconfig  | grep 'Link encap' |  awk  '{print $1}' | head -1", shell=True, stdout=subprocess.PIPE)
	output = p.communicate()[0].rstrip()
	return output

def ping(ip):
	# This is NOT ok. Should not allow user input in Popen function
	p = subprocess.Popen("ping -c 1 " + ip, shell=True, stdout=subprocess.PIPE)

# Print the header information
def printHeader():
	print("SUMMARY")
	print("\tDeletes the specified IP from the ARP table, then pings the IP to")
	print("\textablish the correct Physical Address.")
	print("\tThe script will then continually monitor the specified IP's entry in")
	print("\tthe ARP table. If the IP's ARP table ever changes or is removed, the")
	print("\tscript will BEEP and set the Physical Address back to the correct value.")	
	print("AUTHORS")
	print("\tAlan Reed <alreed13@gmail.com>")
	print("\tSam Cappella <sjcappella@gmail.com>")
	print("\tPlease contact the authors with any questions or questions.")
	print("CONTRIBUTE")
	print("\thttps://github.com/alan-reed/ARP-Defense")
	print("LICENSE")
	print("\tCopyright 2013. Apache license 2.0")
	print("SYNTAX")
	print("\tUse: python defendARP.py -h for help.")
	sys.exit()

# Print basic usage info
def printUsageInfo():
	print("Usage:")
	print("\tpython defendARP.py -a <ip_addr_to_monitor>")
	print("\tpython defendARP.py --address=<ip_addr_to_monitor>")
	print("Help:")
	print("\tpython defendARP.py --help")
	sys.exit()

# Main function
def main(argv):
	# Create option parser
	parser = OptionParser()
	# Define options
	parser.add_option("-a", "--address", dest="ip_addr", help="IP address to monitor.")
	parser.add_option("-f", "--interface", dest="interface",  help="Interface to defend.")
	parser.add_option("-i", "--info", action="store_true", dest="showInfo",  help="Show the copyright and about information.")
	(options, args) = parser.parse_args()
	
	# Validate arguments
	if options.showInfo == True:
		printHeader()
	if options.ip_addr == None:
		printUsageInfo()

	if options.interface == None:
		interface = getInterface()
		my_ip = getMyIp(interface)
	else: 
		my_ip = getMyIp(interface)
	if options.ip_addr == my_ip:
		print("Error: Cannot monitor your own IP Address -- Try using the Default Gateway.\n")
		printUsageInfo()

	#TODO
	# Make sure the IP address is reachable

	# Call main defense logic
	startDefense(options.ip_addr, my_ip, interface)

# Main function
if __name__ == "__main__":
	main(sys.argv)