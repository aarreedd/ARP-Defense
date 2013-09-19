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
import subprocess
from optparse 	import OptionParser

###############################################################
##################### MAIN DEFENSE LOGIC ######################

def startDefense(ipAddress, my_ip, interface):
	'''
	ipAddress = IP to defend.
	my_ip = IP on the device running the script.
	interface = Network interface we are defending.
	'''

	# Remove given IP Address from local ARP table.
	print("\nINITIALIZING...")
	print("Removing %s from the ARP table.") % (ipAddress)
	os.system("arp -d " + ipAddress)
	print("OK.")

	# Ping the IP to establish it's correct MAC address.
	# NOTE: The ARP could still be poisoned if an attacker sends poison packets while we are pinging.

	print("Obtainting MAC address.")

	ping(ipAddress)

	mac = getMAC(ipAddress)

	print("MAC address found: %s") % (mac)

	# Confirm the physical address of target
	valid = False
	while valid != True:
		print("Is %s the correct MAC address for %s (y/n)?") % (mac,ipAddress)
		answer = str(raw_input("> "))
		if answer == "N" or answer == "n":
			print("If this is not the correct MAC then you have already been poisoned.")
			print("You must start this script in a 'safe' state.")
			sys.exit()
		elif answer == "Y" or answer == "y":
			print("OK.\n")
			print("Monitoring your ARP table...\n")
			goodMac = mac
			valid = True

	# Set monitor loop
	monitor = True
	while monitor == True:
		mac = getMAC(ipAddress)

		# Check to make sure our good MAC address matches the one in the ARP table
		if goodMac != mac:
			beep()
			print("ARP POISONED!")
			print("Spoofed IP: %s") % (ipAddress)
			attackersIP = ''
			attackersIP = getAttackerIP(ipAddress, mac)
			print("Attacker is sending your traffic to %s") % (attackersIP)
			print("%s's actual Physical Address: %s") % (ipAddress, goodMac)
			print("Attacker's Physical Address: %s") % (mac)
			print("Attempting to reset the correct Physical Address...")

			deleteMAC(ipAddress)
			
			# Re-ping the target to establish correct MAC
			ping(ipAddress)

			mac = getMAC(ipAddress)

			print("ARP Table reset.")
			print("\nMonitoring your ARP table...\n")

		# Wait for 2 seconds
		time.sleep(2)
		
		
###############################################################
###################### UTILITY FUNCTIONS ######################
		
# Grab the IP address on a specific interface
def getMyIp(interface):
	# This is ok because we validate the output (check to make sure it is an IP address). But could be used to exfultrate info. 
	p = subprocess.Popen("ifconfig " + interface + " | grep 'inet addr' | awk -F: '{print $2}' | awk '{print $1}'", shell=True, stdout=subprocess.PIPE)
	output = p.communicate()[0].rstrip()

	try:
	    socket.inet_aton(output)
	    return output
	except socket.error:
	    return ''

# play beep sound
def beep():
	print("\a")

# Remove a IP/MAC pair from ARP table where IP == $1
def deleteMAC(ipAddress):
	p = subprocess.Popen("arp -d " + ipAddress, shell=True, stdout=subprocess.PIPE)
	output = p.communicate()[0].rstrip()

# Get duplicate IP from ARP table
def getAttackerIP(goodIP, mac):
	command = "arp -a | grep '" + mac + "' | grep -v '(" + goodIP + ")' |  awk  '{print $2}'"
	p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
	output = p.communicate()[0].rstrip()
	output = output.replace('(', '').replace(')', '')
	return output

# Get MAC of IP from ARP Table
def getMAC(ip):	
	p = subprocess.Popen("arp -a | grep  '(" + ip + ")' |  awk  '{print $4}'", shell=True, stdout=subprocess.PIPE)
	output = p.communicate()[0].rstrip()
	return output

# Find the name of the interface we are going to use
def getInterface():
	# This is ok because there is not user input. Do NOT trust user input in this function. Use call() instead.
	p = subprocess.Popen("ifconfig  | grep 'Link encap' |  awk  '{print $1}' | head -1", shell=True, stdout=subprocess.PIPE)
	output = p.communicate()[0].rstrip()
	return output

def ping(ip):
	# return == 1: OK.
	# return == 0: Failed.
	p = subprocess.Popen("ping -c 1 " + ip, shell=True, stdout=subprocess.PIPE)
	output = p.communicate()[0].rstrip()
	if "1 received" in output:
		return 1
	else:
		return 0

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
	
def isUnix():
	if os.name == "posix":
		return 1
	else:
		return 0

def printOsRequirements():
	print("ERROR:");
	print("\tThis script only works on Unix systems.")
	print("\tAn equivalent script for Windows can be found at https://github.com/alan-reed/ARP-Defense/blob/master/defendAPR.bat")
	sys.exit()
		

###############################################################
############################ MAIN #############################

def main(argv):
	
	# Check OS (must be unix)
	if not isUnix():
		printOsRequirements()

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
		print("Error: Cannot monitor your own IP Address -- Try using the Default Gateway's IP.\n")
		printUsageInfo()

	# Make sure the IP address is reachable
	res = ping(options.ip_addr)
	if res == 0:
		print("Address unreachable.");
		sys.exit()
	
	# Call main defense logic
	startDefense(options.ip_addr, my_ip, interface)

if __name__ == "__main__":
	main(sys.argv)