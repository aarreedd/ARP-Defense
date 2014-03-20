# ARP-Defense

##SUMMARY:

This repository containts ARP Defense Scripts that can be run on a single device to protect against ARP Poisoning Attacks and to identify which device on the network is executing the attack. 

DefendARP.py for Unix
DefendARP.bat for Windows


##HOW IT WORKS:

Initialize script before you have been ARP poisoned and confrim the remote host's IP and MAC. The script then monitors your machine's ARP table. If the MAC address you are monitoring changes (indicating ARP Poisoning), the script will reset the MAC Address and identify the source of the attack.


##LICENSE:

Copyright 2013. Apache License 2.0.


##AUTHORS:

Alan Reed

Jon Weber

Sam Cappella


##CONTACT THE AUTHOR:

Please feel free to contact the authors with any questions or comments. alan.william.reed at gmail OR sjcappella at gmail.
