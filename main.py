import subprocess, sys, os, re, requests

print(r"""
							    	      ____        _         _                       _         _____     _                            
						  	  	     / ___| _   _| |__   __| | ___  _ __ ___   __ _(_)_ __   |_   _|_ _| | _____  _____   _____ _ __ 
								     \___ \| | | | '_ \ / _` |/ _ \| '_ ` _ \ / _` | | '_ \    | |/ _` | |/ / _ \/ _ \ \ / / _ \ '__|
								      ___) | |_| | |_) | (_| | (_) | | | | | | (_| | | | | |   | | (_| |   <  __/ (_) \ V /  __/ |   
								     |____/ \__,_|_.__/ \__,_|\___/|_| |_| |_|\__,_|_|_| |_|   |_|\__,_|_|\_\___|\___/ \_/ \___|_|   
                                                                                                
		                                                                                         _____           _ 
													|_   _|__   ___ | |
													  | |/ _ \ / _ \| |
													  | | (_) | (_) | |
													  |_|\___/ \___/|_|

	""")


while True:

	try:
		print("\t\t\t\t\t\t\t\t 0. Find Domain + Subdomain + Filter Live Subdomain + Check Service + Vulnerable Subdomain [All-in-One]")
		print("\t\t\t\t\t\t\t\t 1. Find Domain [Fetch the domains from hackerone program]")
		print("\t\t\t\t\t\t\t\t 2. Find Subdomain [Enumerate the domains to find subdomain]")
		print("\t\t\t\t\t\t\t\t 3. Filter Live Subdomain [Filter out live subdomain from list of subdomain]")
		print("\t\t\t\t\t\t\t\t 4. Find Service [Check which subdomain points to which service]")
		print("\t\t\t\t\t\t\t\t 5. Find Vulnerability [Check for HTTP 404 status code]")
		
		select = str(input("\n\t\t\t\t\t\t\t\t\t\tEnter Index Number (Default is 0): "))
		
		if select == "0":
			break
		elif select == "1":
			break
		elif select == "2":
			break
		elif select == "3":
			break
		elif select == "4":
			break
		elif select == "5":
			break
		elif select == "":
			break
		else:
			print("\n\t\t\t\t\t\t\t\t\t     [-] Wrong Index Number select. Try again...\n")
	
	except KeyboardInterrupt:
		print("\n\n[*] User Requested An Interrupt")
		print("[*] Apllication Shutting Down")
		sys.exit(1)


subdomain_dir = "scans/subdomain/"
github_serices_dir = "scans/services/github/"
github_regex = r"[a-z0-9\.\-]{0,70}\.?github\.io\."
	
def find_domain():

	if (os.path.isdir("scans/")):
		pass
	else:
		subprocess.run(["mkdir", "scans/"])
		
	try:
		subprocess.run(["python3", "hackerone.py"])
		
		print("[+] Domains File are stored at " + os.getcwd() + "/scans/domains.txt")
	
	except KeyboardInterrupt:
		print("\n\n[*] User Requested An Interrupt")
		print("[*] Apllication Shutting Down")
		sys.exit(1)
	

def find_subdomain(file_path):
	
	# Find Subdomain

	try:
	
		if (os.path.isdir(subdomain_dir)):
			pass
		else:
			subprocess.run(["mkdir", subdomain_dir])

		with open(file_path) as auto_scan_fp:
			
			line = auto_scan_fp.readline()
			
			while line:
			
				domain_name = line.strip()
			
				print("=" * 150)
				print("Scanning: {}".format(domain_name))
				print("=" * 150)
				
				if (os.path.isdir(subdomain_dir + domain_name)):
					pass
				else:
					subprocess.run(["mkdir", subdomain_dir + domain_name])
				
				list_files = subprocess.run(["amass", "enum", "-active", "-d", domain_name, "-o", subdomain_dir + domain_name + "/" + domain_name])
				
				if (os.stat(subdomain_dir + domain_name + "/" + domain_name).st_size == 0):
				
					subprocess.run(["rm", "-r", subdomain_dir + domain_name])
					
					with open("scans/subdomain/manual_scan", 'w') as manual_scan_fp:
						manual_scan_fp.write(domain_name + "\n")
				
				line = auto_scan_fp.readline()

		print("\n[+] Subdomains are stored at " + os.getcwd() + subdomain_dir)
	
	except KeyboardInterrupt:
		print("\n\n[*] User Requested An Interrupt")
		print("[*] Apllication Shutting Down")
		sys.exit(1)

def filter_live_subdomain():
	
	# Scan for live subdomain

	try:
		for dirname in os.listdir(subdomain_dir):

			subdomain_file = subdomain_dir + dirname + "/" + dirname
			
			with open(subdomain_file) as live_subdomain_scan_fp:
			
				line = live_subdomain_scan_fp.readline()
				
				while line:
					
					subdomain_name = line.strip()
					
					print("=" * 150)
					print("Scanning: {} -> {}".format(dirname, subdomain_name))
					print("=" * 150)
					
					live_dir = subdomain_dir + dirname + "/live"
					
					if (os.path.isdir(live_dir)):
						pass
					else:
						subprocess.run(["mkdir", live_dir])
					
					live_subdomain = subdomain_dir + dirname + "/live/" + subdomain_name

					host_command = subprocess.run(['host', subdomain_name], encoding='utf-8', stdout=subprocess.PIPE)
					
					host_command_stdout = ""
					
					for host_command_line in host_command.stdout.split('\n'):
						host_command_stdout = host_command_stdout + host_command_line + "\n"
					
					print(host_command_stdout)
					
					if "not found" in host_command_stdout:
						pass
					else:
						with open(live_subdomain, 'w') as live_subdomain_fp:
							live_subdomain_fp.write(host_command_stdout)
					
					line = live_subdomain_scan_fp.readline()
			
		print("\n[+] Live Subdomains are stored at " + os.getcwd() + subdomain_dir + "[domain_name]/" + "live")
	
	except KeyboardInterrupt:
		print("\n\n[*] User Requested An Interrupt")
		print("[*] Apllication Shutting Down")
		sys.exit(1)

def check_service():

	#Check Github services			

	github_serices_dir = "scans/services/github/"

	try:
		
		if (os.path.isdir("scans/services")):
			if (os.path.isdir(github_serices_dir)):
				pass
			else:
				subprocess.run(["mkdir", github_serices_dir])		
		else:
			subprocess.run(["mkdir", "scans/services"])

		for dirname in os.listdir(subdomain_dir):

			subdomain_file = subdomain_dir + dirname + "/live"
			
			github_serices_dir = github_serices_dir + dirname + "/"
			
			for live_subdomain_file in os.listdir(subdomain_file):
			
				service_stdout = ""
			
				#print("=" * 150)
				print("Checking for Services: {} -> {}".format(dirname, live_subdomain_file))
				#print("=" * 150)
			
				with open(subdomain_file + "/" + live_subdomain_file) as service_scan_fp:
				
					line = service_scan_fp.readline()
					
					while line: 
					
						service_stdout = service_stdout + line		
						line = service_scan_fp.readline()	
					
				canoncial_domain = re.search(github_regex, service_stdout)
				
				if (canoncial_domain):
					canoncial_domain_final = canoncial_domain.group()[:-1]
					#print(canoncial_domain_final)
					
					print("=" * 150)
					print("[+] Found Github Service: {} -> {}".format(dirname, live_subdomain_file))
					print("=" * 150)
					
					if (os.path.isdir(github_serices_dir)):
						pass
					else:
						subprocess.run(["mkdir", github_serices_dir])
					
					github_serices_dir_final = github_serices_dir + live_subdomain_file
					
					with open(github_serices_dir_final, 'w') as github_service_fp:
						github_service_fp.write(service_stdout)
			
			github_serices_dir = "scans/services/github/"

		print("\n[+] Subdomain services are stored at " + os.getcwd() + "scans/services")
	
	except KeyboardInterrupt:
		print("\n\n[*] User Requested An Interrupt")
		print("[*] Apllication Shutting Down")
		sys.exit(1)

def find_404():

	#Find 404 on services
	
	try:

		github_vuln_service = "scans/vuln_services/github/"

		github_404 = github_vuln_service + "404/"

		if (os.path.isdir("scans/vuln_services")):
			if (os.path.isdir(github_vuln_service)):
				if (os.path.isdir(github_404)):
					pass
				else:
					subprocess.run(["mkdir", github_404])	
			else:
				subprocess.run(["mkdir", github_vuln_service])
		else:
			subprocess.run(["mkdir", "scans/vuln_services"])

		print("*" * 150)
		print("\t\t\t\tFinding Vulnerability")
		print("*" * 150 + "\n")

		for github_serice_domain_dir in os.listdir(github_serices_dir):
			
			github_vuln_service_domain = github_serices_dir + github_serice_domain_dir
			
			for github_serice_subdomain in os.listdir(github_vuln_service_domain):
			
				vuln_subdomain_finder = ""
				
				#print(github_vuln_service_domain + "/" + github_serice_subdomain)
			
				with open(github_vuln_service_domain + "/" + github_serice_subdomain) as github_service_vuln_scan_fp:
					
					line = github_service_vuln_scan_fp.readline()
						
					while line: 
						
						vuln_subdomain_finder = vuln_subdomain_finder + line		
						line = github_service_vuln_scan_fp.readline()	
						
				#print(vuln_subdomain_finder)
				
				canoncial_domain = re.search(github_regex, vuln_subdomain_finder)
				
				if (canoncial_domain):
					canoncial_domain_final = canoncial_domain.group()[:-1]
					#(canoncial_domain_final)
					
					check_vuln = "http://" + github_serice_subdomain
					
					#print(check_vuln)
					
					subdomain_statuscode = requests.head(check_vuln)
					
					if subdomain_statuscode.status_code == 404:
						#print(subdomain_statuscode.status_code)
					
						#print(github_serice_domain_dir)
					
						if (os.path.isdir(github_404 + github_serice_domain_dir)):
							pass
						else:
							subprocess.run(["mkdir", github_404 + github_serice_domain_dir])
						
						github_vuln_serices_dir_final = github_404 + github_serice_domain_dir + "/" + github_serice_subdomain
						
						print("=" * 150)
						print("[+] Found Vulnerable Subdomain: {} -> {}".format(github_serice_domain_dir, github_serice_subdomain))
						print("=" * 150)
						
						with open(github_vuln_serices_dir_final, 'w') as github_service_fp:
							#print(vuln_subdomain_finder)
							github_service_fp.write(vuln_subdomain_finder)
		
		print("\n[+] Vulnerable Subdomain are stored at " + os.getcwd() + github_404)
		
	except KeyboardInterrupt:
		print("\n\n[*] User Requested An Interrupt")
		print("[*] Apllication Shutting Down")
		sys.exit(1)


if select == "" or select == "0":
	find_domain()
	find_subdomain("domains")
	filter_live_subdomain()
	check_service()
	find_404()

if select == "1":
	find_domain()

elif select == "2":
	find_subdomain("scans/domains.txt")

elif select == "3":
	filter_live_subdomain()

elif select == "4":
	check_service()
	
elif select == "5":
	find_404()
