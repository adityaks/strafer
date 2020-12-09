#!/usr/bin/python

'''
Original BSD License (BSD with advertising)

Copyright (c) 2020, {Aditya K Sood - https://adityaksood.com}
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of SecNiche Security Labs nor the names of its contributors
    may be used to endorse or promote products derived from this software
    without specific prior written permission.
    
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
OF THE POSSIBILITY OF SUCH DAMAGE.
'''

# importing required libraries for successful execution of this tool

lib_requirements = ['os','re','time','sys','urllib','urllib2','requests','json','geoip']
for import_library in lib_requirements:
    try:
        globals()[import_library] = __import__(import_library)
    except:
        print "[-] %s - import library failed !" %(import_library)
        print "[-] tool cannot continue, please install the required library !"
        print "[*] sudo apt-get install python-setuptools to install 'easy_install'"
        sys.exit(0)
try:
    from BeautifulSoup import BeautifulSoup
except:
    print "[-] import library failed for BeautifulSoup !"



def banner():
    print "\t-----------------------------------------------------------"
    cs_banner = """  


		   _____  __                ____           
		  / ___/ / /_ _____ ____ _ / __/___   _____
		  \__ \ / __// ___// __ `// /_ / _ \ / ___/
		 ___/ // /_ / /   / /_/ // __//  __// /    
		/____/ \__//_/    \__,_//_/   \___//_/     
                                           

	STRAFER : A Tool to Detect Potential Infections in ElasticSearch Deployments !
        Authored by: Aditya K Sood {https://adityaksood.com} 
        """
    print cs_banner
    print "\t----------------------------------------------------------"



def dump_http_responses_text(url):
        try:
                url_http="http://"+url
                url_https="https://"+url
                http_handle = requests.get(url_http)
                if http_handle.status_code == 200:
                        print "[*] valid URL configuration is: %s\n" %url_http
                        print http_handle.text

                if http_handle.status_code == 401:
                        print "[*] authentication in place for the elasticsearch instance: %s\n" %url_http
                        print http_handle.text
                        print "[*] -------------------------------------------------------------------------\n"
                        sys.exit(0)


        except requests.exceptions.RequestException as e:
                raise SystemExit(e)
        except requests.exceptions.HTTPError as err:
                raise SystemExit(err)
        except TypeError as h:
                print "[-] check if options such as url has been specified properly!"
                sys.exit(0)
        except ValueError as h:
                print "[-] check if options such as url has been specified properly!"
                sys.exit(0)
    
        return


# patterns to scan in responses

def elasticsearch_ransom_map(url):
	try:
		url_http="http://"+url
		url_https="https://"+url
		http_handle = requests.get(url_http)
		if http_handle.status_code == 200:
       	  		print "[*] valid URL configuration is: %s\n" %url_http
	  		json_resp =  http_handle.text

			j_resp = http_handle.json()
			count = 0
			if "bitcoin" in json_resp:
				print "[#] ransomware warning message text pattern matched | pattern - (bitcoin)"
				count=count+1	
			
			if "bitcoin_address" in json_resp:
				print "[#] ransomware warning message text pattern matched | pattern - (bitcoin_address)"
				count=count+1

			if "read_me" in json_resp:
                                print "[#] ransomware warning message text pattern matched | pattern - (index:read_me)"
                                count=count+1

 			if "All your data is a backed up" in json_resp:
                                print "[#] ransomware warning message text pattern matched | pattern - (data backed up)"
                                count=count+1
			
			if re.findall(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b', json_resp):
				print "[#] ransomware warning message text pattern matched | pattern - (bitcoin_account_identifier)"
				count=count+1

			if count >= 3:
				print "[#] -----------------------------------------------------------------------"
				print "[#] -------- [Elasticsearch Ransomware Infection - Highly Probable] -------"
				print "[#] -----------------------------------------------------------------------"

				print "[#] Dumping the full data ......................\n"
			 	# print "[*] dumping the ransomware message\n"
                        
				for key, value in j_resp.items():
                                	print key,value
			else:
				print "[#] halting the detection logic, ransomware infection probability very low......"					
				print "\n[#] -----------------[ No RANSOMWARE NOTIFICATION/DISCLAIMER Traces Detected ] -------------------\n"
				

		if http_handle.status_code == 401:
			print "[*] authentication in place for the elasticsearch instance: %s\n" %url_http
			print http_handle.text
			print "[*] -------------------------------------------------------------------------\n"
			sys.exit(0)


	except requests.exceptions.RequestException as e:
		raise SystemExit(e)
	except requests.exceptions.HTTPError as err:
		raise SystemExit(err)
	except TypeError as h:
		print "[-] check if options such as url has been specified properly!"
        	sys.exit(0)
   	except ValueError as h:
        	print "[-] check if options such as url has been specified properly!"
        	sys.exit(0)
    
	except KeyboardInterrupt:
		sys.exit(0)
    	return
		
def elasticsearch_meow_infections(url):
        try:
                url_http="http://"+url
                url_https="https://"+url
                http_handle = requests.get(url_http)
                if http_handle.status_code == 200:
                        print "[*] valid URL configuration is: %s\n" %url_http
                        json_resp =  http_handle.text

                        count = 0
                        
			if "yellow" in json_resp:
				print "[#] detected indices are in yellow state ... potential missing replica shards"
				count=count+1


			if "open" in json_resp:
				print "[#] despite in yellow state, indices support open operation"
				count=count+1

			if "-meow" in json_resp:
                                print "[#] detected infection indicator of botnet infection....---- meow botnet"
                                count=count+1

			if count >= 3:
				print "[#] health in yellow detected for indices are in open state with botnet infection signature" 
				print "[#] Indices are infected. Potential data destruction occured, check your indices and stored data"
				
				print "\n[#] ------------------------ [MEOW BOTNET INFECTION DETECTED] ----------------------------------"
				print "\n"
				print http_handle.text
			else:
				print "[#] ---------------[ No Infections Detected ] ----------------------------\n"


 		if http_handle.status_code == 401:
			print "[*] authentication in place for the elasticsearch instance: %s\n" %url_http
                        print http_handle.text
                        print "[*] -------------------------------------------------------------------------\n"
                        sys.exit(0)

   	except requests.exceptions.RequestException as e:
		raise SystemExit(e)
        except requests.exceptions.HTTPError as err:
                raise SystemExit(err)
        except TypeError as h:
                print "[-] check if options such as url has been specified properly!"
                sys.exit(0)
        except ValueError as h:
                print "[-] check if options such as url has been specified properly!"
                sys.exit(0)

        return


# verify authentication

def verify_auth(url):
        try:
                url_http="http://"+url
                url_https="https://"+url
                http_handle = requests.get(url_http)
                if http_handle.status_code == 200:
                        print "[*] seems like the elasticsearch interface is exposed....\n"
			print "[*] valid URL configuration is: %s\n" %url_http
                        print http_handle.text

			print "[*] enumerating data from the remote elasticsearch instance .........\n"
                        time.sleep(2)

			targets = ['_cat/nodes','_cat/indices','_cat/master','_cat/tasks','_cat/shards','/_search?pretty','_cat/health']

			for item in targets:
				print "[*] dumping the contents of: %s" %item
				print "[*] ---------------------------------------\n"
				time.sleep(1)
				target_resource_index=str(item)
				cat_target =  str(url_http + target_resource_index)
				elasticsearch_s_url_h = requests.get(cat_target)
				if elasticsearch_s_url_h.status_code == 200:
					print elasticsearch_s_url_h.text

			print "[*] request processed successfully ! exiting !\n"

			sys.exit(0)
                	
		if http_handle.status_code == 401:
                        print "[*] authentication is not in  place for the elasticsearch instance: %s\n" %url_http
                        if "missing authentication credentials" in http_handle.text:
				print "[*] security exception occurred: missing authentication credentials\n"
				print http_handle.text
			print "[*] -------------------------------------------------------------------------\n"

			print "[*] request processed successfully ! exiting !"
                        sys.exit(0)

        except requests.exceptions.RequestException as e:
                raise SystemExit(e)
        except requests.exceptions.HTTPError as err:
                raise SystemExit(err)
        except TypeError as h:
                print "[-] check if options such as url has been specified properly!"
                sys.exit(0)
        except ValueError as h:
                print "[-] check if options such as url has been specified properly!"
                sys.exit(0)

        return




# routine to check if the remote elasticsearch instance is a honeynet or not 

def detect_elastichoney_hp(url):
        try:
                url_http="http://"+url
                url_https="https://"+url
                http_handle = requests.get(url_http)
                if http_handle.status_code == 200:
                        print "[*] valid URL configuration is: %s\n" %url_http
                        json_resp =  http_handle.text

                        count = 0

                        if "b88f43fc40b0bcd7f173a1f9ee2e97816de80b19" in json_resp:
                                print "[#] detected buildhash for elastichoney: (build_hash: b88f43fc40b0bcd7f173a1f9ee2e97816de80b19)"
                                count=count+1


                        if "USNYES" in json_resp:
                                print "[#] detected hardcoded name for elastichoney: (name: USNYES)"
                                count=count+1

                        if "1cf0aa9d61f185b59f643939f862c01f89b21360" in json_resp:
                                print "[#] detected index for elastichoney: (index_name: 1cf0aa9d61f185b59f643939f862c01f89b21360)" 
				count=count+1

			if "db18744ea5570fa9bf868df44fecd4b58332ff24" in json_resp:
				print "[#] detected index for elastichoney: (index_name: db18744ea5570fa9bf868df44fecd4b58332ff24)"
				count=count+1

			if "index_not_found_exception" in json_resp:
				print "[#] detected specific indicator for elastichoney <index_not_found_exception> occured for: _security/_authenticate resource -- STRANGE!"
				count=count+1

			if "404" in json_resp:
                                print "[#] detected specific indicator for elastichoney <400> occured for: _security/_authenticate resource -- STRANGE!"
                                count=count+1
	
                        if count >= 2:                                
                                print "\n[#] ------------------------ [Elasticsearch <ELASTICHONEY> Honeypot Detected] ----------------------------------"
                                print "\n"
                        else:
                                print "[#] ---------------[ No Elasticsearch <ELASTICHONEY> HONEYPOT Detected] ----------------------------\n"
				sys.exit(0)

                if http_handle.status_code == 401:
                        print "[*] authentication in place for the elasticsearch instance: %s\n" %url_http
                        print http_handle.text
                        print "[*] -------------------------------------------------------------------------\n"
                        sys.exit(0)

        except requests.exceptions.RequestException as e:
                raise SystemExit(e)
        except requests.exceptions.HTTPError as err:
                raise SystemExit(err)
        except TypeError as h:
                print "[-] check if options such as url has been specified properly!"
                sys.exit(0)
        except ValueError as h:
                print "[-] check if options such as url has been specified properly!"
                sys.exit(0)

        return



def detect_elasticpot_hp(url):
        try:
                url_http="http://"+url
                url_https="https://"+url
                http_handle = requests.get(url_http)
                if http_handle.status_code == 200:
                        print "[*] valid URL configuration is: %s\n" %url_http
                        json_resp =  http_handle.text
                        count = 0
                        
                        if "ews" in json_resp:
                                print "[#] detected index related for elasticpot: (index: ews)"
                                count=count+1

                        if "Flake" in json_resp:
                                print "[#] detected hardcoded name for elasticpot: (name: Flake)"
                                count=count+1
                        
                        if "b88f43fc40b0bcd7f173a1f9ee2e97816de80b19" in json_resp:
                                print "[#] detected buildhash for elasticpot: (build_hash: b88f43fc40b0bcd7f173a1f9ee2e97816de80b19)"
                                count=count+1

			if "dummy" in json_resp:
				print "[#] detected index for elasticpot: (index: dummy 5)"
				count=count+1

			if count >= 2:
                                print "\n[#] ------------------------ [Elasticsearch <ELASTICPOT> Honeypot Detected] ----------------------------------"
                                print "\n"
				# print http_handle.text 
		
                        else:
                                print "[#] ---------------[ No Elasticsearch <ELASTICPOT> HONEYPOT Detected] ----------------------------\n"
                                sys.exit(0)

		if http_handle.status_code == 401:
                       	print "[*] authentication in place for the elasticsearch instance: %s\n" %url_http
                        print http_handle.text
                        print "[*] -------------------------------------------------------------------------\n"
                        sys.exit(0)

        except requests.exceptions.RequestException as e:
                raise SystemExit(e)
        except requests.exceptions.HTTPError as err:
                raise SystemExit(err)
        except TypeError as h:
                print "[-] check if options such as url has been specified properly!"
                sys.exit(0)
        except ValueError as h:
                print "[-] check if options such as url has been specified properly!"
                sys.exit(0)

        return


def tool_usage():
	print "[-] usage: %s <elasticsearch_host (local or remote)> <elasticsearch service port> <module_name>" %str(sys.argv[0])
	print "[*] modules: [verify_auth] | [ransomware] | [meow_bot] | [eshoney_hp] [espot_hp]"
	print "[*]      : verify_auth --> check if elasticsearch interface is <EXPOSED>"
	print "[*]      : ransomware --> check potential <RANSOMWARE> infections"
	print "[*]      : meow_bot --> check for potential <MEOW BOT> infections"
	print "[*]      : eshoney_hp --> check if the elasticsearch instance is <ELASTICHONEY> honeynet"
	print "[*]	 : espot_hp --> check if the elasticsearch instance is <ELASTICPOT> honeypot"
	print "\n[*] example: %s 127.0.0.1 9200 ransomware\n" %str(sys.argv[0])

def main():
	banner()
	try:
		ip_address = str(sys.argv[1])
		port = int(sys.argv[2]);
		module = str(sys.argv[3]);
		url_domain = str(ip_address+":"+str(port))
		print "[*] [------------------------------------------------------------]"
		print "[*] [     ELASTICSEARCH Infections / Honeypot Detection Tool     ]"
		print "[*] [------------------------------------------------------------]"

		print "\n"

		time.sleep(2)
		print "[#] Checking the <GEOIP> status of the Elasticsearch instance ......"
		from geoip import geolite2
		ip_match = geolite2.lookup(ip_address)
		print "[*] Elasticsearch instance is located in <%s> | <%s>\n" %(ip_match.country, ip_match.timezone)

		print "[*] elasticsearch url is constructed as: %s\n" %str(url_domain)
		elasticsearch_url=url_domain
	

		# -------------------------------------------------------------------       
                # Triggering routine to detect Elasticseaarch infected with ransomware
                # --------------------------------------------------------------------

		if module == "ransomware":
			print "[*] dumping the search index info to check ransom demand ........"
			print "[*] sending request to the source index to analyze the ransomware asks by the malware operator ......."
			#time.sleep(2)
			target_resource=str("/_search?pretty=true")
			elasticsearch_s_url = str(elasticsearch_url+target_resource)
			elasticsearch_ransom_map(elasticsearch_s_url)
		
 		# -----------------------------------------------------------------------       
                # Triggering routine to verify authz/authn on the  Elasticsearch instance
                # -----------------------------------------------------------------------


		if module == "verify_auth":
			print "[*] validating authentication: if interface is open to access..\n"
                        target_resource=str("/")
                        elasticsearch_s_url = str(elasticsearch_url+target_resource)
                        verify_auth(elasticsearch_s_url)
			print "\n[*] request processed successfully ! exiting !\n"
			sys.exit(0)
		
		# ----------------------------------------------------------------	 
		# Triggering routine to detect Elasticsearch ELASTICHONEY Honeypot
		# ----------------------------------------------------------------

		if module == "eshoney_hp":
			print "[*] starting ---[ROUND 1]--- detecting indicators for Elastisearch ELASTICHONEY Honeypot.........."
			target_resource_a=str("/")
			elasticsearch_s_url_a = str(elasticsearch_url+target_resource_a)
                        detect_elastichoney_hp(elasticsearch_s_url_a)
			
			print "[*] starting ---[ROUND 2]--- detecting indicators for Elastisearch ELASTICHONEY Honeypot.........."
                        target_resource_b=str("/_security/_authenticate")
                        elasticsearch_s_url_b = str(elasticsearch_url+target_resource_b)
                        detect_elastichoney_hp(elasticsearch_s_url_b)

			print "[*] starting ---[ROUND 3]--- detecting indicators for Elastisearch ELASTICHONEY Honeypot........."
                        target_resource_c=str("/_cat/indices")
                        elasticsearch_s_url_c = str(elasticsearch_url+target_resource_c)
                        detect_elastichoney_hp(elasticsearch_s_url_c)

			print "\n[*] request processed successfully ! exiting !\n"
			sys.exit(0)


		# ----------------------------------------------------------------       
                # Triggering routine to detect Elasticsearch ELASTICPOT Honeypot
                # ----------------------------------------------------------------

                if module == "espot_hp":
                        print "[*] starting ---[ROUND 1]--- detecting indicators for Elastisearch ELASTICPOT Honeypot........."
                        target_resource_d=str("/")
                        elasticsearch_s_url_d = str(elasticsearch_url+target_resource_d)
                        detect_elasticpot_hp(elasticsearch_s_url_d)


                        print "[*] starting ---[ROUND 2]--- detecting indicators for Elastisearch ELASTICHONEY Honeypot......."
                        target_resource_f=str("/_cat/indices")
                        elasticsearch_s_url_f = str(elasticsearch_url+target_resource_f)
                        detect_elasticpot_hp(elasticsearch_s_url_f)

                        print "\n[*] request processed successfully ! exiting !\n"
                        sys.exit(0)


		# ----------------------------------------------------------------       
                # Triggering routine to detect MEOW Botnet
                # ----------------------------------------------------------------

		if module == "meow_bot":
			print "\n"
                	# print "[*] [-----------------------------[ ### ]----------------------------------]"
                	print "[*] executing detection logic for checking [MEOW Bot]  infections  ...........\n"

			target_resource=str("/_cat/indices?v&health=yellow")
                	elasticsearch_s_url = str(elasticsearch_url+target_resource)
                	elasticsearch_meow_infections(elasticsearch_s_url)
                	# print "[*] [-----------------------------[ ### ]----------------------------------]"


		time.sleep(2)
		print "\n[*] request processed successfully ! exiting !\n"
		sys.exit(0)
		
	except IndexError:
		tool_usage()
		'''
		print "[-] usage: %s <elasticsearch_host (local or remote)> <elasticsearch service port> <module_name>" %str(sys.argv[0])
		print "[*] modules: [verify_auth] | [ransomware] | [meow_bot] | [eshoney_hp]"
		print "[*]	: verify_auth --> check if elasticsearch interface is exposed"
		print "[*]	: ransomware --> check potential ransomware infections"
		print "[*]	: meow_bot --> check for potential meow bot infections"
		print "[*] 	: eshoney_hp --> check if the elasticsearch instance is honeynet"
		print "\n[*] example: %s 127.0.0.1 9200 ransomware\n" %str(sys.argv[0])
		'''
		sys.exit(0)

	except (TypeError, ValueError):
		print "[-] type/value error occurred\n"
		tool_usage()
		sys.exit(0) 


	except KeyboardInterrupt:
		sys.exit(0)

if __name__=="__main__":
	main()
