#!/usr/bin/env python
# encoding: UTF-8
import re, sys, json
import urllib.parse, urllib.request, requests
import core 
from bs4 import BeautifulSoup



def drupal_get_version(target):
	#<meta name="generator" content
	try:
		soup=str(core.get_page(target+"CHANGELOG.txt"))
		regex= re.findall(r'Drupal (.*?),', str(soup))
		if regex!= []:
			return regex[0],"/CHANGELOG.txt"
			#return soup.split(",")[0].split(">")[3]
		else:
			#print ("CHANGELOG.txt not found")
			soup=core.get_page(target)
			regex = re.findall(r'content="Drupal (.*?) \(http(s|):\/\/(www\.|)drupal.org\)"', str(soup))
			#print (soup)
			if regex != []:
				return regex[0][0],"META Generator Tag"
			#for link in soup.find_all('meta'):
			#	if "generator" in str(link):
			#		c=str(link).split('"')[1]
			#		if hasNumbers(c) and c.lower().startswith("drupal "):
			#			return str(link).split('"')[1].split("(")[0]
			else:
				r=request.get(target)
				if r.status_code == 200 and r.headers["X-Generator"]:
					return r.headers["X-Generator"],"X-Generator HTTP Header"
				return 'X.X.X',""
						#return "###"
			#return 'NO <meta name="generator"'
			#return "###"
	except Exception as e:
		return "X.X.X"
	
def wp_drupal_theme_id(target):
        try:
                soup=str(core.get_page(target))
                wp_theme = re.findall(re.compile('/themes/(.+?)/'),str(soup))
                #result=soup.split("themes")[1].split("/")[1]
                if wp_theme:
                        return wp_theme[0]
                return fuzz_dru_component(target,"themes")
        except Exception as e:
                print ("wp_drupal_theme_id",e)
                return ""

def get_drupal_plugins(target):
	soup=core.get_page(target)
	lst=[]
	try:
		for link in soup.find_all('script'):
			for x in str(link).split("\n"):
				#print (x,1)
				if "modules" in x:
					i=0
					for y in x.split("/"):
						if "modules" in y:
							lst.append (x.split("/")[i+1].split("\\")[0])
						i+=1
		return sorted(set(lst))
	except Exception as e:
		print (e)
	return "-"

def get_dru_plugins_drupalxray_com(url):
	modulelist=[]
	if "www" in url:
    		url = url.replace("www.","")
	if "https://" in url:
		url = url.replace("https://","")
	if "http://" in url:
		url = url.replace("http://","")
	url="http://drupalxray.com/xray/"+url
	xrayurl= requests.get(url).text.split("\n")
	for line in xrayurl:
		if '<a href="https://www.drupal.org/project/' in line:
			module=line[line.index("target=\"_blank\">")+16:line.index("</a>")]
			modulelist.append(module)
	return modulelist[1:]


def check_dru_default_files(target):
	#Check for default files
	try:
		files=[]
		defFiles=['sites/seetings.inc', 'sites/seetings.php~', 'sites/seetings.php.txt', 'sites/seetings.php.old', 'sites/seetings.php_old', 
		'sites/seetings.php-old', 'sites/seetings.php.save', 'sites/seetings.php.swp', 'sites/seetings.php.swo', 'sites/seetings.php_bak', 
		'sites/seetings.php-bak', 'sites/seetings.php.original', 'sites/seetings.php.old', 'sites/seetings.php.orig', 'sites/seetings.php.bak', 
		'sites/seetings.save', 'sites/seetings.old', 'sites/seetings.bak', 'sites/seetings.orig', 'sites/seetings.original', 'sites/seetings.txt',
		"sites/default/seetings.inc",'README.txt','INSTALL.mysql.txt','MAINTAINERS.txt','profiles/standard/translations/README.txt',
		'profiles/minimal/translations/README.txt','INSTALL.pgsql.txt','UPGRADE.txt','CHANGELOG.txt','INSTALL.sqlite.txt','LICENSE.txt',
		'INSTALL.txt','COPYRIGHT.txt','web.config','modules/README.txt','modules/simpletest/files/README.txt','modules/simpletest/files/javascript-1.txt',
		'modules/simpletest/files/php-1.txt','modules/simpletest/files/sql-1.txt','modules/simpletest/files/html-1.txt','modules/simpletest/tests/common_test_info.txt',
		'modules/filter/tests/filter.url-output.txt','modules/filter/tests/filter.url-input.txt','modules/search/tests/UnicodeTest.txt',
		'themes/README.txt','themes/stark/README.txt','sites/README.txt','sites/all/modules/README.txt','sites/all/themes/README.txt',
		'modules/simpletest/files/html-2.html','modules/color/preview.html','themes/bartik/color/preview.html',
		"LICENSE.txt", "web.config", "update.php","robots.txt", "install.php", "xmlrpc.php",
		"/sites/all/modules/contrib/", "/sites/default/modules/"]
		for f in defFiles:	
			#print (target+f)
			resp = requests.get(target+f)
			if resp.status_code==200 and resp.text != ("" or None):
				files.append(target+f)
		#if files:
		return files
		#return [""]
	except Exception as e:
		print (e)


def dru_users(url):
	#Enumerating Drupal Usernames via \"Views\" Module...
	views = "?q=admin/views/ajax/autocomplete/user/"; users=""
	alphanum = list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	usernames = []
	try:
		htmltext = requests.get(url+"?q=admin/views/ajax/autocomplete/user/NotExisingUser1234!").text
		#If NotExisingUser1234 returns [], then enumerate users
		if htmltext == '[]':
			for letter in alphanum:
				htmltext = requests.get(url+views+letter).text
				regex = '"(.+?)"'
				pattern =    re.compile(regex)
				usernames = usernames + re.findall(pattern,htmltext)
		for blognum in range (1,50):
			htmltext = requests.get(url+"?q=blog/"+str(blognum)).text
			regex = "<title>(.+?)\'s"
			pattern =    re.compile(regex)
			user = re.findall(pattern,htmltext)
			usernames = usernames + user
		#if usernames:
		for x in sorted(set(usernames)):
			users=users+x+", "
		return users[:-2]
		#return [""]
	except Exception as e:
		return users
		print (e)


def dru_forgotten_pass(url):
        # Username Enumeration via Forgotten Password
        # can't conquer captcha 
        query_args = {"name": "N0t3xist!1234" ,"form_id":"user_pass"}
        data = urllib.parse.urlencode(query_args).encode("utf-8")
        # HTTP POST Request
        req = urllib.request.Request(url+"user/password")
        try:
                htmltext = urllib.request.urlopen(req,data=data).read()
                #print (htmltext)
                if re.findall(re.compile('Sorry,.*N0t3xist!1234.*is not recognized'),str(htmltext)):
                	return url+"user/password"
                elif re.findall(re.compile("N0t3xist!1234.*reconnu"),str(htmltext)):
                	return url+"user/password"
                return ""
        except Exception as e:
                print (e)

def fingerprint_dru_version_hash_based(target):
	json_file = open('Data/dru/drupal.json')
	#json1_str = json1_file.read()
	json_data = json.load(json_file)
	versions=[]
	try:
		for x in json_data.keys():
			ddl_url=target+x
			if requests.get(ddl_url).status_code == 200:
				#print (target+x) 
				ddl_name="/tmp/"+x.replace("/","-")
				core.download_file(ddl_url, ddl_name)
				ddl_hash = core.md5_hash(ddl_name)
				core.remove_file(ddl_name)
				for h in json_data[x].keys():
					if h == ddl_hash:
						#print (json_data[x][h])
						versions.append(json_data[x][h])
		return sorted(set(versions))
	except Exception as e:
		print (e)


def fuzz_dru_component(target,component):
    components=[]
    try:
        data_file=open('Data/dru/'+component)
        data = data_file.readlines()
        for com in data:
        	x=target+"???????????/"+component+"/"+com
        	c=requests.get(x)
        	print (x)
        	if c.status_code ==200 and c.text != ("" or None):
        		components.append(com)
        return components
    except Exception as e:
        print ("fuzz_wp_"+component,e)
        return []

def get_dru_mod_vulns(x,modules):
    dru_mod_vulns=[]
    f = open("Data/dru/dru-mod-vulns","r")
    line = f.readlines()
    for modulename in line:
        moduleonlyname=modulename[modulename.index("Vulnerable module:")+18:modulename.index("Type:")]
        if "Module" in moduleonlyname:
            moduleonlyname=moduleonlyname.replace("Module","")		#remove "Module" keyword from name
        if "Drupal" in moduleonlyname:
            moduleonlyname=moduleonlyname.replace("Drupal","") 		#remove "Drupal" keyword from name
        moduleonlyname=moduleonlyname.replace(" ","") 			#remove spaces from name
        moduleonlyname=moduleonlyname.lower() 				#make name lower case for matching
        moduleonlyname=moduleonlyname.replace("\n","")			 #remove newlines from name
        if moduleonlyname in modules:
        	#modulename[:modulename.index(" Vulnerable module:")]
        	dru_mod_vuln=[]
        	dru_mod_vuln.append(modulename[modulename.index("Vulnerable module:"):modulename.index("Type:")]+", "+modulename[modulename.index("Type:"):modulename.index("Descripion:")])
        	#dru_mod_vuln.append()
        	dru_mod_vuln.append(modulename[modulename.index("Url:"):modulename.index("Version:")].replace("Url: ",""))
        	dru_mod_vuln.append(modulename[modulename.index("Descripion:"):modulename.index("Url:")].replace("Descripion: ",""))
        	dru_mod_vulns.append(dru_mod_vuln)
    return dru_mod_vulns


def get_dru_core_vulns(version):
        dru_core_vulns=[]#i=0
        #print (version)#,len(version))
        f = open("Data/dru/dru-vulns")
        lines = f.readlines();
        for line in lines:
                versions=line.split("Version: [")[1]
                if len(version)==1:
                	version=version+".0"
                if ("'"+version+"'") in versions:
                        #print (version) print (versions)
                        #i+=1
                        dru_core_vuln=[]
                        #dru_core_vuln.append(line[:line.index("Type:")])
                        dru_core_vuln.append(line[line.index("Type:"):line.index("Descripion:")])
                        dru_core_vuln.append(line[line.index("Url:"):line.index("Version:")].replace("Url: ",""))
                        dru_core_vuln.append(line[line.index("Descripion:"):line.index("Url:")].replace("	","").replace("Descripion: ",""))
                        dru_core_vulns.append(dru_core_vuln)
        return dru_core_vulns
        #print (i)
        #return []




def dru_additional_infos(x,theme,plugins):
	return [""]+[dru_users(x)]+[dru_forgotten_pass(x)]+[""]+[""]+[""]+[""]+[core.dirs_listing("dru",x,theme,plugins)]
	#check_dru_default_files(x)
"""
dru_t4rgets=["http://ensias.um5.ac.ma","https://drupal.org","https://gsas.harvard.edu","https://www.linux.com/"]

for x in dru_t4rgets:
	if x[len(x)-1] != '/':
			x=x+"/"
	print (x)
	#modulescanner(x)
	for x in get_dru_core_vulns(drupal_get_version(x)):
		print (x)
	#print (check_dru_default_files(x))
	#print (dru_users(x))
	#print (dru_forgotten_pass(x))
	#fingerprint_dru_version_hash_based(x)



def checkifdrupal(url):
	try:
		count_dp_keywords = 0
		if "http://" in url:
			website = urllib2.urlopen(url)
		else:
			website = urllib2.urlopen("http://" + url)
		websiteread = website.readlines()
		for web in websiteread:
			if re.findall('[D|d]rupal.js',web):
				count_dp_keywords += 1
			if re.findall('[D|d]rupal',web):
				count_dp_keywords += 1
		if count_dp_keywords > 1:
			#print count_dp_keywords
			return True
		else:
			return False
	except:
		print "Site offline or takes to long to respond"
"""	