#!/usr/bin/python3
# encoding: UTF-8
import re, sys, requests 
import requests, re
import core 
"""target = sys.argv[0]
if("http" not in target[:4]):
    target = "http://%s" %target
if(target[len(target)-1] != '/'):
    target = "%s/" %target"""

expFile    = "Data/joo/files_exploits.csv"
compFile = "Data/joo/joo-components" #vulnerable joo components

def joomla_theme_id(target):
	try:
		htmltext = requests.get(target+'index.php').text
		WebTemplate = re.findall("/templates/(.+?)/", htmltext,re.IGNORECASE)
		#htmltext = requests.get(target+'administrator/index.php').text
		#AdminTemplate = re.findall("/administrator/templates/(.+?)/", htmltext,re.IGNORECASE)
		return WebTemplate[0]
	except Exception as e:
		print (e)


def joomla_get_version(target):
	try:
		soup=core.get_page(target)
		regex=re.findall(r'content=(?:\"|\')Joomla! (.*?) - Open Source Content Management(?:\"|\')', str(soup))
		if regex!= []:
			return regex[0],"META Generator Tag"
		else:
			xml_files = ['administrator/manifests/files/joomla.xml','language/en-GB/en-GB.xml',
			'administrator/components/com_content/content.xml','administrator/components/com_plugins/plugins.xml',
			'administrator/components/com_media/media.xml','mambots/content/moscode.xml']
			for xml_file in xml_files:
				soup=core.get_page(target+xml_file)
				regex = re.findall(r'<version>(.*?)</version>', str(soup))
				if regex!=[]:
					return regex[0],"/"+xml_file
				else:
					soup=str(core.get_page(target+"README.txt"))
					regex=re.findall(r'package to version (.*?)\n', str(soup))
					if regex != []:
						return regex[0],"/README.txt"
					else:
						return "X.X.X",""
		#return 'NO <meta name="generator"'
		#return "###"
	except Exception as e:
		print(e)
		return "X.X.X"


def get_joomla_plugins(target):
	#files=get_files(target,"")
	#=[]
    try:
        htmltext = requests.get(target).text
        modulesFound = re.findall(re.compile('/modules/(.+?)/'),htmltext)
        componentsFound = re.findall(re.compile('/components/(.+?)/'),htmltext)
        #pluginsFound = re.findall(re.compile('/plugins/(.+?)/'),htmltext)
        #if modulesFound+componentsFound:
        return sorted(set(modulesFound+componentsFound))#+pluginsFound))
        #return []
    except Exception as e:
        print (e)
        return []


def fuzz_joo_components(target):
    headers = {'User-Agent':'Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/38.0'}
    toCheck = ["<h1>Not Found</h1>","<title> 404 - Page not found</title>","\"center error-404\""]
    foundComp = []
    bad_resp = requests.get("%scomponents/impo5sIblexXxD35" %target).text
    i = 0
    with open(compFile,"r") as f:
        for line in f: 
            i += 1
            line = line.strip()
            if(len(line) > 0 and line != "com_"):
                #print "[%s] Testing '%s'" %(i,line)
                url = "%scomponents/%s" %(target,line)    
                #print url
                try:
                    r = requests.get(url,headers=headers,timeout=10)
                    Valid = True
                    for c in toCheck:
                        if(c in r.text):
                            Valid = False
                            break
                    if(r.status_code != 404 and Valid and (r.url == url or r.url == "%s/" %url) 
                        and r.text != bad_resp):
                        foundComp.append(line)
                        #print "%s [FOUND]" %line
                except: 
                    pass
    return foundComp


def check_joo_default_files(target):
    #Check for default/configuration files
    files=[]
    defFiles=['configuration.php~','configuration.php.new','configuration.php.new~','configuration.php.old','configuration.php.old~','configuration.bak',
    'configuration.php.bak','configuration.php.bkp','configuration.txt','configuration.php.txt','configuration - Copy.php','configuration.php.swo','configuration.php_bak',
    'configuration.orig','configuration.php.save','configuration.php.original','configuration.php.swp','configuration.save','.configuration.php.swp','configuration.php1',
    'configuration.php2','configuration.php3','configuration.php4','configuration.php4','configuration.php6','configuration.php7','configuration.phtml','configuration.php-dist',
    'README.txt','htaccess.txt','administrator/templates/hathor/LICENSE.txt','web.config.txt','joomla.xml','robots.txt.dist','LICENSE.txt',
    'media/jui/fonts/icomoon-license.txt','media/editors/tinymce/jscripts/tiny_mce/license.txt','media/editors/tinymce/jscripts/tiny_mce/plugins/style/readme.txt',
    'libraries/idna_convert/ReadMe.txt','libraries/simplepie/README.txt','libraries/simplepie/LICENSE.txt','libraries/simplepie/idn/ReadMe.txt']
    
    backup=['1.txt','2.txt','1.gz','1.rar','1.save','1.tar','1.tar.bz2','1.tar.gz','1.tgz','1.tmp','1.zip','2.back','2.backup','2.gz','2.rar','2.save',
    '2.tar','2.tar.bz2','2.tar.gz','2.tgz','2.tmp','2.zip','backup.back','backup.backup','backup.bak','backup.bck','backup.bkp','backup.copy','backup.gz',
    'backup.old','backup.orig','backup.rar','backup.sav','backup.save','backup.sql~','backup.sql.back','backup.sql.backup','backup.sql.bak','backup.sql.bck',
    'backup.sql.bkp','backup.sql.copy','backup.sql.gz','backup.sql.old','backup.sql.orig','backup.sql.rar','backup.sql.sav','backup.sql.save','backup.sql.tar',
    'backup.sql.tar.bz2','backup.sql.tar.gz','backup.sql.tgz','backup.sql.tmp','backup.sql.txt','backup.sql.zip','backup.tar','backup.tar.bz2','backup.tar.gz',
    'backup.tgz','backup.txt','backup.zip','database.back','database.backup','database.bak','database.bck','database.bkp','database.copy','database.gz','database.old',
    'database.orig','database.rar','database.sav','database.save','database.sql~','database.sql.back','database.sql.backup','database.sql.bak','database.sql.bck',
    'database.sql.bkp','database.sql.copy','database.sql.gz','database.sql.old','database.sql.orig','database.sql.rar','database.sql.sav','database.sql.save',
    'database.sql.tar','database.sql.tar.bz2','database.sql.tar.gz','database.sql.tgz','database.sql.tmp','database.sql.txt','database.sql.zip','database.tar',
    'database.tar.bz2','database.tar.gz','database.tgz','database.tmp','database.txt','database.zip','joom.back','joom.backup','joom.bak','joom.bck','joom.bkp',
    'joom.copy','joom.gz','joomla.back','Joomla.back','joomla.backup','Joomla.backup','joomla.bak','Joomla.bak','joomla.bck','Joomla.bck','joomla.bkp','Joomla.bkp',
    'joomla.copy','Joomla.copy','joomla.gz','Joomla.gz','joomla.old','Joomla.old','joomla.orig','Joomla.orig','joomla.rar','Joomla.rar','joomla.sav','Joomla.sav',
    'joomla.save','Joomla.save','joomla.tar','Joomla.tar','joomla.tar.bz2','Joomla.tar.bz2','joomla.tar.gz','Joomla.tar.gz','joomla.tgz','Joomla.tgz','joomla.zip',
    'Joomla.zip','joom.old','joom.orig','joom.rar','joom.sav','joom.save','joom.tar','joom.tar.bz2','joom.tar.gz','joom.tgz','joom.zip','site.back','site.backup',
    'site.bak','site.bck','site.bkp','site.copy','site.gz','site.old','site.orig','site.rar','site.sav','site.save','site.tar','site.tar.bz2','site.tar.gz','site.tgz',
    'site.zip','sql.zip.back','sql.zip.backup','sql.zip.bak','sql.zip.bck','sql.zip.bkp','sql.zip.copy','sql.zip.gz','sql.zip.old','sql.zip.orig','sql.zip.save',
    'sql.zip.tar','sql.zip.tar.bz2','sql.zip.tar.gz','sql.zip.tgz','upload.back','upload.backup','upload.bak','upload.bck','upload.bkp','upload.copy',
    'upload.gz','upload.old','upload.orig','upload.rar','upload.sav','upload.save','upload.tar','upload.tar.bz2','upload.tar.gz','upload.tgz','upload.zip']
    for f in defFiles:  
        #print (target+f)
        try:
            resp = requests.get(target+f)
            if resp.status_code==200 and resp.text != ("" or None):
                files.append(target+f)
        except:
            pass
    #if files:
    return files
    #return []

def joo_users(url):
    #Enumerating Joomla Usernames via "Feed"
    #jooUsers=[]
    users=""
    try:
        resp = requests.get(url+'/?format=feed').text
        jooUsers = re.findall("<author>(.+?) \((.+?)\)</author>", resp,re.IGNORECASE)
        #if jooUsers:
        for x in set(jooUsers):
            users=users+x+", "
        return users[:-2]
        #return sorted(set(jooUsers))
        #return []
            #print (jooUsers)
            #joo_add_infos["users"]=[]
            #joo_add_infos.append(jooUsers)

    except Exception as e:
        return users[:-2]
        print (e)


def find_admin_login_page(target):
    login_pages=[]
    admin_files = ['administrator','admin','panel','webadmin','modir','manage','administration',
    'joomla/administrator','joomla/admin']
    for x in admin_files:
        resp=requests.get(target+x).status_code
        if resp == 200:
            return target+x
    #if login_pages:
    return ""
    #return []

#def find_backup_file():
	

def joo_check_user_registration(url):
    try:
        reg_url = url + 'index.php?option=com_users&view=registration'
        resp = requests.get(reg_url)
        reg_source = resp.text
        #reg_source.url)
        #sys.exit()
        if 'type="password"' in reg_source or 'registration.register' in reg_source or 'jform_password2' in reg_source or 'jform_email2' in reg_source:
            #print ('User registration open: ' + reg_url )
            return resp.url
        return ""
    except Exception as e:
        print ("wp_check_user_registration",e)
        return []

def fingerprint_joo_version_hash_based(target):
    json_file = open('joomla.json')
    #json1_str = json1_file.read()
    json_data = json.load(json_file)
    versions=[]
    try:
    	for x in json_data.keys():
    		ddl_url=target+x
    		if requests.get(ddl_url).status_code == 200:
    			#print target+x 
    			ddl_name="/tmp/"+x.replace("/","-")
    			core.download_file(ddl_url, ddl_name)
    			ddl_hash = core.md5_hash(ddl_name)
    			core.remove_file(ddl_name)
    			for h in json_data[x].keys():
    				if h == ddl_hash:
    					#print (json_data[x][h])
    					versions.append(json_data[x][h])
    	return sorted(set(versions))
    except:
        pass


def get_joo_core_vulns(version):
    joo_core_vuln=joo_core_vulns=[]#i=0
    f = open("Data/joo/joo-vulns")
    lines = f.readlines();
    for line in lines:
        versions=line.split("Version: [")[1]
        if version in versions:
            joo_core_vuln=[]
            #print versions
            #i+=1
            #joo_core_vuln.append(line[:line.index("Type:")])
            joo_core_vuln.append(line[line.index("Type:"):line.index("Descripion:")])
            joo_core_vuln.append(line[line.index("Url:"):line.index("Version:")].replace("Url: ",""))
            joo_core_vuln.append(line[line.index("Descripion:"):line.index("Url:")].replace("   ","").replace("Descripion: ",""))
            joo_core_vulns.append(joo_core_vuln)
            #sys.stdout.flush()
    return joo_core_vulns
    #print (i)
    #return []


def CharOrNumber(c):
    if(c.isalpha() or str(c).isdigit() or c == '_'):
        return True
    return False

def NumberOrMinus(c):
    if(c == '-' or str(c).isdigit()):
        return True
    return False

def noPrevious(lowLine,semiComp):
    index = lowLine.find(semiComp)
    if("component" in lowLine[(index-11):index]):
        return True
    return False

def get_joo_com_vulns(foundComp):
    exploits = []
    if foundComp==['']:
        return []
    #print (foundComp)
    with open(expFile,"r") as f:
        for line in f:
            for comp in foundComp:
                semiComp = comp[4:]
                lowLine = line.lower()
                if((comp in lowLine or (" %s " %semiComp in lowLine and noPrevious(lowLine,semiComp) 
                    and NumberOrMinus(lowLine[lowLine.find(semiComp)+len(semiComp)+1]))) 
                    and ("Joomla" in line or "joomla" in line) 
                    and (CharOrNumber(lowLine[lowLine.find(comp)+len(comp)]) is False or "com_" not in line)):
                    line=line.strip()
                    if '"' in line: 
                        sline=line.replace('"','')
                    else:
                        sline=line.replace("'","")
                    sline=sline.replace("[","");sline=sline.replace("]","")
                    sline=sline.split(",")
                    #print (comp,semiComp)
                    exploit=[]
                    exploit.append("Vulnerable Component")
                    exploit.append("https://www.exploit-db.com/exploits/"+sline[0].replace("'",""))
                    exploit.append(sline[2]) #"Description: "
                    exploits.append(exploit)
    #if exploits:
    return exploits
    #return []



"""
joo_t4rgets=["http://emi.um5.ac.ma","http://www.joomla.org","http://grabcad.ir/bitumen/","http://gosaonline.co.za/"]

for x in joo_t4rgets:
    print (x)
    if x[len(x)-1] != '/':
            x=x+"/"
"""
def joo_additional_infos(x,theme,plugins):
    return [""]+[joo_users(x)]+[""]+[find_admin_login_page(x)]+[joo_check_user_registration(x)]+[""]+[""]+[core.dirs_listing("joo",x,theme,plugins)]
    #check_joo_default_files(x)
    #exploits = get_joo_com_vulns(foundComp)
#print "\nJoomla! exploits found [%s]: \n" %len(exploits)
"""
def dispaly_joo_com_vulns(foundComp,exploits):
    for comp in foundComp:
        semiComp = comp[4:]
        print colored("\n%s:\n" %comp,"red")
        for exp in exploits:
            lowexp = exp.lower()
            if(comp in lowexp or semiComp in lowexp):
                split = exp.split(",") 
                code = split[1].split("/")
                code = code[len(code)-1].split(".")[0]
                output = "%s    [https://www.exploit-db.com/exploits/%s/]" %(split[2],code)
                print '-' * len(output) 
                print output
                print '-' * len(output)

"""