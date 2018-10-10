import urllib.parse, re
import sys,json
import urllib.request, requests
from lxml import etree
import core 

def wp_drupal_theme_id(target):
    try:
        soup=str(core.get_page(target))
        wp_theme = re.findall(re.compile('/themes/(.+?)/'),str(soup))
        #result=soup.split("themes")[1].split("/")[1]
        if wp_theme:
            return wp_theme[0]
        return fuzz_wp_component(target,"themes")
    except Exception as e:
        print ("wp_drupal_theme_id",e)
        return ""


def wp_get_version(target):
    try:
        soup=core.get_page(target)
        #print (str(soup))
        regex = re.findall(r'<meta content="WordPress (.*?)"', str(soup))
        if regex != []:
            return regex[0],"META Generator Tag"
        else:
            regex = re.findall(r'<generator>https://wordpress.org/\?v=(.*?)</generator>', str(soup))
            if regex != []:
                return regex[0],"Meta tag"
            else:
                soup=core.get_page(target+"wp-links-opml.php")
                regex = re.findall(r'generator="wordpress/(.*?)"', str(soup))
                if regex != []:
                    return regex[0],"/wp-links-opml.php"
        #return fingerprint_wp_version_hash_based(target)
        return "X.X.X",""
    except Exception as e:
        print ("wp_get_version",e)
        return "X.X.X",""

def get_wp_plugins(target):
    plugins=dict()
    lplugins=[]
    try:
        soup=core.get_page(target)
        res=re.findall(re.compile('/wp-content/plugins/(.+?)/(.+?)"'),str(soup))
        for x in sorted(set(res)):
            if len(x[1].split("?ver="))!=1:
                plugins[x[0]]=x[1].split("?ver=")[1]
            else:
                plugins[x[0]]=""
        res1=re.findall(re.compile('Powered by (.+?) -'),str(soup))
        for x in sorted(set(res1)):
            plugins[x]=""
        for x,y in zip(plugins.keys(),plugins.values()):
            if y:
                lplugins.append([x,y])
            else:
                lplugins.append([x])
        #if lplugins:
        return lplugins
        #return [""] #+fuzz_wp_component(target,"plugins")
    except Exception as e:
        print ("get_wp_plugins",e)
        return []

    """
        http://nmap.org/nsedoc/scripts/http-wordpress-plugins.html
    """

        
def check_wp_default_files(target):
    #Check for default files
    files=[]
    f=open("Data/wp/default-files")
    defFiles=f.readlines()
    for f in defFiles:
        f=f.strip()
        #print (target+f)
        try:
            resp = requests.get(target+f)
            """
            Valid = True
            toCheck = ["<h1>Not Found</h1>","<title> 404 - Page not found</title>","\"center error-404\""]
            for c in toCheck:
                if(c in resp.text):
                    Valid = False
                    break
            """
            if resp.status_code==200 and resp.text != ("" or None):
                files.append(target+f)
        except:
            pass
    #if files:
    return files
    #return [""]


def wp_users(url):
    #Enumerating Wordpress Usernames via "Feed"
    usernames=[];users=""
    try:
        resp = requests.get(url+"?feed=rss2").text
        wpUsers = re.findall("<dc:creator><!\[CDATA\[(.+?)\]\]></dc:creator>", resp,re.IGNORECASE)
        if wpUsers:
            usernames = wpUsers + usernames
        #Enumerating Wordpress Usernames via "Author"
    except Exception as e:
        pass
    for user in range(1,20):
        try:
            resp = requests.get(url+"?author="+str(user)).text
            wpUser = re.findall("author author-(.+?) ", resp,re.IGNORECASE)
            if wpUser and wpUser not in usernames : 
                usernames = wpUser + usernames
            #wpUser = re.findall("/author/(.+?)/feed/", resp,re.IGNORECASE)
            #if wpUser : usernames = wpUser + usernames
        except Exception as e:
            print (e)
    #if usernames:
    for x in set(usernames):
        users=users+x+", "
    return users[:-2]
    #return sorted(set(usernames))
    #return [""]

def wp_forgotten_pass(url):
    # Username Enumeration via Forgotten Password
    # can't conquer captcha 
    try:
        query_args = {"user_login": "N0t3xist!1234"}
        data = urllib.parse.urlencode(query_args).encode("utf-8")
        req = urllib.request.Request(url+"wp-login.php?action=lostpassword")
        htmltext = urllib.request.urlopen(req,data=data).read()
        #print (htmltext)
        if re.findall(re.compile('Invalid username'),str(htmltext)):
            return url+"wp-login.php?action=lostpassword"
        return ""
    except Exception as e:
        print ("wp_forgotten_pass",e)
        return ""

def fingerprint_wp_version_hash_based(url):
    tree = etree.parse("Data/wp/wp_versions.xml")
    root = tree.getroot()
    version=[]
    try:
        # Iterating through 'src' file
        for i in range(len(root)):
            # Download file
            ddl_url  = (url + root[i].get('src') ).replace('$','')
            ddl_name = "/tmp/" + (root[i].get('src').replace('/','-'))
            #print (ddl_url, ddl_name)
            if requests.get(ddl_url).status_code == 200:
                core.download_file( ddl_url , ddl_name)
                # Get hash of the file
                ddl_hash = core.md5_hash(ddl_name)
                # Delete the file
                core.remove_file(ddl_name)
                # Iterating throug 'md5' hash
                for j in range(len(root[i])):
                    if "Element" in str(root[i][j]):
                        # Detect the version
                        if ddl_hash == root[i][j].get('md5'):
                            version.append(root[i][j][0].text)
                            #print ("WordPress version %s identified from advanced fingerprinting" % root[i][j][0].text)
        return sorted(set(version))
    except Exception as e:
        print ("fingerprint_wp_version_hash_based",e)
        return []

def fuzz_wp_component(target,component):
    components=[]
    try:
        with open('Data/wp/'+component+'.json') as data_file:
                data = json.load(data_file)
        for com in data.keys():
            x=target+"wp-content/"+component+"/"+com
            c=requests.get(x)
            #sys.stdout.write('\r')
            #sys.stdout.write(str(c))
            #sys.stdout.flush()
            print (x)
            if c.status_code ==200 and c.text != ("" or None):
                components.append(com)
        return components
    except Exception as e:
        print ("fuzz_wp_"+component,e)
        return []


def wp_path_disclosure(url):
    #u can use also wp-includes/rss-functions.php
    try:
        rss_file = url + 'wp-includes/rss.php'
        rss_source = requests.get(rss_file)
        if rss_source.status_code==200 and  rss_source.text != ("" or None):
            rss_source=rss_source.text
            #print (rss_source)
            path = re.findall(r'<b>(.*?)wp-includes/rss.php</b>', rss_source)
            if path != []:
                return rss_file
        tw_theme = url + 'wp-content/themes/twentyfifteen/index.php'
        theme_source = requests.get(tw_theme)
        if theme_source.status_code==200 and  theme_source.text != ("" or None):
            theme_source=theme_source.text
            #print (theme_source)
            path = re.findall(r'<b>(.*?)wp-content/themes/twentyfifteen/index.php</b>', theme_source)
            if path != []:
                return tw_theme
        tw_theme = url + 'wp-content/themes/twentysixteen/index.php'
        theme_source = requests.get(tw_theme)
        if theme_source.status_code==200 and  theme_source.text != ("" or None):
            theme_source=theme_source.text
            #print (theme_source)
            path = re.findall(r'<b>(.*?)wp-content/themes/twentysixteen/index.php</b>', theme_source)
            if path != []:
                return tw_theme
        tw_theme = url + 'wp-content/themes/twentyseventeen/index.php'
        theme_source = requests.get(tw_theme)
        if theme_source.status_code==200 and  theme_source.text != ("" or None):
            theme_source=theme_source.text
            #print (theme_source)
            path = re.findall(r'<b>(.*?)wp-content/themes/twentyseventeen/index.php</b>', theme_source)
            if path != []:
                return tw_theme
        return "" 
    except Exception as e:
        print ("wp_path_disclosure",e)
        return ""

def wp_check_user_registration(url): #Checking user registration status
    try:
        reg_url = url + 'wp-login.php?action=register'
        reg_source = requests.get(reg_url).text
        #print (reg_source)
        if 'Registration confirmation will be emailed to you' in reg_source or 'value="Register"' in reg_source or 'id="user_email"' in reg_source:
            #print ('User registration open: ' + reg_url )
            return reg_url
        return ""
    except Exception as e:
        print ("wp_check_user_registration",e)
        return ""

def wp_get_vulns(component,name):
    #name in [wordpresses,themes,plugins]
    lcomponent=[];plug_ver=""; vulns=[]
    headers = {'Authorization': 'Token token=pV3960fusFKH3dGAM47U1zA7AVGHSNVkviKVgwiHDfI'}
    if type(component)!=list:
        lcomponent.append(component)
    else:
        lcomponent=component
    for f in lcomponent:
        #f=f[0].replace(" ","")
        if type(f)==list:
            try:
                plug_ver=f[1]
            except:
                pass
            f=f[0]
        #f=f[0]
        g=f
        f=f.replace(".","")
        #print (f,g,plug_ver,1111111111)
        #print (f,"<<<<<<<<<<<<<<<<<<<<<<<<")
        try:
            r = requests.get('https://wpvulndb.com/api/v3/'+name+'/'+f, headers=headers)
            response = r.json()
            #print (r.url)
            if 'Not found' not in str(response) and "HTTP Token: Access denied" not in str(response):
                #print (response)
                for x in response[g]["vulnerabilities"]:
                    #print (x)
                    #print (x["references"].keys())
                    #print (g,plug_ver,x["fixed_in"])
                    if core.is_lower(plug_ver,x["fixed_in"]) :
                        #print (x["vuln_type"],x["title"],x["references"])
                        vuln=[]
                        if "exploitdb" in x["references"].keys():
                            for u in x["references"]["exploitdb"]:
                                vuln.append("Type: "+x["vuln_type"])
                                vuln.append("https://www.exploit-db.com/exploits/"+str(u))
                                vuln.append(x["title"])
                        elif "cve" in x["references"].keys():
                            for u in x["references"]["cve"]:
                                vuln.append("Type: "+x["vuln_type"])
                                vuln.append("https://www.cvedetails.com/cve/cve-"+str(u))
                                vuln.append(x["title"])
                        elif "url" in x["references"].keys():
                            for u in x["references"]["url"]:
                                vuln.append("Type: "+x["vuln_type"])
                                vuln.append(u)
                                vuln.append(x["title"])
                        elif "secunia" in x["references"].keys():
                            for u in x["references"]["secunia"]:
                                vuln.append("Type: "+x["vuln_type"])
                                vuln.append("https://secuniaresearch.flexerasoftware.com/community/advisories/"+str(u))
                                vuln.append(x["title"])
                        else:
                            vuln.append("Type: "+x["vuln_type"])
                            vuln.append(x["references"])
                            vuln.append(x["title"])
                        vulns.append(vuln)
        except Exception as e:
            print ("wp_get_component_vulns",e)
    #if vulns:
    return vulns
    #return [""]


def wp_additional_infos(target,theme,plugins):
    return [""]+[wp_users(target)]+[wp_forgotten_pass(target)]+[""]+[""]+[wp_path_disclosure(target)]+[wp_check_user_registration(target)]+[core.dirs_listing("wp",target,theme,plugins)]
    #check_wp_default_files(target)
    #wp_t4rgets=["https://iran-cyber.net","https://wparena.com","https://guggenheim.org/","http://mtvgreece.gr/","https://wordpress.com/","http://derbycon.com/","http://m-csc.com/","http://www.thefashionspot.com/"]
#"https://generatewp.com",
#print (wp_add_infos)
"""
for x in wp_t4rgets:
    if x[len(x)-1] != '/':
            x=x+"/"
    print (x)
    print (wp_additional_infos(x))
#================================= Moooore FUNctions 
"""

def cms_id_robots(url):
    url = url + 'robots.txt'
    robotstr = str((url))
    if robotstr!= '':
        if 'If the Joomla site is installed' in robotstr or 'Disallow: /administrator/' in robotstr:
            return 'joomla'
        if 'Allow: /core/*.css$' in robotstr or 'Disallow: /index.php/user/login/' in robotstr or 'Disallow: /web.config' in robotstr:
            return 'drupal'
        if 'Disallow: /wp-admin/' in robotstr or 'Allow: /wp-admin/admin-ajax.php' in robotstr:
            return 'wordpress'
        else:
            print ("robots.txt not found or empty!")


def cms_id_headers(headers):
        if '/wp-json/' in headers:
            return 'WordPress'
        elif 'X-Drupal-' in headers or '19 Nov 1978 05' in headers:
            ## Drupal [the date is interesting isn't it? just google it ;) ]
            return 'drupal'
        elif 'Expires: Wed, 17 Aug 2005 00:00:00 GMT' in headers:
            ## This is the only weird but common header i noticed in joomla Sites
            return 'joomla'


def cms_id_source_code(s, site): 
    if '/wp-content/' in hstring:
        return "WordPress"
    elif 'src="/misc/drupal.js"' in hstring:
        return "Drupal"
    elif 'css/joomla.css' in hstring:
        return "Joomla"

