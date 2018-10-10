#!/usr/bin/python3
import urllib.parse, re, os#, csv
#import sys, os,http
import urllib.request, requests, socket, hashlib
from bs4 import BeautifulSoup

"""
if len(sys.argv) != 2:
  sys.stderr.write('Usage ./spider.py T@rg3t\n')
  sys.exit(1)
t4rget=sys.argv[1]
"""


#proxyDict = {"http"  : "http://10.23.201.11:3128","https" : "https://10.23.201.11:3128"}
#url=urllib.parse.urlsplit(t4rget)



"""
if not os.path.exists(url[1]+"/"):
	os.makedirs(url[1])
	
if os.path.isfile(url[1]+"/"+url[1]+".urls"):
	os.remove(url[1]+"/"+url[1]+".urls")
urlsfile= open(url[1]+"/"+url[1]+".urls", "a")

if os.path.isfile(url[1]+"/"+url[1]+".html"):
	os.remove(url[1]+"/"+url[1]+".html")
reportfile= open(url[1]+"/"+url[1]+".html", "a")

reportfile.write("<!DOCTYPE html><html><head>	<title>"+url[1]+" Report </title></head><body>")

"""


def get_page(target):
	try:
		#.encode('utf8')
		req = urllib.request.Request(target)
		"""
		if "https" in target:
			req.set_proxy('https://10.23.201.11:3128', 'https')
		else:
			req.set_proxy('http://10.23.201.11:3128', 'http')
		"""
		f = urllib.request.urlopen(req)
		##soup = BeautifulSoup(f,"html.parser",from_encoding="iso-8859-1")
		soup = BeautifulSoup(f,"lxml",from_encoding="iso-8859-1")
		return soup
	except Exception as e:
		try:
			return requests.get(target).text
		except Exception as e:
			#raise e
		#print (str(e)+" > "+target)
			print ("get_page",e)
			return ""

def check_index(target):
	resp = requests.get(target).text
	dirList = re.search("<title>Index of", resp,re.IGNORECASE)
	if dirList:
		return target


def dirs_listing(cms,target,theme,plugins): #Checking for Directory Listing
	dirs_list=[];d=[]
	try:
		if cms=="wp":
			dirs=["wp-content/uploads/", "wp-content/plugins/", "wp-content/themes/",'wp-includes/','wp-admin/']
			d=check_index(target+'wp-content/'+theme)
			if d:
				dirs_list.append(d)
			url='wp-content/plugins/'
		elif cms== "joo":
			dirs=['administrator/','bin/','cache/','cli/','components/','images/','includes/','language/','layouts/',
			'libraries/','media/','modules/','plugins/','templates/','tmp/','administrator/components',
			'administrator/modules','administrator/templates','images/stories','images/banners']
			url='components/'
		else:
			dirs=['includes/','misc/','modules/','profiles/','scripts/','sites/','includes/','themes/']
			url='modules/'
		for x in dirs:
			d=check_index(target+x)
			if d:
				dirs_list.append(d)
		for p in plugins:
			p=p.replace(" ","-")
			d = check_index(target+url+p)
			if d:
				dirs_list.append(d)
	except Exception as e:
		print (e)
	return dirs_list


def union(a,b): #If a=[1,2,3] b=[2,3,4]. After union(a,b) makes a=[1,2,3,4] and b=[2,3,4]
	for e in b:
		if e not in a:
			a.append(e)
	return a

def hasNumbers(inputString):
	return any(char.isdigit() for char in inputString)


def download_file(url, filename):
	try:

		# Open the request
		source = requests.get( url).text

		# Write the file
		with open( filename, 'wb' ) as ddl_file:
			ddl_file.write(source.encode('utf8'))

	except Exception as e:
		raise e


def remove_file(filename):
	try:
		os.remove(filename)
	except Exception as e:
		raise e


def md5_hash(filename):
	return hashlib.md5(open(filename, 'rb').read()).hexdigest()


def is_lower(a,b):
	if b:
		la=a.split(".")
		lb=b.split(".")
		if len(la)<len(lb):
			for x in range(len(lb)-len(la)):
				la.append("0")
		elif len(lb)<len(la):
			for x in range(len(la)-len(lb)):
				lb.append("0")
		for x,y in zip(la,lb):
			if x < y:
				return True
			elif x > y:
				return False
	return False
	

def get_files(target,crawled):
	soup=get_page(target)
	url=urllib.parse.urlsplit(target)
	fileslst=[]
	#print (soup)
	try:
		for link in soup.find_all(re.compile("(img|script)"), src=True):
			x = urllib.parse.urljoin(target, link['src'])
			#print ("==> File:",x)
			if url[1] in x and x not in fileslst and x not in crawled:
				fileslst.append(x)
				#print ("==> File:",x)
		for link in soup.find_all('link', href=True):
			x = urllib.parse.urljoin(target, link['href'])
			#print ("==> File:",x)
			if url[1] in x and x not in fileslst and x not in crawled:
				fileslst.append(x)
				#print ("==> File:",x)
		return fileslst
	except Exception as e:
		return ""
		#print (e)



def get_links(target):
	soup=get_page(target)
	url=urllib.parse.urlsplit(target)
	lst=[]
	try:
		for link in soup.find_all('a', href=True):
			x = urllib.parse.urljoin(target, link['href'])
			if url[1] in x:
				lst.append(x)
		return lst
	except Exception as e:
		print (e,"links")
		return ""


def Crawl_web(target):
	tocrawl=[target]
	crawled=l=[]
	while tocrawl != []:
		p=tocrawl.pop(0)
		if p not in crawled:
			print (p[0:])
			f=get_links(p)
			union(tocrawl,f)
			crawled.append(p)
			print ("CRAWLED: ",len(crawled))
			print ("TO CRAWL: ",len(tocrawl))
			print (len(f))
	return crawled #Returns the list of links




	#except Exception as e:
	#	print ("cms_id",e)
		#print (wp,jml,drpl)
		#return "WP: "+str(wp)+"\nDrupal: "+str(drpl)+"\nJoomla: "+str(jml)

def get_http_headers_and_ip(url):
	server=powered_by=ip=""
	try:
		response =  urllib.request.urlopen(url)
		for x in response.getheaders():
			if "server" in x[0].lower():
				server=x[1]
			if "x-powered-by" in x[0].lower():
				powered_by=x[1]
		url=url.replace("//","")
		url=url.replace("https:","")
		url=url.replace("http:","")
		if url[len(url)-1] == '/':
			url=url[:len(url)-1]
	except:
		pass
	try:
		ip=socket.gethostbyname(url)
	except Exception as e:
		#print (e)
		pass
	return [server,powered_by,ip,url]


#DEPTH LIMIT
#execute_exploit !



"""
def match_vuln(cms):
	#print (cms)
	try:
		lst=[]
		desc=["Url: ","Description: ","Published: ","Type: ","Platform: "]
		with open('vulns/exploit-db.csv', 'r') as csvfile:
			spamreader = csv.reader(csvfile,delimiter=',')
			for row in spamreader:
				#print (row[2].lower())
				if cms.lower() in row[2].lower() :
					#lst.append("\n\t"+desc[1]+row[2]+"\n\t"+desc[0]+row[1]+"\n\t"+desc[2]+row[3]+"\n\t"+desc[3]+row[5]+"\n\t"+desc[4]+row[6])
					lst.append(desc[1]+row[2])
				if len(lst)>3:
					return "More than 3"
	except Exception as e:
		return ["No vulns"]
"""