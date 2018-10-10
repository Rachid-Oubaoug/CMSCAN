#!/usr/bin/env python3
# encoding: UTF-8
from flask import Flask, render_template, redirect, make_response
from flask_weasyprint import HTML, render_pdf
from flask_wtf import FlaskForm
from wtforms import SubmitField
from wtforms.validators import DataRequired, Length

from flask import Flask, flash, url_for, session, request, logging
#from data import Articles
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps

import core, re, hashlib, json, datetime, requests
import wpscan as wps
import joomscan as jms
import drupscan as drs

app=Flask(__name__)
app.config['SECRET_KEY']='cxny7912810xr9u23'
# Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'a'
app.config['MYSQL_DB'] = 'cmscan'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
# init MYSQL
mysql = MySQL(app)


# Register Form Class
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')


# User Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # Create cursor
        cur = mysql.connection.cursor()

        # Execute query
        cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)", (name, email, username, password))

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('You are now registered and can log in', 'success')

        return redirect(url_for('login'))
    return render_template('register.html', form=form)


# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get Form Fields
        username = request.form['username']
        password_candidate = request.form['password']

        # Create cursor
        cur = mysql.connection.cursor()

        # Get user by username
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['password']

            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                return redirect(url_for('scan'))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)
            # Close connection
            cur.close()
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('login.html')

# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


def cmscan(target): # u can id cms via: Generator meta tag - source code - robots.txt - headers
    #try:
    #if target[len(target)-1] != '/':
    #   target=target+"/"
    if not target.endswith("/"):
        target=target + "/"
    if not re.match(r"^http", target):
        target = "http://" + target
    #if "http://" not in target and "https://" not in target:
    #   target = "http://" + target
    wp=jml=drpl=0
    soup=str(core.get_page(target)).lower()
    heads=core.get_http_headers_and_ip(target)
    #print (soup)
    for l in soup.split(" "):
        if "wp-" in l:
            wp+=1
        elif "joomla" in l:
            jml+=1
        elif "drupal" in l:
            drpl+=1
    #print (wp,jml,drpl)
    if wp>jml and wp>drpl:
        theme=wps.wp_drupal_theme_id(target)
        plugins=wps.get_wp_plugins(target)
        version,found=wps.wp_get_version(target)
        vulns=wps.wp_get_vulns(version,"wordpresses")+wps.wp_get_vulns(theme,"themes")+wps.wp_get_vulns(plugins,"plugins")
        ads=wps.wp_additional_infos(target,theme,plugins)
        return ["WordPress",version,theme,plugins,heads,vulns,ads,found]
    elif drpl>jml and drpl>wp:
        theme=drs.wp_drupal_theme_id(target)
        plugins=drs.get_drupal_plugins(target)
        version,found=drs.drupal_get_version(target)
        vulns=drs.get_dru_core_vulns(version)+drs.get_dru_mod_vulns(target,plugins)
        ads=drs.dru_additional_infos(target,theme,plugins)
        return ["Drupal",version,theme,plugins,heads,vulns,ads,found] 
    elif jml>wp and jml>drpl:
        version,found=jms.joomla_get_version(target)
        theme=jms.joomla_theme_id(target)
        plugins=jms.get_joomla_plugins(target)
        vulns=jms.get_joo_core_vulns(version)+jms.get_joo_com_vulns(plugins)
        ads=jms.joo_additional_infos(target,theme,plugins)
        return ["Joomla",version,theme,plugins,heads,vulns,ads,found]
    else:
        #print (target, wp,jml,drpl)
        return 0
    #except Exception as e:
    #    print ("cmscan",e)
    #    return ["###","###","###","###","###"]

def get_exploits(cms):
    exploits = []
    expFile    = "Data/joo/files_exploits.csv"
    with open(expFile,"r") as f:
        for line in f:
            if cms in line.lower():
                line=line.strip()
                if '"' in line: 
                    sline=line.replace('"','')
                else:
                    sline=line.replace("'","")
                sline=sline.replace("[","");sline=sline.replace("]","")
                sline=sline.split(",")
                exploit=[]
                exploit.append(sline[3].replace("'","")) #date
                exploit.append(sline[0].replace("'","")) #id
                exploit.append(sline[2]) #desc
                exploit.append(sline[1].split("/")[len(sline[1].split("/"))-1].replace("'","")) #download
                exploits.append(exploit)
    return sorted(exploits)[::-1],len(exploits)

def need_to_update_cms(cms,version):
    if cms=="WordPress" and core.is_lower(version,"4.9.8"):
        return True,"4.9.8"
    elif cms=="Joomla" and core.is_lower(version,"3.8.12"):
        return True,"3.8.12"
    elif cms=="Drupal" and core.is_lower(version,"8.6.0"):
        return True,"8.6.0"
    else:
        return False,""

def store_scan_results(cms_list):
    now = datetime.datetime.now()
    cms_list=cms_list+[now.strftime("%Y-%m-%d %H:%M")]
    json_file=open('db.json', 'r')
    json_data = json.load(json_file)
    not_found=True
    for x in json_data:
        if x[:-1]==cms_list[:-1]:
            not_found=False
    if not_found:
        with open('db.json', 'r') as json_file:
            oldData = json.load(json_file)
        with open('db.json', 'w+') as json_file:
            # convert from Python dict-like structure to JSON format
            data = oldData.append(cms_list)
            jsoned_data = json.dumps(oldData, indent=True)
            json_file.write(jsoned_data)


def get_all_scans_results():
    results=[]
    json_file=open('db.json', 'r')
    json_data = json.load(json_file)
    for key,i in zip(json_data,range(len(json_data))):
    	results.append([i+1]+key)
    return results

def get_one_scan_results(sid):
    json_file=open('db.json', 'r')
    json_data = json.load(json_file)
    i=1
    for key in json_data:
        if i==int(sid):
            return key
        i+=1

def delete_scan(sid):
    newData=[]
    i=1
    with open('db.json', 'r') as json_file:
        oldData = json.load(json_file)
    for x in oldData:
        if i!=int(sid):
            newData.append(x)
        i+=1
    #print (newData)
    with open('db.json', 'w+') as json_file:
        jsoned_data = json.dumps(newData, indent=True)
        json_file.write(jsoned_data)


@app.route("/scan", methods=['GET', 'POST'])
def scan():
    form = scan_form()
    if form.validate_on_submit():
        cms=cmscan(form.site.data)
        if cms==0:
            return render_template('index.html', form=form)
        store_scan_results(cms)
        update,latest_ver=need_to_update_cms(cms[0],cms[1])
        json_file=open('db.json', 'r')
        json_data = json.load(json_file)
        return render_template('scan.html',site=form.site.data,form=form,cms=cms,update=update,latest_ver=latest_ver,len=len(json_data))
    return render_template('index.html', form=form)


@app.route("/db")
def db():
    scans=get_all_scans_results()
    length=len(scans)
    return render_template('db.html',scans=scans,lenn=length)

@app.route("/db/<sid>")
def db_(sid):
    cms=get_one_scan_results(sid)
    update,latest_ver=need_to_update_cms(cms[0],cms[1])
    return render_template('onescan.html',cms=cms,update=update,latest_ver=latest_ver,sid=sid)

@app.route("/db/del/<sid>")
def delete(sid):
    delete_scan(sid)
    return redirect("db")

@app.route("/", methods=['GET', 'POST'])
@app.route("/about")
def about():
    return render_template('about.html')

@app.route("/exploits")
def exploits():
    wp_exp,wp_len=get_exploits("wordpress")
    joo_exp,joo_len=get_exploits("joomla")
    dru_exp,dru_len=get_exploits("drupal")
    return render_template('exploits.html',wp_exp=wp_exp,wp_len=wp_len,dru_exp=dru_exp,dru_len=dru_len,joo_exp=joo_exp,joo_len=joo_len)

@app.route("/exploit/<eid>")
def exploit(eid):
    exploit=get_exploit(eid)
    return render_template('exploit.html',exp=exploit)

@app.route("/crawler",methods=['GET', 'POST'])
def crawler_():
    form = crawl_form()
    if form.validate_on_submit():
        urls=[]
        resp=requests.get("http://api.hackertarget.com/pagelinks/?q="+form.site.data).text
        for x in resp.split("\n"):
            if "/" in x and form.site.data in x:
                urls.append(x)
        target=form.site.data
        if not target.endswith("/"):
            target=target + "/"
        if not re.match(r"^http", target):
            target = "http://" + target
        #if "http://" not in target and "https://" not in target:
        #   target = "http://" + target
        wp=jml=drpl=0
        soup=str(core.get_page(target)).lower()
        #print (soup)
        for l in soup.split(" "):
            if "wp-" in l:
                wp+=1
            elif "joomla" in l:
                jml+=1
            elif "drupal" in l:
                drpl+=1
        if wp>jml and wp>drpl:
            iurls=wps.check_wp_default_files(target)
            return render_template('crawling.html',form=form,urls=sorted(set(urls)),iurls=iurls)
        elif drpl>jml and drpl>wp:
            iurls=drs.check_dru_default_files(target)
            return render_template('crawling.html',form=form,urls=sorted(set(urls)),iurls=iurls)
        elif jml>wp and jml>drpl:
            iurls=jms.check_joo_default_files(target)
            return render_template('crawling.html',form=form,urls=sorted(set(urls)),iurls=iurls)
        else:
            return render_template('crawling.html',form=form,urls=sorted(set(urls)))
    return render_template('crawler.html',form=form)
"""
@app.route("/crawler/<url>")
def crawler(url):
    page=""
    resp=requests.get("https://api.hackertarget.com/pagelinks/?q="+url).text
    for x in resp.split("\n"):
        page=page+x+(" <br> ")
    return page
"""
@app.route("/pdf/<sid>")
def pdf(sid):
    cms=get_one_scan_results(sid)
    update,latest_ver=need_to_update_cms(cms[0],cms[1])
    rendered = render_template('pdf.html',cms=cms,update=update,latest_ver=latest_ver)
    return render_pdf(HTML(string=rendered))

@app.route("/terminal")
def terminal():
    return render_template('terminal.html')

class scan_form(FlaskForm):
    site = StringField('Enter site to scan',validators=[DataRequired(), Length(min=2, max=40)])
    submit = SubmitField('START SCAN')

class crawl_form(FlaskForm):
    site = StringField('Enter site to crawl',validators=[DataRequired(), Length(min=2, max=40)])
    submit = SubmitField('CRAWL')



"""
wp_t4rgets=["http://www.thefashionspot.com/","https://guggenheim.org/","http://mtvgreece.gr/","https://wparena.com",
"https://wordpress.com/","http://derbycon.com/"]#,"http://m-csc.com/"]
joo_t4rgets=["http://emi.um5.ac.ma","http://www.joomla.org","http://grabcad.ir/bitumen/","http://gosaonline.co.za/"]
dru_t4rgets=["http://ensias.um5.ac.ma","https://www.linux.com/"] #"https://gsas.harvard.edu/" "http://drupal.org",

desc=["[+] CMS:","[+] VERSION:","[+] THEME:","[+] PLUGIN:", "[+] Headers:", "[+] VULNERABILITY:"]#,"[+] ADDITIONAL_INFOS:"]


default_files
users
forgotten_pass
joo_find_admin_login_page
joo_check_user_registration
wp_path_disclosure
wp_check_user_registration
dirs_listing

for x in wp_t4rgets:
    print (x)
    for l,d in zip(cmscan(x),desc):
        if type(l)==list:
            for y in l:
                print (d,y)
        else:
            print (d,l)
    #for l in cmscan(x):
    #    print (l)
    #cmscan(x)
    #print("\n")
"""

if __name__ == "__main__":
	app.run(host='0.0.0.0', port=5000, debug=True)
