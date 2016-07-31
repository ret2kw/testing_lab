import os
import re
#import docker handling code
import w4sp

import netifaces
import subprocess
import traceback
import time

from multiprocessing import Process

NSROOT = w4sp.ns_root

# import the Flask class from the flask module, try to install if we don't have it
try:
    from flask import Flask, render_template, request, jsonify
except:
    try:
        subprocess.check_call(['pip', 'install', 'flask'])
        from flask import Flask, render_template, request, jsonify

    except:
        subprocess.check_call(['apt-get', 'install', 'python-flask'])
        from flask import Flask, render_template, request, jsonify


# create the application object
app = Flask(__name__)
app.config.from_object(__name__)

def get_connections():
    """this should return all of the machines that are connected"""

    tmp = []

    for ns in w4sp.ns_root.ns:
        for nic in ns.nics:
            if 'root' in nic:
                yield 1,ns.pid
            for os in w4sp.ns_root.ns:
                if os != ns and nic in os.nics and nic not in tmp:
                    tmp.append(nic)
                    print('%s connected %s' % (ns.pid,os.pid))
                    yield ns.pid,os.pid



def psef(grep):
    """this is python replacement for ps -ef, based off of
        http://stackoverflow.com/questions/2703640/process-list-on-linux-via-python"""

    pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]

    for pid in pids:
        try:

            #read the command line from /proc/<pid>/cmdline
            with open(os.path.join('/proc', pid, 'cmdline'), 'rb') as cmd:
                cmd = cmd.read()
                if grep in cmd:
                    return pid, cmd

        #if the proc terminates before we read it
        except IOError:
            continue

    return False




# use decorators to link the function to a url
@app.route('/')
def launcher():

    dockers = []

    for docker in NSROOT.ns:
        dockers.append(docker)

    return render_template('launcher2.html', dockers=dockers)


@app.route('/getnet')
def getnet():
    """This returns the nodes and edges used by visjs, node = { 'id': ns.pid, 'label': ns.name, 'title': ip_address }
        edges = { 'from': ns_connected_from, 'to': ns_connected_to }""" 

    data = {}
    data['nodes'] = []
    data['edges'] = []

    for ns in w4sp.ns_root.ns:
        tmp = {}
        tmp['id'] = ns.pid
        tmp['label'] = ns.name
    
        if ns.name == 'inet':
            tmp['color'] = 'rgb(0,255,0)'

        tmp_popup = ''
        for ips in ns.get_ips():
            # { 'nic' : ip }
            tmp_popup += '%s : %s <br>' % ips.popitem()

        tmp['title'] = tmp_popup 
        data['nodes'].append(tmp)

    tmp_popup = ''
    #now add the root ns
    for ips in w4sp.ns_root.get_ips():
        tmp_popup += '%s : %s <br>' % ips.popitem()

    data['nodes'].append({'id' : 1, 'label' : ' kali ', 'color' : 'rgb(204,0,0)', 'title' : tmp_popup})

    for f,t in get_connections():
        tmp = {}
        tmp['from'] = f
        tmp['to'] = t
        data['edges'].append(tmp)

    print(data)
    return jsonify(**data)



@app.route('/runshark', methods=['POST', 'GET'])
def runshark():
    """this runs wireshark within the network namespace"""

    error = None
    if request.method == 'POST':
        print('[*] POST IN RUNSHARK')
        for key in request.form.keys():
            if request.form[key] == '1':
                w4sp.runshark('root')
            for ns in NSROOT.ns:
                if ns.pid == request.form[key]:
                    print ns.pid
                    print ns.name
                    w4sp.runshark(ns.name)

    return 'launched'


@app.route('/setup')
def setup():
    """start the network"""

    if len(NSROOT.ns) >= 1:
        return 'REFRESH'

    try:
        w4sp.setup_network2('eth0')
        time.sleep(3)
        return 'REFRESH'
 
    except:
        print(traceback.format_exc())
        return 'ERROR'


@app.route('/mitm')
def mitm():
    """this connects vic3 to the root ns so we can mitm it"""

    #should add a check to see if vic3 already exists
    if w4sp.c('vic3'):
        return 'ERROR'

    NSROOT.register_ns('vic3', 'w4sp/labs:victims')
    w4sp.c('vic3').connect(w4sp.ns_root)

    for nic in netifaces.interfaces():
        if 'root' in nic:
            w4sp.r('ip link set $nic down')
            w4sp.r('ip link set $nic name vic3')
            w4sp.r('ip link set vic3 up')

    return 'ok'
    

@app.route('/is_ips')
def is_ips():
    """quick check to see if suricata is running"""

    if psef('suricata'):
        return 'ok',200
    else:
        return 'error',404



@app.route('/ips')
def ips():
    """this starts suricata if it isn't running"""
  
    if psef('suricata'):
        return 'error',404

    #if sw2 isn't even up then we need to bail
    if not w4sp.c('sw2'):
        return 'error',404

    #here I need to start up ELK, then suricata, then logstash
    #check if ELK is running and if not start it
    if not w4sp.c('elk'):
        NSROOT.register_ns('elk', 'w4sp/labs:elk')
        #connect elk container to sw2 container
        w4sp.c('elk').connect(w4sp.c('sw2'))

    #now start suricata on sw1
    w4sp.c('sw1').dexec('suricata -i br0')
    #also start up logstash
    w4sp.c('sw1').dexec('/opt/logstash/bin/logstash -f /etc/logstash/conf.d/logstash.conf')
    return 'ok'



@app.route('/sploit')
def sploit():
    """this starts up and connects the sploitable instance"""

    #if sploit is already created, just bail
    if w4sp.c('sploit'):
        return 'error', 404

    #create the sploitable container and connect to sw2
    NSROOT.register_ns('sploit', 'w4sp/labs:sploitable')
    w4sp.c('sploit').connect(w4sp.c('sw2'))
    return 'ok'


@app.route('/elk')
def elk():
    """this is just to start up ELK if we want to run it without the IPS"""

    #if elk already exists, bail
    if w4sp.c('elk'):
        return 'error',404
    
    #other create and connect up elk
    NSROOT.register_ns('elk', 'w4sp/labs:elk')
    #connect elk container to sw2 container
    w4sp.c('elk').connect(w4sp.c('sw2'))
    return 'ok'


@app.route('/wifi')
def wifi():
    """this sets up and configures the wireless docker
        we are going to explicitly ignore the iw help and 
        screenscrape the output to get our interface names
        this function is going to make a lot of assumptions
        thar be dragons"""

    #check if the wifi docker is already running
    if w4sp.c('wifi'):
        #if it check if the cleartext hostapd is running
        if psef('hostapd_clear'):
            return 'wifi already running', 404

        #if hostapd isn't running lets start it
        else:
            w4sp.c('wifi').dexec('hostapd /hostapd_clear.conf')
            return 'ok1'

    #count of interfaces discovered and var for nic name
    count = 0
    phy = False

    #our regex to find phy%d
    match = re.compile('phy\d')
  
    #get iw output
    iwo = subprocess.check_output(['iw', 'list'])

    for line in iwo.split():
        #find they phy interface number
        if match.search(line):
            count += 1
            phy = line.strip()


    #check that we got one and only one phy
    if count >= 2:
        return 'got more than one phy interface, remove one wireless device', 500

    if not phy:
        return 'didn''t find a valid phy, please check wifi device connection', 500
            
    #we get here we should have a valid phy name
    #we are going to spin up the wireless container
    NSROOT.register_ns('wifi', 'w4sp/labs:wireless')
    #connect wifi container to sw2
    w4sp.c('wifi').connect(w4sp.c('sw2'))

    #no we need to move our wifi nic into the container
    cmd = 'iw phy %s set netns %s' % (phy, w4sp.c('wifi').pid)
 
    try:
        subprocess.call(cmd.split(' '))
        #ugh, delaying so setup_wifi.py can catch the new interface :/
        time.sleep(0.01)
        w4sp.c('wifi').dexec('hostapd /hostapd_clear.conf')
        return 'ok'

    except:
        return 'error moving wireless device to container', 500



@app.route('/wpa2')
def wpa2():
    """this sets up and configures the wireless docker
        we are going to explicitly ignore the iw help and 
        screenscrape the output to get our interface names
        this function is going to make a lot of assumptions
        thar be dragons"""

    #check if the wifi docker is already running
    if w4sp.c('wifi'):
        #if it check if the cleartext hostapd is running
        if psef('hostapd_clear'):
            return 'wifi already running', 404

        #if hostapd isn't running lets start it
        else:
            w4sp.c('wifi').dexec('hostapd /hostapd_wpa2.conf')
            return 'ok1'

    #count of interfaces discovered and var for nic name
    count = 0
    phy = False

    #our regex to find phy%d
    match = re.compile('phy\d')

    #get iw output
    iwo = subprocess.check_output(['iw', 'list'])

    for line in iwo.split():
        #find they phy interface number
        if match.search(line):
            count += 1
            phy = line.strip()


    #check that we got one and only one phy
    if count >= 2:
        return 'got more than one phy interface, remove one wireless device', 500

    if not phy:
        return 'didn''t find a valid phy, please check wifi device connection', 500

    #we get here we should have a valid phy name
    #we are going to spin up the wireless container
    NSROOT.register_ns('wifi', 'w4sp/labs:wireless')
    #connect wifi container to sw2
    w4sp.c('wifi').connect(w4sp.c('sw2'))

    #no we need to move our wifi nic into the container
    cmd = 'iw phy %s set netns %s' % (phy, w4sp.c('wifi').pid)

    try:
        subprocess.call(cmd.split(' '))
        w4sp.c('wifi').dexec('hostapd /hostapd_clear.conf')
        return 'ok'

    except:
        return 'error moving wireless device to container', 500



@app.route('/shutdown')
def shutdown():
    """cleans up mess"""

    w4sp.ns_root.shutdown()
    time.sleep(3)
    return ''


# start the server with the 'run()' method
if __name__ == '__main__':

    #see if we can run docker
    try:
        images = subprocess.check_output(['docker', 'images']).split('\n')
    except (OSError,subprocess.CalledProcessError) as e:

        #if e is of type subprocess.CalledProcessError, assume docker is installed but service isn't started
        if type(e) == subprocess.CalledProcessError:
            subprocess.call(['service', 'docker', 'start'])
            images = subprocess.check_output(['docker', 'images']).split('\n')

        elif e.errno == os.errno.ENOENT:
            # handle file not found error, lets install docker
            subprocess.call(['apt-get', 'update'])
            subprocess.call(['apt-get', 'install', '-y', 'docker.io', 'bridge-utils', 'debootstrap'])
            subprocess.call(['service', 'docker', 'start'])
            images = subprocess.check_output(['docker', 'images']).split('\n')
            
        else:
            # Something else went wrong
            raise
    


    try:
        tmp_n = 0
        for image in images:
            if 'w4sp/labs' in image:
                tmp_n += 1
        #basic check to see if we have at least six w4sp named images
        if tmp_n > len(os.listdir('images')):
            print('[*] w4sp/labs images available')

        else:
            print('[*] Not enough w4sp/labs images found, building now')
            #nasty hack for the sploitable vm, need to run debootstrap first
            subprocess.call(['debootstrap',
                             '--arch', 'i386', 
                             'hardy', 'images/sploitable/hardy-chroot', 
                             'http://old-releases.ubuntu.com/ubuntu'])
            w4sp.docker_build('images/')

    except:
        #just a placeholder
        raise


    w4sp.docker_clean()

    #app.jinja_env.globals.update(get_connections=get_connections)

    #subprocess.call(['iceweasel', '127.0.0.1:5000'])

    app.run(debug=True)


