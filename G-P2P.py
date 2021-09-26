import random
import sys
import threading
import tkinter
from tkinter import PhotoImage, ttk, font, messagebox, Tk
import socket
from threading import Thread
import pickle
import time
from tkinter.constants import END, FALSE
from urllib.parse import urlparse
import urllib.request, urllib.parse, urllib.error
from xml.dom.minidom import parseString
from xml.dom.minidom import Document
import http.client
import re
import ipaddress
import stun
import upnpy
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

#main GUI parameters
mainwindow = tkinter.Tk()
InputFrameRow1 = tkinter.Frame(mainwindow)
progressbar = tkinter.ttk.Progressbar(InputFrameRow1, orient="horizontal", mode="determinate", length=100)
InputFrameRow2 = tkinter.Frame(mainwindow, bg='red')
InputFrameRow3 = tkinter.Frame(InputFrameRow2)
IPString = tkinter.StringVar()
PortString = tkinter.StringVar()

#P2P parameters
receivedmetadata = False
peerCreated = False
continueOperatingthread = True
continuethread = True
list_receivingdatasocket_peers=[]
list_of_peers = []
publicaddress=""
thismasterport = random.randint(1024,49151)
FakeIP = '172.217.21.46'#'8.8.8.8'
FakePort = 80
BROADDACTDISCOVERYIP = '239.255.255.250'
BROADDACTDISCOVERYPORT = 1900
myself = "You are live"
Me = "Me"
offline = "You are offline"
numberofpeers = "Number of connected peers is: "
operatingthreadstarted = "Operating thread started.\n"
operatingthreadstopped = "Operating thread stopped.\n"
recevingthreadstarted = "Receiving thread started.\n"
receivingthreadstarted = "Receiving thread started.\n"
receivingthreadstopped = "Receiving thread stopped.\n"
lsnsocketcreated = "Listening socket created.\n"
portforwardsuccessful = "Port forward successful.\n"
portforwardfailed = "Main Port forward failed.\n"
tryNAT = "Trying Nat-PMP.\n"
UPNPPORTFORWARD = "Trying UPNP port forwarding.\n"
UPNPPORTFORWARDFAIL = "UPNP port forwarding failed.\n"
success = "Peer created.\n"
thispeerremoved = "This peer is disconnected.\n"
peerremoved = "A peer is disconnected.\n"
publicipstatement ="Please give this address to your peers if you want them to connect to you: "
failed = "Failed to initiate peer, please check your internet connection.\n"
NATFAIL = "Could not connect to NAT-PMP on port 5351.\n"
ATPORT = " at port "
successfulpeerconnection = "Peer connected successfuly.\n"
peerconnectedtoyou = "New peer connected from "
failpeerconnection = "Peer connection failed.\n"
failedtoconnect = "Peer failed to connect to you.\n"
IPwrongformat = "IP address not in the correct format.\n"
Portwrongformat = "Port not in the correct format.\n"
correctparameters = "Trying to connect peer.\n"
disconnecting = "Disconnecting now.\n"
local = "127.0.0.1"
newline = "\n"
indent = ">>> "
peerlabel = "Peer "
slash=" or "
zero = 0
alreadyconnected = "You are already connected.\n"
havetobeconnectedtopeer= "You have to be connected to a peer to send encryprted messages"
havetobeconnectedtitle = "Hello Peer"
createpeermessage="Please press on the Create Peer button and get connected before sending encrypted messages"
emptymessage = "Please enter a message before sending"
emptymessage = "Please enter text before sending"
emptymessagetitle = "Empty message"
threadstopped = "Thread stopped\n"
isoperatingthreadalive = False
maxValue = 100
twentyvalue = 20
fiftyvalue = 50
seventyyvalue = 70

private_key = rsa.generate_private_key(
    public_exponent=115792089237316195423570985008687907853269984665640564039457584007908834671663,
    key_size=2048,
    backend=default_backend())
public_key = private_key.public_key()
pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)

thispeer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
WAIT = 1
TCP = "TCP"
def UpdateLogList(message):
   LogList.config(state=tkinter.NORMAL)
   LogList.insert(tkinter.END, message)
   LogList.config(state=tkinter.DISABLED)
def operatingThread(peer): #only for receiving data
   UpdateLogList(operatingthreadstarted)
   global isoperatingthreadalive
   try:
      while continueOperatingthread:
         conn, addr = peer.accept()
         port = int.from_bytes(conn.recv(2),byteorder='big',signed=False)
         lsningaddr = list(addr)
         lsningaddr[1] = port
         lsningaddr = tuple(lsningaddr)
         sent = SendMetaData(conn)
         receivedpeerpkbytes = conn.recv(4096)
         list_receivingdatasocket_peers.append([lsningaddr,receivedpeerpkbytes])
         list_of_peers.append([conn,receivedpeerpkbytes])
         peerindex = str(len(list_of_peers)-1)
         if sent:
            UpdateLogList(peerconnectedtoyou+addr[0]+newline)
            t2 = Thread(target=ReceivingMediaThread, args=(conn,receivedpeerpkbytes, peerindex)) #start receiving data from the new connected peer
            t2.start()
            UpdateGUIListofPeers()
         else:
            UpdateLogList(failedtoconnect)
   except Exception as e:
         UpdateLogList(operatingthreadstopped) #need to disconnect this peer
         isoperatingthreadalive = False
         return True
def UpdateGUIListofPeers():
   x = len(list_of_peers)
   ListofPeers.delete(1,1)
   if x == 1 or x == 0:
      ListofPeers.insert(1, numberofpeers+str(zero))
   else: ListofPeers.insert(1, numberofpeers+ str(x-1))
def SearchChat(event):
   ListofMessages.tag_remove("found", '1.0', END)
   input = txtboxSearch.get()
   if input:
      idx = '1.0'
      while 1:
         idx = ListofMessages.search(input, idx,stopindex=END,nocase=1)
         if not idx: return
         starting_index =int(idx.split(".")[0])
         ending_index  = len(input)+int(idx.split(".")[1])
         coordinates = "{}.{}".format(starting_index, ending_index)
         ListofMessages.tag_add('found', idx, coordinates)
         ListofMessages.tag_config('found', font=(font.BOLD), foreground='red')
         idx = coordinates
   txtboxSearch.focus_set()
def SendInput():
   try:
      textinput = txtboxInput.get("1.0",'end-1c')
      if len(textinput) >0:
         txtboxInput.focus()
         txtboxInput.mark_set(tkinter.INSERT,'0.0')
         broadcast(textinput)
         return True
      else: 
         messagebox.showinfo(emptymessagetitle,emptymessage)
         return True
   except Exception as e:
      return False
def getexternalIPSTUN():
   try:
      nat_type, external_ip, external_port = stun.get_ip_info()
      if not ipaddress.ip_address(external_ip).is_private:
         return external_ip
   except Exception as e:
      return ""
   return ""
def upnpPublicIP():
   try:
      upnp = upnpy.UPnP()
      devices = upnp.discover()
      if len(devices) >0:
         device = upnp.get_igd()
         services = device.get_services()
         for service in services:
            try:
               actions = service.get_actions()
               output = service.GetExternalIPAddress()
               externaladdress = list(output.values())[0]
               return externaladdress
            except Exception as e:
               continue
      else: return ""
   except Exception as e:
      return ""
   return ""
def upnpAddPortMapping(address):
    successfulmap = False
    UpdateLogList(UPNPPORTFORWARD)
    upnp = upnpy.UPnP()
    devices = []
    try:
       devices = upnp.discover()
    except Exception as e:
       successfulmap = False
    if len(devices) > 0:
       device = upnp.get_igd()
       services = device.get_services()
       for service in services:
          try:
             actions = service.get_actions()
             res = service.AddPortMapping(
                NewRemoteHost='',
                NewExternalPort=thismasterport,
                NewProtocol=TCP,
                NewInternalPort=thismasterport,
                NewInternalClient=address[0],
                NewEnabled=1,
                NewPortMappingDescription='Port mapping entry from UPnPy.',
                NewLeaseDuration=0
                )
             if len(res) == 0:
                successfulmap = True
                UpdateLogList(portforwardsuccessful)
                return True
             else:
                successfulmap = False 
                return False
          except Exception as e:
             continue
       if successfulmap == False:
          UpdateLogList(UPNPPORTFORWARDFAIL)
          return False
    else:
       UpdateLogList(UPNPPORTFORWARDFAIL)
       return False  
def CreateIPforward(addresses):
   try:
      SSDP_ADDR = BROADDACTDISCOVERYIP
      SSDP_PORT = BROADDACTDISCOVERYPORT
      SSDP_MX = 2
      SSDP_ST = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
      ssdpRequest = "M-SEARCH * HTTP/1.1\r\n" + \
         "HOST: %s:%d\r\n" % (SSDP_ADDR, SSDP_PORT) + \
         "MAN: \"ssdp:discover\"\r\n" + \
         "MX: %d\r\n" % (SSDP_MX, ) + \
         "ST: %s\r\n" % (SSDP_ST, ) + "\r\n"
      sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      sock.sendto(ssdpRequest.encode(), (SSDP_ADDR, SSDP_PORT))
      time.sleep(WAIT)
      resp = sock.recv(1000)
      parsed = re.findall(r'(?P<name>.*?): (?P<value>.*?)\r\n', str(resp,'utf-8'))
      # get the location header
      location = [x for x in parsed if x[0].lower() == "location"]
      router_path = location[0][1]
      router_path = urlparse(router_path) 
      # get the profile xml file and read it into a variable
      directory = urllib.request.urlopen(location[0][1]).read()  #check here
      dom = parseString(directory)
      service_types = dom.getElementsByTagName('serviceType')
      path = ''
      for service in service_types:
         if service.childNodes[0].data.find('WANIPConnection') > 0:
            path = service.parentNode.getElementsByTagName('controlURL')[0].childNodes[0].data
      doc = Document()
      envelope = doc.createElementNS('', 's:Envelope')
      envelope.setAttribute('xmlns:s', 'http://schemas.xmlsoap.org/soap/envelope/')
      envelope.setAttribute('s:encodingStyle', 'http://schemas.xmlsoap.org/soap/encoding/')
      body = doc.createElementNS('', 's:Body')
      fn = doc.createElementNS('', 'u:AddPortMapping')
      fn.setAttribute('xmlns:u', 'urn:schemas-upnp-org:service:WANIPConnection:1')
      arguments = [
         ('NewExternalPort', str(thismasterport)), # specify port on router
         ('NewProtocol', 'TCP'),                 # specify protocol
         ('NewInternalPort', str(thismasterport)),           # specify port on internal host
         ('NewInternalClient', addresses[0]), # specify IP of internal host
         ('NewEnabled', '1'),                    # turn mapping ON
         ('NewPortMappingDescription', 'Ghazawi P2P'), # add a description
         ('NewLeaseDuration', '0')]
      argument_list = []
      for k, v in arguments:
         tmp_node = doc.createElement(k)
         tmp_text_node = doc.createTextNode(v)
         tmp_node.appendChild(tmp_text_node)
         argument_list.append(tmp_node)
      for arg in argument_list:
         fn.appendChild(arg)
      body.appendChild(fn)
      envelope.appendChild(body)
      doc.appendChild(envelope)
      pure_xml = doc.toxml()
      conn = http.client.HTTPConnection(router_path.hostname, router_path.port)
      conn.request('POST',path,pure_xml,{'SOAPAction': '"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"','Content-Type': 'text/xml'})
      resp = conn.getresponse()
      if resp.status == 200:
         UpdateLogList(portforwardsuccessful)
         return True
      else:
         UpdateLogList(portforwardfailed)
         UpdateLogList(tryNAT)
        # res = CreateNatPMPPortForward()
         res=False
         if res: UpdateLogList(portforwardsuccessful)
         if not res: UpdateLogList(NATFAIL)
         return res
   except Exception as e:
      UpdateLogList(str(e)+newline)
      UpdateLogList(tryNAT)
      res=False
      #res = CreateNatPMPPortForward()
      return res
def getInternalIP():
   try:
      ip = socket.gethostbyname(socket.gethostname())
      if ip == local:
         return False
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      s.connect((FakeIP, FakePort))
      addr = []
      addr.append(s.getsockname()[0])
      addr.append(s.getsockname()[1])
      s.close()      
      return addr
   except Exception as e:
      return False
def broadcast(message): 
    try:
      if len(list_of_peers) == 0:
          messagebox.showinfo(havetobeconnectedtitle,createpeermessage)
          return
      for i in range(len(list_of_peers)):
          try:
            if list_of_peers[i][0] != thispeer:
                     thispk = list_of_peers[i][1]
                     this_public_key = serialization.load_pem_public_key(thispk, backend=default_backend())
                     m = (message).encode()
                     encrypted = this_public_key.encrypt(m,padding.OAEP
                     (mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),label=None))
                     sock = list_of_peers[i][0]
                     sock.send(encrypted)
                     ListofMessages.config(state=tkinter.NORMAL)
                     ListofMessages.insert(tkinter.END,Me+indent+message+newline)
                     ListofMessages.config(state=tkinter.DISABLED)
                     ListofMessages.see(tkinter.END)
                     txtboxInput.delete('1.0',tkinter.END)
            elif len(list_of_peers) == 1:
               messagebox.showinfo(havetobeconnectedtitle,havetobeconnectedtopeer)
          except Exception as e:
             UpdateLogList(str(e))
             DisconnectPeer(thispk,sock)
             continue
    except Exception as e:
       DisconnectThisPeer()
       UpdateLogList(str(e))   
def CreatePeer(): #listening socket can only receive data to it
   try:
      startProgressBar()
      global isoperatingthreadalive
      try:
         address = getInternalIP()
         if address == False:
            UpdateLogList(failed)
            stopProgressBar()
            return False
      except Exception as e:
         UpdateLogList(failed)
         stopProgressBar()
         return False
      thispeer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      thispeer.bind((address[0], thismasterport))
      thispeer.listen()
      UpdateLogList(lsnsocketcreated)
      UpdateProgressBar(twentyvalue)
      T = threading.Thread(target=operatingThread, args=(thispeer,))
      isprivate =ipaddress.ip_address(address[0]).is_private
      if isprivate: #handle when IP is not private
         res =CreateIPforward(address) 
         if not res: 
            res =  upnpAddPortMapping(address) #CreateIPforward(address)#
         if res:
            UpdateProgressBar(fiftyvalue)
            T.start()
            isoperatingthreadalive = T.is_alive()
            list_receivingdatasocket_peers.insert(0,[thispeer.getsockname(),pem]) #insert public key of yourself
            list_of_peers.append([thispeer,pem])
            UpdateLogList(success)
            UpdateProgressBar(seventyyvalue)
            publicIPaddress = getexternalIPSTUN()
            if publicIPaddress == "":publicIPaddress = upnpPublicIP()
            if publicIPaddress != "":
               publicaddress = str(publicIPaddress)+slash+address[0]+ATPORT+str(thismasterport)+newline
               buttonCreatePeer.configure(command=DisconnectThisPeer, text="Disconnect")
               UpdateProgressBar(maxValue)
               stopProgressBar()
               buttonConnect.config(state=tkinter.NORMAL)
               buttonConnect.config(command=ConnectPeer)
               buttonSend.config(state=tkinter.NORMAL)
               UpdateLogList(publicipstatement+publicaddress+newline)
               ListofPeers.delete(0,0)
               ListofPeers.insert(0,myself)
            else:
               UpdateLogList(failed)
               ListofPeers.delete(0,0)
               ListofPeers.insert(0,offline)
               stopProgressBar()
               return
         else:
            UpdateLogList(failed)
            ListofPeers.insert(0,offline)
            stopProgressBar()
            return
      else:
         publicaddress = str(address[0]) +ATPORT+str(thismasterport)+newline
         buttonCreatePeer.configure(command=DisconnectThisPeer, text="Disconnect")
         UpdateProgressBar(maxValue)
         stopProgressBar()
         buttonConnect.config(state=tkinter.NORMAL)
         buttonConnect.config(command=ConnectPeer)
         buttonSend.config(state=tkinter.NORMAL)
         T.start()
         isoperatingthreadalive = T.is_alive()
         list_receivingdatasocket_peers.insert(0,[thispeer.getsockname(),pem]) #insert public key of yourself
         list_of_peers.append([thispeer,pem])
         UpdateLogList(publicipstatement+publicaddress+newline)
         ListofPeers.delete(0,0)
         ListofPeers.insert(0,myself)
   except Exception as e:
      UpdateLogList(str(e)+newline)
      ListofPeers.insert(0,offline)
      stopProgressBar()
      return
def UpdateProgressBar(currentValue):
   progressbar["value"]=currentValue
   mainwindow.update()
def startProgressBar():
   progressbar.grid()
   progressbar.start()
   mainwindow.update()
def stopProgressBar():
   progressbar.stop()
   progressbar.grid_remove()
   mainwindow.update()      
def DisconnectThisPeer():
   UpdateLogList(disconnecting)  #may need to kill the threads also
   global thispeer
   global continueOperatingthread
   try:
      for i in range(len(list_of_peers)):
            try:
               sock = list_of_peers[i][0]
               peerpk = list_of_peers[i][1]
               if peerpk != pem:
                  try:
                     sock.send(pem)
                     sock.close()
                  except Exception as e:
                     sock.close()
            except Exception as e:
               continue
      thispeer.close()
      list_of_peers.clear()
      list_receivingdatasocket_peers.clear()
      buttonCreatePeer.configure(command=CreatePeer, text="Create Peer")
      thispeer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      UpdateLogList(thispeerremoved)
      buttonConnect.config(state=tkinter.DISABLED)
      buttonSend.config(state=tkinter.DISABLED)
      ListofPeers.delete(0,0)
      ListofPeers.insert(0,offline)
      UpdateGUIListofPeers()
      return True
   except Exception as e:
      return True
def DisconnectPeer(pk,conn):
   try:
      #address = conn.getpeername()
      for i in range(len(list_receivingdatasocket_peers)):
         if list_receivingdatasocket_peers[i][1] == pk:
            list_receivingdatasocket_peers.pop(i)
            break
      for i, x in enumerate(list_of_peers):
         if pk in x:
            list_of_peers.pop(i)
            conn.close()
            break
      UpdateGUIListofPeers()
      UpdateLogList(peerremoved)
      return
   except Exception as e:
      return
def ReceivingMediaThread(conn, pk, peerindex):
   UpdateLogList(receivingthreadstarted)
   while continuethread:
      data = b""
      try:
            data += conn.recv(4096) #both video and audio
            if data == pem: 
               DisconnectPeer(pk, conn)
               UpdateLogList(receivingthreadstopped)
               return
            original_message = private_key.decrypt(data, padding.OAEP
            (
               mgf=padding.MGF1(algorithm=hashes.SHA256()),
               algorithm=hashes.SHA256(),
               label=None
            ))
            message = str(original_message, 'utf-8') #str(addr[0]) + ": " + str(message, 'utf-8')
            ListofMessages.config(state=tkinter.NORMAL)
            ListofMessages.insert(tkinter.END,peerlabel+str(peerindex)+indent+message+newline)
            ListofMessages.config(state=tkinter.DISABLED)
            ListofMessages.see(tkinter.END)
            data = b""
      except Exception as e: #might be the metadata
            DisconnectPeer(pk,conn)
            UpdateLogList(receivingthreadstopped)
            return
   DisconnectPeer(pk,conn)
   UpdateLogList(receivingthreadstopped)              
   return
def ConnectPeer(): 
   ip = False
   try:
      ipaddress.ip_address(IPString.get())
      ip = True
   except ValueError:  # no inet_pton here, sorry
      UpdateLogList(IPwrongformat)
      return False
   try:
      if 1 <= int(PortString.get()) <= 65535:
         if ip == True: UpdateLogList(correctparameters)
   except ValueError as e:
      UpdateLogList(Portwrongformat)
      return False
   try:
      global continuethread
      global receivedmetadata
      continuethread = True
      startProgressBar()
      x = len(list_receivingdatasocket_peers)
      check = []
      check.insert(0,[IPString.get(), int(PortString.get())])
      for y in range(x):
         if list_receivingdatasocket_peers[y][0][0] == check[0][0] and list_receivingdatasocket_peers[y][0][1] == check[0][1] :
            UpdateLogList(alreadyconnected)
            UpdateProgressBar(maxValue)
            stopProgressBar()
            return False
      peersocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      peersocket.connect((IPString.get(), int(PortString.get())))
      port = int(thismasterport).to_bytes(2, byteorder='big', signed=False)
      peersocket.send(port)
      #lock = threading.Lock()
      receivedmetadata = False
      ReceieveMetaData(peersocket)
      if receivedmetadata== True:
         peersocket.send(pem)
         UpdateProgressBar(fiftyvalue)
         txtboxIP.delete('0',tkinter.END)
         txtboxPort.delete('0',tkinter.END)
         #need to get the pk of connected peer:
         connectedpeerpk = b''
         for i in range(len(list_receivingdatasocket_peers)):
            if list_receivingdatasocket_peers[i][0][1] == peersocket.getpeername()[1]: #NEED TO CHANGE TO IP:PORT format
               connectedpeerpk = list_receivingdatasocket_peers[i][1]
               list_of_peers.append([peersocket,connectedpeerpk])
         t2 = Thread(target=ReceivingMediaThread, args=(peersocket,connectedpeerpk,str(len(list_of_peers)-1)))
         t2.start()
         UpdateGUIListofPeers()
         txtboxInput.focus()
         txtboxInput.mark_set(tkinter.INSERT,'0.0')
         UpdateLogList(successfulpeerconnection)
         UpdateProgressBar(maxValue)
         stopProgressBar()
      else:
         return False
   except Exception as e:
      UpdateLogList(failpeerconnection)
      stopProgressBar()
      return False
def SendMetaData(peer):
      try:
         list_receivingdatasocket_peers_bytes = pickle.dumps(list_receivingdatasocket_peers)
         peer.send(list_receivingdatasocket_peers_bytes)
         return True
      except Exception as e:
         return False
def ReceieveMetaData(peer):
      try:
         global receivedmetadata
         if receivedmetadata == False:
            received_list_of_peers_bytes = peer.recv(4096)
            global list_receivingdatasocket_peers
            merged_list_of_peers = []
            received_list_of_peers = pickle.loads(received_list_of_peers_bytes)
            merged_list_of_peers = list_receivingdatasocket_peers + received_list_of_peers
            temp_list = []
            for i in merged_list_of_peers:
               if i not in temp_list:
                  temp_list.append(i)
            list_receivingdatasocket_peers = temp_list
            receivedmetadata = True
            return True
         else:
            return False   
      except Exception as e:
         return False
def FocusOnSending(event):
   if event.keysym == "Tab":
      buttonSend.focus()
      return("break")
def FocusOnConnecting(event):
   if event.keysym == "Return":
      buttonConnect.focus()
      return("break")
def Connecting(event):
   ConnectPeer()
   txtboxInput.focus()
   txtboxInput.mark_set(tkinter.INSERT,'0.0')
   return("break")
def Sending(event):
   SendInput()
   return("break")
def onclosing():
    if messagebox.askyesnocancel("Quit", "Do you want to quit?"):
      startProgressBar()
      UpdateProgressBar(twentyvalue)
      DisconnectThisPeer()
      UpdateProgressBar(maxValue)
      stopProgressBar()
      mainwindow.destroy()
      sys.exit()
if __name__ == "__main__":
   mainwindow.grid()
   mainwindow.title("Welcome to the G-P2P network")
   mainwindow.protocol("WM_DELETE_WINDOW", onclosing)

   InputFrameRow1.grid(column=0, row=0, sticky='NSEW')
   InputFrameRow1.columnconfigure(7, weight=1)
        
   InputFrameRow2.grid(column=0, row=1, sticky='NSEW')
   InputFrameRow2.columnconfigure(1, weight=1)
   InputFrameRow2.rowconfigure(0, weight=1)
        
   InputFrameRow3 = tkinter.Frame(InputFrameRow2)
   InputFrameRow3.grid(column=0, row=0, sticky='NSEW')
   InputFrameRow3.columnconfigure(0, weight=1)
   InputFrameRow3.columnconfigure(1, weight=1)
   InputFrameRow3.rowconfigure(1, weight=1)
        
   InputFrameRow4 = tkinter.Frame(mainwindow)
   InputFrameRow4.grid(column=0, row=2, sticky='NSEW')
   InputFrameRow4.columnconfigure(1, weight=1)
   InputFrameRow4.rowconfigure(0, weight=1)

   mainwindow.columnconfigure(0, weight=1) 
   mainwindow.rowconfigure(1, weight=1)
       
   buttonCreatePeer = tkinter.Button(InputFrameRow1, text="Create Peer", command=CreatePeer)
   buttonCreatePeer.grid(column=0, row=0, sticky='w')
   lblIP = tkinter.Label(InputFrameRow1, text="Peer IP:")
   lblIP.grid(column=1, row=0, sticky='w')
   txtboxIP = tkinter.Entry(InputFrameRow1,width=20, textvariable=IPString)
   txtboxIP.grid(column=2, row=0, sticky='w')
   lblPort = tkinter.Label(InputFrameRow1, text="Peer Port:")
   lblPort.grid(column=3, row=0, sticky='w')
   txtboxPort = tkinter.Entry(InputFrameRow1,width=5, textvariable=PortString)
   txtboxPort.bind("<Tab>", FocusOnConnecting)
   txtboxPort.bind("<Return>", Connecting)
   txtboxPort.grid(column=4, row=0, sticky='w')
   buttonConnect = tkinter.Button(InputFrameRow1,text='Connect', state=tkinter.DISABLED, command=ConnectPeer)
   buttonConnect.grid(column=5, row=0, sticky='w')
   buttonConnect.bind("<Return>", Connecting)

   lblSearch = tkinter.Label(InputFrameRow1, text="Search:")
   lblSearch.grid(column=6, row=0, sticky='w')
   sv = tkinter.StringVar()
   txtboxSearch = tkinter.Entry(InputFrameRow1, textvariable=sv, width=50)
   txtboxSearch.grid(column=7, row=0, sticky='EW')
   txtboxSearch.bind("<KeyRelease>",SearchChat)

   ListofPeers = tkinter.Listbox(InputFrameRow3, height=2)
   ListofPeers.grid(column=0,row=0, sticky='NSEW')
   ListofPeers.insert(0,offline)
   ListofPeers.insert(1,numberofpeers + str(len(list_receivingdatasocket_peers)))

   LogList = tkinter.Text(InputFrameRow3, bg='black', fg='white', width=30, wrap=tkinter.WORD, state=tkinter.DISABLED)
   LogList.grid(column=0, row=1, sticky='NSEW',)
   ScrollBarLog = tkinter.Scrollbar(InputFrameRow3)
   ScrollBarLog.grid(column=1, row=1, sticky='NSEW')
   LogList.config(yscrollcommand=ScrollBarLog.set)
   ScrollBarLog.config(command=LogList.yview)
        
   ListofMessages = tkinter.Text(InputFrameRow2, width=100, wrap=tkinter.WORD, state=tkinter.DISABLED)
   ListofMessages.grid(column=1, row =0, sticky='NSEW')
   ScrollBar = tkinter.Scrollbar(InputFrameRow2)
   ScrollBar.grid(column=2, row=0, sticky='NSEW')
   ListofMessages.config(yscrollcommand = ScrollBar.set)
   ScrollBar.config(command=ListofMessages.yview)

   Inputlbl = tkinter.Label(InputFrameRow4, text="Message:", font=('Ariel',12, font.BOLD))
   Inputlbl.grid(column=0, row=0, sticky='w')
   txtboxInput = tkinter.Text(InputFrameRow4, height=4, state='normal', wrap=tkinter.WORD)
   txtboxInput.grid(column=1, row=0, sticky='EW')
   txtboxInput.bind("<Tab>", FocusOnSending)
   ScrollBarInput = tkinter.Scrollbar(InputFrameRow4)
   ScrollBarInput.grid(column=2, row=0, sticky='NSEW')
   txtboxInput.config(yscrollcommand=ScrollBarInput.set)
   ScrollBarInput.config(command=txtboxInput.yview)

   buttonSend = tkinter.Button(InputFrameRow4,text='Send', font=('Ariel',12, font.BOLD), bg='RoyalBlue1', width=10, borderwidth=5, command=SendInput, state=tkinter.DISABLED)
   buttonSend.grid(column=3, row=0, sticky='NSEW')
   buttonSend.bind("<Return>", Sending)

   mainwindow = tkinter.mainloop()
 