# Req: adb :S
#Req: pip3 install pure-python-adb
#Req: pip3 install PyYaml

import http.client
from adb.client import Client
import json
import yaml
import ssl
import sys

#HTTPS Client
class HTTPSClient:
	def __init__(self, domain):
		self.domain = domain
		

	def get(self,url):
		#No proxy
		self.conn = http.client.HTTPSConnection(self.domain)

		self.conn.request("GET",url)
		resp=self.conn.getresponse()
		respBody=resp.read()
		self.conn.close()
		ret = {"code": resp.status,"body":respBody}
		return ret


#Get packages using pure-python-adb
#Assuming only one device connected to the computer
class Pm:
	def __init__(self):
		c=Client()

		self.device=c.devices()[0]
		
		self.pkgs=[]

	def get_installed_pkgs(self):
		Out.step("Getting installed apps.....")
		op = self.pm_list()
		pkgs = self.device.shell("pm list packages").replace('package:','').split('\n')
		for p in pkgs:
			pkg=Package(p)
			#pm list returns an empty line
			if pkg.name !="":
				self.pkgs.append(pkg)
		return pkgs


	def pm_list(self):
		return self.device.shell("pm list packages")


class Package:
	def __init__(self,name):
		self.name = name
		self.koodous = Koodous()


###################################### Koodous
class Koodous:
	def __init__(self):
		self.httpC = HTTPSClient("api.koodous.com")
		self.malResults = []
		self.results = []
		self.tags = []
		self.rating = 0

	def check(self,pkg):
		self.pkg = pkg
		print(pkg+" ...... ", end="", flush=True)
		response = self.query(pkg)
		if response is not None:
			results = self.parseResponse(response)
			self.results = results
			self.analyze(results)
		
		
	def query(self,pkg):
		url='/apks?search=package_name:"'+pkg+'"'
		responceData = self.httpC.get(url)
		resp = responceData["body"]
		if responceData["code"] == 200:
			strTemp = str(resp)[2:]
			return  strTemp[0:len(strTemp)-1]
		else:
			OutBut.alarm("Error "+str(responceData["code"])+" in retrieving Koodous report for Package: "+pkg)
			return None



	def parseResponse(self,resp):
		#print("\n"+resp)
		resbonse = resp.replace("\\\"","'").replace("\\'", "'")
		dict1 = yaml.safe_load(resbonse)

		results = json.dumps(dict1['results'])
		dict2 = json.loads(results,object_hook = self.obj_creator)
		return dict2


	def obj_creator(self,d):
		return KoodResult(d['app'], d['displayed_version'], d['rating'], d['sha256'], d['tags'], d['analyzed'])


	def analyze(self,results):
		resNum = len(results)
		sameHash = False
		
		for r in results:
			if (r.rating < 0):
				self.malResults.append(r)

		for m in self.malResults:
			#print(m)
			if (m.tags not in self.tags):
				self.tags.append(m.tags)

		#Rating
		resNum=len(self.results)
		malNum=len(self.malResults)
		if resNum>0:
			self.rating = round(malNum/resNum *100,2)
		else:
			self.rating = 0


	def display_results(self):

		Out.bold(self.pkg+":")		
		

		Out.underline("Ratio of malicious to total results")
		#print(malNum+"/"+resNum+" --> "+str(int(malNum)/int(resNum))+" %")
		print(str(len(self.malResults))+"/"+str(len(self.results))+" --> "+str(self.rating)+" %")

		Out.underline("Koodous Tags:")
		print(self.tags)

		Out.underline("Koodous malicious results:")
		for m in self.malResults:
			print(m)


class KoodResult:
	def __init__(self,appName="",version="",rating="",sha2="",tags="", analyzed=""):
		self.appName=appName
		self.version = version
		self.rating = rating
		self.sha2 = sha2
		self.tags = tags
		self.analyzed = analyzed

	def __str__(self):
		a=''
		if(self.analyzed==True):
			a='\033[1m'+"Analyzed, check URL"+ '\033[0m'
		return "App Name: "+str(self.appName)+"\t Rating: "+str(self.rating)+"\t Url: https://koodous.com/apks/"+self.sha2+"\t "+a


class Out:
	@staticmethod
	def bold(text):
		print('\033[1m'+text+ '\033[0m')

	@staticmethod
	def header(text):
		eqs=""
		for x in range(len(text)):
			eqs +="=" 
		print("\n"+eqs)
		print('\033[1m'+text+ '\033[0m')
		print(eqs+"\n")

	@staticmethod
	def alarm(text):
		print('\033[91m'+text+ '\033[0m')


	@staticmethod
	def underline(text):
		print('\033[4m'+text+ '\033[0m')

	@staticmethod
	def step(text):
		print('\033[3m>>>>'+text+ '\033[0m')

################################################# Main #########################################

malApps=[]
safeApps = []


try:
	pm=Pm()
except IndexError:
	# No connected devices
	Out.alarm("No device detected. run adb devices -l to make sure that a device is available")
	sys.exit()

except ConnectionRefusedError:
	# ADB server not running
	Out.alarm("ADB Server might not be running... please execure \"adb start-server\" then rerun this script")
	sys.exit

#Probably ADB server is down
except RuntimeError as e:
	if str(e).index("Is adb running on your computer?") != 0:
		Out.alarm("Connection with ADB server failed")
		Out.step("Run \"adb start-server\" to restart ADB server then run joefinder again")
		sys.exit()

pkgs = pm.get_installed_pkgs()
Out.step("Checking reports on Koodous about installed apps.... ")
for pkg in pm.pkgs:
	pkg.koodous.check(pkg.name)
	if( len(pkg.koodous.malResults) > 0):
		malApps.append(pkg)
	else:
		safeApps.append(pkg)	

Out.header("Number of installed Apps:")
print(str(len(pkgs)))

Out.header("\"Safe\" Apps (No indication that they are malicious)")
for p in safeApps:
	print(p.name)

print("\n\nNumber: "+str(len(safeApps)))

Out.header("Apps that MIGHT be malicious")
sortedMalApps = sorted(malApps, key=lambda p: p.koodous.rating)
for p in sortedMalApps:
	p.koodous.display_results()
	print("\n")

print("\n\nNumber of suspicious apps:"+str(len(sortedMalApps)))



