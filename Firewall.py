# -*- coding: utf-8 -*-
"""
Created on Thu Sep 20 13:55:21 2018

@author: V17IAhmed36
"""
import datetime

def ReadFile(inFile):
    inFile += ""#".txt"
    with open(inFile, "r") as f:
        content = f.readlines()    
    content = [x.strip() for x in content]
    return (content)
    

def WriteFile(fileName,conFile):
    try:
        fileName = fileName+".txt"
        conf= open(fileName, "a")              
        for x in conFile:
          conf.writelines( x+"\n")
        conf.close()      
        return True   
    except:
        return False   
    return True


def getConfigFileType(configFile):
# returns srx or netscreen
    for line in configFile:
        if (line.find("set service ")!=-1):
            return "Netscreen"
        if (line.find("set applications ")!=-1):
            return "SRX"
        if (line.find("config firewall service custom")!=-1):
            return "Fortinet"               
    return 


class Firewall:

    def __init__(self, name,ip,username,password,configFile,routeFile):
        self.name = name
        self.ip = ip
        self.username = username
        self.password = password
        self.configFile = configFile#self.getConfigFile()
        self.routeFile = routeFile#self.getRouteFile()
        self.createdConfig = []
        
#    def getConfigFile(self):
#        return ReadFile(self.name)
#
#    def getRouteFile(self):
#        return ReadFile(self.name+"_routes")
    
    def getRouteTable(self):
        #return routeing table
        pass
    
    def getRouteInterface(self,IP):
        #return interface
        pass
    
    def getInterfaceZone(self,IP):
        #retun Zone
        pass
    
    def getAddressNames(self,zone,IP):
        #return addressNames
        pass
    
    def createAddress(self,addressName,zone,IP):
        #return config for address
        pass
    
    def getAppNames(self,startPort,endPort,protocol):
        #return appNames
        pass
    
    def createApp(self,startPort,endPort,protocol,appName=None):
        #return app config
        pass
    
    def createPolicy(self,policyName,sourceZone,sourceAddressNames,destinationZone,detinationAddressNames,appNames):
        #return config of policy
        pass
    
    def getAddressNamesIncludingIP(self,zone,IP):
        #return all addesses/address Groups that includes the IP
        pass
    
    def getAddressesSameIPZone(self):
        #return groups of dupliate addresses with the same IP and zone
        pass
    
    def createStaticRouteIP(self,IP,interface,nextHop):
        #return config for routing 
        pass
    