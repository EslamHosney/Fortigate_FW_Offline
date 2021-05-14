# -*- coding: utf-8 -*-
"""
Created on Thu Sep 20 13:58:30 2018

@author: https://github.com/EslamHosney
"""
import netaddr
from Firewall import Firewall,WriteFile, ReadFile

class Fortinet(Firewall):
    
    def __init__(self,name,ip,username,password,configFile,routeFile):
        Firewall.__init__(self, name,ip,username,password,configFile,routeFile)
        self.type = "Fortinet"
        self.routeTable = self.getRouteTable()
        
    def getRouteTable(self):#Fortinet Done
        #Iterates through the Route file and return routeing table
        lineIndex = 0
        routeTable = {}
        while(lineIndex < len(self.routeFile)):
            buff = self.routeFile[lineIndex].split()
            if (len(buff) > 0):
                address = buff[1].split('/')[0] # checks if this lines contains IPv4 subnet
                if(netaddr.valid_ipv4(address)):#check if the IPv4 is valid to make sure that this line contains address
                    routeTable[netaddr.IPNetwork(buff[1])]=self.routeFile[lineIndex].split()[-1]# add the route to route table dictionary
            lineIndex += 1
        return routeTable
    
    def getRouteInterface(self,IP):#Fortinet Done
        #return the route Interface for a subnet and returns None if no route found even default, IP in netaddr IPv4 Network
        bestMatchInterface = None
        bestMatchSubnet = netaddr.IPNetwork("0.0.0.0/0")
#        bestMatchSize = bestMatchSubnet.size
        for subnet, interface in self.routeTable.iteritems():
#            print (subnet,interface)
            if ((IP in subnet) and (subnet.size <= bestMatchSubnet.size)):
#                print "Match"
                bestMatchInterface = interface
#                print bestMatchInterface
                bestMatchSubnet = subnet
#                bestMatchSize = subnet.size
        return bestMatchInterface
    
    def getIPZone(self,IP):#Fortinet Done
        #get routeInterface for IP and check the configFile for the Zone for this interface retun Zone
        interface = self.getRouteInterface(IP)
        #print interface
        zone = None
        if (interface == None):
            raise ValueError('No route found for this IP! please add route to the '+self.name+'_routes file and try again')
        for lineIndex in range(len(self.configFile)):
            if (self.configFile[lineIndex].find("config system zone") != -1 ):
                #print (self.configFile[lineIndex])
                for intIndex in range(lineIndex,len(self.configFile)):
                    if (self.configFile[intIndex].find('set interface') != -1 and self.configFile[intIndex].find(interface) != -1):
                        #print self.configFile[intIndex]
                        for index in range(intIndex,lineIndex,-1):
                            if (self.configFile[index].find('edit') != -1 ):
                                zone = self.configFile[index].split('"')[-2]
                                break
                        break
                break
        return zone
    
    def getAddressNames(self,zone,IP):#Fortinet Done Not correct
        #return addressNames
        addressNames = []
        for configLineIndex in range(len(self.configFile)):
            if (self.configFile[configLineIndex].find("config firewall address") != -1 ):
                addressLineStartIndex = configLineIndex
                for addressLineIndex in range(addressLineStartIndex,len(self.configFile)):
                    if (self.configFile[addressLineIndex].find('edit ') != -1 and len(self.configFile[addressLineIndex].split('"')) > 2):
                        lastAddress = self.configFile[addressLineIndex].split('"')[-2]
                        
                    if (self.configFile[addressLineIndex].find('set associated-interface ') != -1 and len(self.configFile[addressLineIndex].split('"')) > 2):
                        lastZone = self.configFile[addressLineIndex].split('"')[-2]
                        
                    if (self.configFile[addressLineIndex].find('set subnet '+str(IP.ip)+" "+str(IP.netmask)) != -1 ):
                        #print ("Here", zone, lastZone)
                        if (lastZone == zone):
                            addressNames.append(lastAddress)
        return addressNames
    
    
    def createAddress(self,addressName,zone,IP):#Fortinet Done
        #return config for address in the created config list and add it to the local file and config list
        lines = ['config firewall address',
                 'edit "'+addressName+'"',
                 'set associated-interface "'+zone+'"',
                 'set subnet '+str(IP.ip)+" "+str(IP.netmask),
                 'next',
                 'end']
        self.configFile += lines
        self.createdConfig += lines    
        WriteFile(self.name,lines)
        return addressName

    
    def getAppNames(self,startPort,endPort,protocol):
        # app ports could be written in 2 ways 222 or 222-222 so we check for both and then check for protocol return appNames
        if(startPort == endPort == protocol):
            return protocol
        
        appName = None
                           
        if (startPort == endPort):
            for lineIndex in range(len(self.configFile)):
                if (self.configFile[lineIndex].find("config firewall service custom") != -1 ):
                    for intIndex in range(lineIndex,len(self.configFile)):
                        if (self.configFile[intIndex] == "set "+protocol.lower()+"-portrange "+startPort):
                            #print self.configFile[intIndex]
                            for index in range(intIndex,lineIndex,-1):
                                if (self.configFile[index].find('edit') != -1 ):
                                    #print self.configFile[index]
                                    appName = self.configFile[index].split('"')[-2]
                                    break
                            break
                    break
         
        if (not startPort == endPort):
            for lineIndex in range(len(self.configFile)):
                if (self.configFile[lineIndex].find("config firewall service custom") != -1 ):
                    for intIndex in range(lineIndex,len(self.configFile)):
                        if (self.configFile[intIndex].find("set "+protocol.lower()+"-portrange "+startPort+"-"+endPort)!= -1):
#                            print self.configFile[intIndex]
                            for index in range(intIndex,lineIndex,-1):
                                if (self.configFile[index].find('edit') != -1 ):
#                                    print self.configFile[index]
                                    appName = self.configFile[index].split('"')[-2]
                                    break
                            break
                    break
        return appName
    
    def createApp(self,startPort,endPort,protocol,appName=None):#Fortinet Done
        #return app config
        if (not appName):
            if (startPort == endPort):
                appName = protocol.upper()+"_"+startPort
                lines = ['config firewall service custom',
                         'edit "'+appName+'"',
                         'set '+protocol.lower()+'-portrange '+startPort,
                         'next',
                         'end'] 
            else:
                appName = protocol.upper()+"_"+startPort+"-"+endPort
                lines = ['config firewall service custom',
                         'edit "'+appName+'"',
                         'set '+protocol.lower()+'-portrange '+startPort+'-'+endPort,
                         'next',
                         'end']            
        self.configFile += lines
        self.createdConfig += lines    
        WriteFile(self.name,lines)
        return appName
    
    def createPolicy(self,policyName,sourceZone,sourceAddressNames,destinationZone,destinationAddressNames,appNames):#Fortinet Done
        #add config of policy
        
        srcLine = ''
        dstLine = ''
        oldApps = []
        ID = "-1"
        
        buff = ''
        for address in sourceAddressNames:
            buff += ' "'+address+'"'
        srcLine = 'set srcaddr'+buff
        
        buff = ''
        for address in destinationAddressNames:
            buff += ' "'+address+'"'
        dstLine = 'set dstaddr'+buff
        #lines.append('set srcaddr'+buff)
        
        srcLine = 'set srcaddr "Corporate_Users"'
#        
        lines = []
        lines.append('config firewall policy')
        
        
        ID = self.getPolicy(srcLine,dstLine) # to be used in case i need to check if a policy already exists
        
        #print (dstLine)
        print ("Policy found "+str(ID))

        if (ID > -1):
            lines.append("edit "+ID)
            oldApps = self.getServicePolicyID(ID)
            #print (oldApps, appNames)
            #if ("".join(sorted(oldApps)) == "".join(sorted(appNames)):
            if((set(appNames).issubset(set(oldApps)))):#check if all the new Apps are included in the current policy or not
                return
            else:
                print (set(appNames).difference(set(oldApps)))
            appNames = oldApps+appNames
            appNames = list(set(appNames))
            buff = ''
            for service in appNames:
                buff += ' "'+service+'"'  
            lines.append('set service'+buff)
            lines.append('set comments "'+"Comment"+'"')
        
        else:
            lines.append('edit 0')
            lines.append('set srcintf "'+sourceZone+'"')#ENNPI-Servers-Zone"
            lines.append('set dstintf "'+destinationZone+'"')
            
            buff = ''
            for address in sourceAddressNames:
                buff += ' "'+address+'"'
            lines.append('set srcaddr'+buff)
            
            buff = ''
            for address in destinationAddressNames:
                buff += ' "'+address+'"'        
            lines.append('set dstaddr'+buff)
            
            lines.append('set action accept')
            lines.append('set schedule "always"')
            
            buff = ''
            for service in appNames:
                buff += ' "'+service+'"'  
            lines.append('set service'+buff)
            #lines.append('set comments "'+policyName+'"')
            lines.append('set comments "'+"Comment"+'"')
        
        lines.append('next')
        lines.append('end')
        self.createdConfig += lines
        self.configFile += lines
        WriteFile(self.name,lines)        
        return
    
    def createStaticRouteIP(self,IP,interface,nextHop):
        #return app config
        lines = ['config router static',
                 'edit 0',
                 'set dst '+str(IP.ip)+' '+str(IP.netmask),
                 'set gateway '+str(nextHop.ip)]
        if interface != None:
            lines.append('set device "'+interface+'"')
        lines.append('next')
        lines.append('end') 
        self.configFile += lines
        self.createdConfig += lines    
        WriteFile(self.name,lines)
        return lines
 
    
    
if __name__ == "__main__":
    ip = netaddr.IPNetwork('10.230.99.172')
#    print (str(ip))
    f = Fortinet("","","","",ReadFile('SF.txt'),ReadFile('SF_routes.txt'))
#    print f.getRouteInterface(netaddr.IPNetwork('10.230.216.1'))
#    print f.getIPZone(ip)
    #print f.getAddressNames(f.getIPZone(ip),ip)
    #ID = f.getPolicy('set srcaddr "IT6D6BD" "cs7w9td"','set dstaddr "10.230.214.87" "10.230.214.88" "10.230.214.89" "10.230.214.90" "10.230.214.91" "CXX_Milage_APP_Server_Mgt_IP" "CXX_Milage_DB_Server_Mgt_IP"')
    #print ID , f.getServicePolicyID('319')
    f.getPolicyServiceLen('set srcaddr "Corporate_Users"', '', 8)
    