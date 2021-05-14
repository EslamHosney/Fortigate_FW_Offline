# Fortigate_FW_Offline
This project is created to provide a Python class providing most of the syntax to be used by developers to automate Fortigate FW configuration (policies, create addresses, read addresses,...) working on an offline configuration copy) limiting the impact on performance and live nodes.

## How To Use

To clone and run the examples you'll need:
* [Python2](https://www.python.org/downloads/)
* [pip](https://pip.pypa.io/en/stable/installing/)
* [netaddr](https://pypi.org/project/netaddr/)

From your command line:

```bash

# Clone this repository
$ git clone https://github.com/EslamHosney/Fortigate_FW_Offline.git

# Go into the repository

# Install dependencies
$ pip install -r requirements.txt

# use the below syntax to import Fortinet class to be used
from Fortinet_FW import Fortinet

```


## Prerequisites

* Install python dependencies
* create an object from Fortinet class with teh required data to be used in your code
```
  firewall = Fortinet(name,ip,username,password,ReadFile('FW_Name.txt'),ReadFile('FW_Name_routes.txt'))
```
  name,ip,username,password no manadatory could be replaced by empty str "" given the _configurationfile.txt and the _routes.txt are provided
  [extract_firewall_config](https://github.com/EslamHosney/extract_firewall_config.git) could be used to extract firewall configuration


## Environment

Tested on:
* Windows X 10
* python 2.7
* FortiOS 6.0

It should work on different environments, just keep in mind the versions above.


