# ACI CATALOG : Redundency Plaftorm for Cisco ACI 

# Description

Our platform is designed to provide efficient management and retrieval of critical network data. It enables users to:

Retrieve information about endpoints, subnets, EPGs, tenants, bridgedomains, interfaces, and more.
Monitor and analyze network statistics and performance metrics.

# Installation

1) First of all , Install MySQL Server and set it up on port 3306
    link to mysql server : https://dev.mysql.com/downloads/installer/
                                                                               
2) Install the requirement package pip install -r requirements.txt 
    Install Python if dosent exist ofcourse :D
3) Run the project :                                                                              
    cd ACI_Catalog-1.0.0                                                                            
    python myapp.py                                                                                   
4) Open browser and type localhost:5000                                                                            

# Configuration
Using it for first time , You will be prompted a setup Page to configure Your Local SQL Server 
Else, you can modify those values by editing the .env folder in the root of the Folder

# Usage
Login with username and password. Add the APIC URL to connect to

Select from the top nav bar menu to show results of read only API queries to the APIC.                                                                                  

Use the search bar to filter result, click Search to see the result                                                         
