"""
    The below code is a Flask web application that connects to an APIC (Application Policy
    Infrastructure Controller) to retrieve endpoint and subnet data, stores it in a MySQL database, and
    displays it on different web pages.
    
    Made By Daly MR :D
    
"""

import requests
from dotenv import load_dotenv
from datetime import datetime
from flask import Flask, render_template, request, session, redirect
from flask_bootstrap import Bootstrap
import mysql.connector
import urllib3
import ipaddress
from acitoolkit import Tenant
import logging
import os


app = Flask(__name__)

# Disable the InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# Implement Bootstrap to App
bootstrap = Bootstrap(app)


"""
    This function injects the variables "user", "mysqlhost", and "sql" into the context of the Flask
    application, making them available in templates.
    :return: a dictionary with the variables `user`, `mysqlhost`, and `sql`. These variables will be
    available in templates as `user`, `mysqlhost`, and `sql`.

"""
@app.context_processor
def inject_user_and_host():
    # Replace these with the logic to get your username and mysql_host
    global user
    user = session["username"]
    global mysqlhost 
    if mycnx :
        sql = True
    # Return the variables you want to make available in templates
    return dict(user = user, mysqlhost = mysqlhost, sql = sql)



"""
The function `format_datetime` takes a datetime string in a specific format and returns a formatted
datetime string in a different format.

:param input_datetime: The input_datetime parameter is a string representing a datetime in the
format "YYYY-MM-DDTHH:MM:SS.ssssss+HH:MM"
:return: a formatted datetime string in the format "YYYY-MM-DD HH:MM:SS".
"""

def format_datetime(input_datetime):    # Parse the input string into a datetime object
    input_format = "%Y-%m-%dT%H:%M:%S.%f%z"
    datetime_obj = datetime.strptime(input_datetime, input_format)

    # Define the desired output format
    output_format = "%Y-%m-%d %H:%M:%S"

    # Format the datetime object as a string
    formatted_datetime = datetime_obj.strftime(output_format)

    return formatted_datetime


    
    
"""
Given an IP address, find the corresponding subnet from a database table.
@param ip_address - the IP address to search for
@return The subnet that the IP address belongs to, or None if not found.
"""



def find_subnet(ip_address):
    cursor = mycnx.cursor()
    # Query to retrieve the subnets from the "subnets" table
    query = "SELECT IPsubnet FROM subnets"
    cursor.execute(query)
    subnets = cursor.fetchall()

    # Iterate over each subnet and check if the IP address is within the subnet range
    for subnet in subnets:
        subnet_ip = subnet[0]  # Access the first element of the tuple
        network = ipaddress.IPv4Network(subnet_ip, strict=False)
        if ipaddress.ip_address(ip_address) in network:
            return subnet_ip
    return None  # Return None if no matching subnet is found




    """
 The function `get_unused_ips_in_subnet` takes a subnet query as input, retrieves a list of used IP
 addresses from a database, and returns a sorted list of unused IP addresses within the subnet.
 :param query: The `query` parameter is a string representing an IP network in CIDR notation. For
 example, "192.168.0.0/24" represents the IP network with a subnet mask of 255.255.255.0
 :return: a list of unused IP addresses in the specified subnet.
    """

def get_unused_ips_in_subnet(query):
    # Convert the query to IP network format
    ip_prefix = query.split('/')[0]
    network = ipaddress.ip_network(query, strict=False)

    cursor = mycnx.cursor()

    # Get a list of used IPs from the endpoints table
    used_ips_query = "SELECT DISTINCT IPendpoint FROM endpoints WHERE subnet LIKE %s"
    cursor.execute(used_ips_query, (f"{ip_prefix}/%",))
    used_ips = [str(ip[0]) for ip in cursor.fetchall()]

    # Create a set of all IP addresses in the subnet
    all_ips_in_subnet = set(ip for ip in network.hosts())

    # Remove used IPs from the set of all IPs
    unused_ips = all_ips_in_subnet - set(used_ips)

    # Convert IPv4Address objects to strings, sort them as IP addresses
    unused_ips_strings = sorted([ipaddress.IPv4Address(ip) for ip in unused_ips])

    return unused_ips_strings






    """
    The function calculates the number of possible devices in a given IP address prefix.
    
    :param ip_prefix: The `ip_prefix` parameter is a string that represents an IP address with its
    corresponding prefix length. The IP address and prefix length are separated by a forward slash
    ("/"). For example, "192.168.0.0/24" represents an IP address of "192.168.0
    :return: the number of possible devices that can be assigned IP addresses within the given IP
    prefix.
    """
    
def calculate_possible_devices(ip_prefix):
    try:
        ip_parts = ip_prefix.split('/')
        if len(ip_parts) != 2:
            return None  # Invalid input format
        
        ip_address = ip_parts[0]
        prefix_length = int(ip_parts[1])
        
        if prefix_length < 0 or prefix_length > 32:
            return None  # Invalid prefix length=
        
        usable_ips = 2 ** (32 - prefix_length) - 2
        return usable_ips

    except ValueError:
        return None  # Invalid input or calculation error









    """
    The above function is used to create and initialize tables in a MySQL database for storing
    information related to endpoints, subnets, EPGs, Tenants, BridgeDomains, ApplicationProfiles,
    interfaces, and interface statistics.
    :return: The function `get_database_connection()` returns a MySQL connection object (`mycnx`) if the
    connection is successful. If there is an error connecting to the database, it returns `None`.
    """
    
def get_database_connection():
    # Connect to MySQL server to create the database (use a temporary connection)
    temp_connection = mysql.connector.connect(
        host=mysql_host, user=mysql_username, password=mysql_password
    )
    temp_cursor = temp_connection.cursor()

    # Create the database if it doesn't exist
    temp_cursor.execute(f"CREATE DATABASE IF NOT EXISTS {mysql_database}")
    temp_connection.commit()

    # Close the temporary connection and cursor
    temp_cursor.close()
    temp_connection.close()

    try:
        mycnx = mysql.connector.connect(
            host=mysql_host,
            user=mysql_username,
            password=mysql_password,
            database=mysql_database,
        )
        return mycnx
    except mysql.connector.Error as e:
        # Handle database connection errors
        print("Error connecting to the database:", e)
        return None
    


# Connect to MySQL and initialize cursor
def initialize_database():
    try:
        cursor = mycnx.cursor()
    except mysql.connector.Error as e:
        # Handle database connection error
        logging.error("Error connecting to the database: %s", e)
        return None
        # Create table endpoints if it does not exist
    cursor.execute("CREATE DATABASE IF NOT EXISTS endpointer")
    # Switch to the 'endpointer' database
    cursor.execute("USE endpointer")
    try:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS endpoints (
                id INT PRIMARY KEY AUTO_INCREMENT,
                IPEndpoint VARCHAR(255) UNIQUE,
                MAC VARCHAR(255),
                RelEPG VARCHAR(255),
                RelAPP VARCHAR(255),
                relBD VARCHAR(255)
                subnet VARCHAR(255)
            )
        """
        )
    except mysql.connector.Error as e:
        logging.error("Error creating table 'endpoints': %s", e)
    # Create table subnets if it does not exist
    try:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS subnets (
                id INT PRIMARY KEY AUTO_INCREMENT,
                IPsubnet VARCHAR(255) UNIQUE,
                BD VARCHAR(255),
                Tenant VARCHAR(255),
                Scope VARCHAR(255)
            )
        """
        )
    except mysql.connector.Error as e:
        logging.error("Error creating table 'subnets': %s", e)
    # Create table EPGs if it does not exist
    try:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS EPGs (
                id INT PRIMARY KEY AUTO_INCREMENT,
                EPGName VARCHAR(255),
                TenantId VARCHAR(255),
                EndpointCount INT,
                appprof VARCHAR(255)
            )
        """
        )
    except mysql.connector.Error as e:
        logging.error("Error creating table 'EPGs': %s", e)
    # Create table Tenants if it does not exist
    try:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS Tenants (
                id INT PRIMARY KEY AUTO_INCREMENT,
                TenantId VARCHAR(255) UNIQUE,
                TenantName VARCHAR(255),
                Description VARCHAR(255),
                Scope VARCHAR(255)
            )
        """
        )
    except mysql.connector.Error as e:
        logging.error("Error creating table 'Tenants': %s", e)
    # Create table BridgeDomains if it does not exist
    try:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS BridgeDomains (
                id INT PRIMARY KEY AUTO_INCREMENT,
                BDName VARCHAR(255),
                bdtype VARCHAR(255) UNIQUE,
                iplearning VARCHAR(255),
                bpcast VARCHAR(255),
                tenant VARCHAR(255)
            )
        """
        )
    except mysql.connector.Error as e:
        logging.error("Error creating table 'BridgeDomains': %s", e)
        
    try:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS interfaces (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    PortName VARCHAR(255) UNIQUE,
                    Usages VARCHAR(255),
                    Speed VARCHAR(255),
                    layer VARCHAR(255),
                    admin_st VARCHAR(255)
                )
                """
            )
    except mysql.connector.Error as e:
        print("Error creating table 'interfaces':", e)
        
    try:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS interface_stats (
                id INT PRIMARY KEY AUTO_INCREMENT,
                PortId VARCHAR(255) UNIQUE,
                Switch VARCHAR(255),
                Interface VARCHAR(255),
                PortName VARCHAR(255),
                Speed VARCHAR(255),
                Instat VARCHAR(255),
                Outstat VARCHAR(255),
                PortEvents VARCHAR(255),
                LastEvent VARCHAR(255)
            )
            """
        )
    except mysql.connector.Error as e:
        print("Error creating table 'interface_stats':", e)

    # Commit the changes to the database and return the MySQL connection
    mycnx.commit()





"""
Connect to the APIC (Application Policy Infrastructure Controller) by sending a login request with the provided username and password.
If successful, retrieve the authentication token from the response and store it in the global variable `token`.
If an error occurs during authentication, print an error message. Finally, return the authentication token.
"""


def get_token(apic_url, username, password):
    print("Connecting to APIC...")
    authenerror = 0

    try:
        # Obtain webtoken
        login_url = f"{apic_url}/api/aaaLogin.json"
        login_payload = {"aaaUser": {"attributes": {"name": username, "pwd": password}}}
        response = requests.post(login_url, json=login_payload, verify=False, timeout=3)
        print("Connected!")
        global token
        token = response.json()["imdata"][0]["aaaLogin"]["attributes"]["token"]
  # Relocate token each 60 sec
    except Exception as authenerror:
        print(f"An unexpected error occurred during Authentification ")
    if authenerror:
        return None
    else:
        return token








    
    
        """
        The function `get_interfacevalue_stats` retrieves interface statistics data from an API, stores
        it in a MySQL database, and updates existing statistics if they already exist.
        :return: The function does not explicitly return any value.
        """
        
def get_interfacevalue_stats():
    cursor = mycnx.cursor()
    global token
    stats_url = f"{apic_url}/api/node/class/eqptIngrTotalHist15min.json"
    headers = {
        "Cookie": f"APIC-Cookie={token}"
    }
    try:
        response = requests.get(stats_url, headers=headers, verify=False)
        data = response.json()
    except requests.exceptions.RequestException as e:
        print("Error Inserting interface values ( function : get_interfacevalue_stats)", e)
        return
    
    # Store the interface statistics data in the MySQL database
    for item in data["imdata"]:
        attributes = item.get("eqptIngrTotalHist15min", {}).get("attributes", {})
        if not attributes:
            continue
        instat = round((float(attributes.get("bytesRateMin", ""))/8)/1000000, 3)
        outstat = round((float(attributes.get("bytesRateMax", ""))/8)/1000000,3)
        port_events = format_datetime(attributes.get("repIntvStart",""))
        last_event = format_datetime(attributes.get("repIntvEnd", ""))
        interface = attributes.get("dn", "").split("/sys/phys-")[1].split("]")[0]+"]"
        # Check if the interface statistics already exist in the database
        try:
            cursor.execute("SELECT * FROM interface_stats WHERE Interface = %s", (interface,))
            existing_stats = cursor.fetchone()
        except mysql.connector.Error as e:
            print("Error in checking existence: function (get_interfacevalue_stats)", e)
            continue

        if existing_stats:
            # If the interface statistics already exist, update them with the new information
            update_query = '''
            UPDATE interface_stats
            SET Instat = %s, Outstat = %s, PortEvents = %s, LastEvent = %s
            WHERE Interface = %s
            '''
            update_values = (
                instat, outstat, port_events, last_event, interface
            )
            try:
                cursor.execute(update_query, update_values)
            except mysql.connector.Error as e:
                print("Error in updating: function (get_interfacevalue_stats)", e)
        mycnx.commit()          
        
        
        
    """
    The function `get_interface_stats` retrieves interface statistics data from a specified URL and
    stores it in a MySQL database.
    :return: The function does not explicitly return anything.
    """    
        
    
def get_interface_stats():
    cursor = mycnx.cursor()
    global token
    # Send GET request to retrieve the interface statistics data
    interface_stats_url = f"{apic_url}/api/node/class/l1PhysIf.json?&order-by=l1PhysIf.modTs|desc"

    
    headers = {
        "Cookie": f"APIC-Cookie={token}"
    }

    try:
        response = requests.get(interface_stats_url, headers=headers, verify=False)
        data = response.json()
    except requests.exceptions.RequestException as e:
        print("Error: function (get_interface_stats)", e)
        return

    # Store the interface statistics data in the MySQL database
    for item in data["imdata"]:
        attributes = item.get("l1PhysIf", {}).get("attributes", {})
        if not attributes:
            continue

        switch = attributes.get("dn", "").split("/node-")[1].split("/")[0]
        interface = attributes.get("dn", "").split("/sys/phys-")[1]
        port_name = attributes.get("id", "")
        speed = attributes.get("speed", "")
        
        


        # Check if the interface statistics already exist in the database
        try:
            cursor.execute("SELECT * FROM interface_stats WHERE Interface = %s", (interface,))
            existing_stats = cursor.fetchone()
        except mysql.connector.Error as e:
            print("Error in checking existence: function (get_interface_stats)", e)
            continue

        if existing_stats:
            # If the interface statistics already exist, update them with the new information
            update_query = '''
            UPDATE interface_stats
            SET Switch = %s, PortName = %s, Speed = %s
            WHERE Interface = %s
            '''
            update_values = (
                switch, port_name, speed, interface
            )
            try:
                cursor.execute(update_query, update_values)
            except mysql.connector.Error as e:
                print("Error in updating: function (get_interface_stats)", e)
        else:
            # If the interface statistics do not exist, insert them into the database
            insert_query = '''
            INSERT INTO interface_stats
                ( Switch, Interface, PortName, Speed)
            VALUES
                ( %s, %s, %s, %s, %s)
            '''
            insert_values = (
                switch, interface, port_name, speed
            )
            try:
                cursor.execute(insert_query, insert_values)
            except mysql.connector.Error as e:
                print("Error in insertion: function (get_interface_stats)", e)

    mycnx.commit()




    """
    The function `get_interfaces` retrieves interface data from a specified URL, stores it in a MySQL
    database, and updates or inserts the data based on whether the interface already exists in the
    database.
    :return: The function does not explicitly return any value.
    """
    
def get_interfaces():
    cursor = mycnx.cursor()
    global token
    # Send GET request to retrieve the interface data
    interface_url = f"{apic_url}/api/node/class/l1PhysIf.json?&order-by=l1PhysIf.modTs|desc"
    headers = {
        "Cookie": f"APIC-Cookie={token}"
    }

    try:
        response = requests.get(interface_url, headers=headers, verify=False)
        data = response.json()
    except requests.exceptions.RequestException as e:
        print("Error: function (get_interfaces)", e)
        return

    # Store the interface data in the MySQL database
    for item in data["imdata"]:
        attributes = item.get("l1PhysIf", {}).get("attributes", {})
        if not attributes:
            continue
        
        port_name = attributes.get("id", "")
        usages = attributes.get("usage", "")
        speed = attributes.get("speed", "")
        layer = attributes.get("layer", "")
        admin_st = attributes.get("adminSt", "")

        # Check if the interface already exists in the database
        cursor.execute("SELECT MAX(id) FROM interfaces")
        last_inserted_id = cursor.fetchone()[0]
        # Set the initial ID value for the next insert
        next_id = last_inserted_id + 1 if last_inserted_id else 1
        try:
            cursor.execute("SELECT * FROM interfaces WHERE PortName = %s", (port_name,))
            existing_interface = cursor.fetchone()
        except mysql.connector.Error as e:
            print("Error in checking existence:  function (get_interfaces)", e)
            continue
        if existing_interface:
            # If the interface already exists, update its attributes with the new information
            update_query = '''
            UPDATE interfaces
            SET PortName = %s, Usages = %s,  Speed = %s,layer = %s, admin_st = %s
            WHERE PortName = %s
            '''
            update_values = (port_name, usages,  speed, layer, admin_st, port_name)
            try:
                cursor.execute(update_query, update_values)
            except mysql.connector.Error as e:
                print("Error in updating:  function (get_interfaces)", e)
        else:
            # If the interface does not exist, insert it into the database
            insert_query = '''
            INSERT INTO interfaces (id, PortName, Usages, Speed, layer, admin_st)
            VALUES (%s, %s, %s, %s, %s, %s)
            '''
            insert_values = (next_id, port_name, usages,  speed, layer, admin_st)
            try:
                cursor.execute(insert_query, insert_values)
            except mysql.connector.Error as e:
                print("Error in insertion:  function (get_interfaces)", e)

    mycnx.commit()
    
    




"""
This function retrieves the endpoints from a specified API endpoint and inserts them into a database table.
It uses a cursor object to execute SQL queries and a global token variable for authentication.
"""


def get_endpoints():
    cursor = mycnx.cursor()
    global token
    # Send GET request to retrieve the endpoint data
    endpoint_url = f"{apic_url}/api/class/fvCEp.json?rsp-subtree=children&rsp-subtree-class=fvIp"
    headers = {"Cookie": f"APIC-Cookie={token}"}
    try:
        response = requests.get(endpoint_url, headers=headers, verify=False)
        data = response.json()
    except requests.exceptions.RequestException as e:
        print("Error:  function (get_endpoints)", e)
        return
    # Store the endpoint data in the MySQL database
    for item in data["imdata"]:
        attributes = item.get("fvCEp", {}).get("attributes", {})
        if not attributes:
            continue
        ipendpoint = attributes.get("addr", "")
        # Check if the IP address is valid IPv4
        try:
            ipaddress.IPv4Address(ipendpoint)
        except ipaddress.AddressValueError:
            continue  # Skip invalid IPv4 addresses
        mac = attributes.get("dn", "").split("/cep-")[1].split("/")[0]
        rel_epg = attributes.get("dn", "").split("/epg-")[1].split("/")[0]
        rel_app = attributes.get("dn", "").split("/ap-")[1].split("/")[0]
        rel_bd = attributes.get("bdDn", "").split("uni/tn-")[1].split("/BD-")[1]
        subnet = find_subnet(ipendpoint)        # Check if the endpoint already exists in the database
        # Fetch the last inserted ID from the 'endpoints' table
        cursor.execute("SELECT MAX(id) FROM endpoints")
        last_inserted_id = cursor.fetchone()[0]
        # Set the initial ID value for the next insert
        next_id = last_inserted_id + 1 if last_inserted_id else 1
        try:
            cursor.execute(
                "SELECT * FROM endpoints WHERE IPEndpoint = %s", (ipendpoint,)
            )
            existing_endpoint = cursor.fetchone()
        except mysql.connector.Error as e:
            print("error in exist :  function (get_endpoints)")
            continue
        if existing_endpoint:
            # If the endpoint already exists, update itsattributes with the new information
            try:
                cursor.execute(
                    "UPDATE endpoints SET id = %sMAC = %s, RelEPG = %s, RelAPP = %s, relBD = %s, subnet = %s WHERE IPEndpoint = %s",
                    (next_id, mac, rel_epg, rel_app, rel_bd,subnet, ipendpoint),
                )
            except mysql.connector.Error as e:
                continue
        else:
            # If the endpoint does not exist, insert it into the database
            try:
                cursor.execute(
                    "INSERT INTO endpoints (id, IPEndpoint, MAC, RelEPG, RelAPP, relBD, subnet = %s) VALUES (%s, %s, %s, %s, %s, %s)",
                    (next_id, ipendpoint, mac, rel_epg, rel_app, rel_bd,subnet),
                )
            except mysql.connector.Error as e:
                print("error in insertion : function (get_endpoints)", e)
                continue
    mycnx.commit()




    """
    Retrieve subnets from the APIC and save them to a database table.
    @return None
    """

def get_subnets():
    global token
    cursor = mycnx.cursor()
    # Send GET request to retrieve the endpoint data
    subnet_url = (
        f"{apic_url}/api/node/class/fvSubnet.json?&order-by=fvSubnet.modTs|desc"
    )
    headers = {"Cookie": f"APIC-Cookie={token}"}
    response = requests.get(subnet_url, headers=headers, verify=False)
    data = response.json()
    # Store the endpoint data in the MySQL database
    for item in data["imdata"]:
        attributes = item.get("fvSubnet", {}).get("attributes", {})
        if not attributes:
            continue
        ip = attributes.get("ip", "")
        scope = attributes.get("scope", "")
        tenant = attributes.get("dn", "").split("/tn-")[1].split("/")[0]
        bd = attributes.get("dn", "").split("/BD-")[1].split("/")[0]
        cursor.execute("SELECT MAX(id) FROM subnets")
        last_inserted_id = cursor.fetchone()[0]
        # Set the initial ID value for the next insert
        next_id = last_inserted_id + 1 if last_inserted_id else 1
        # Insert the endpoint data into the "endpoints" table
        insert_query = """
        INSERT IGNORE INTO subnets (id,IPsubnet, BD, Tenant, Scope)
        VALUES (%s ,%s, %s, %s, %s)
        """
        insert_values = (next_id, ip, bd, tenant, scope)
        try:
            cursor.execute(insert_query, insert_values)
        except mysql.connector.errors.IntegrityError as e:
            print(" error when inserting into subnets table", e)
            continue
    # Commit the changes
    mycnx.commit()





"""
Retrieve the EPGs (Endpoint Groups) from the APIC (Application Policy Infrastructure Controller) and store them in a database.
@return None
"""

def get_epgs():
    global token
    cursor = mycnx.cursor()
    epg_url = f"{apic_url}/api/class/fvAEPg.json"
    headers = {"Cookie": f"APIC-Cookie={token}"}
    response = requests.get(epg_url, headers=headers, verify=False,timeout=15)
    epgs_data = response.json()
    for epg_data in epgs_data["imdata"]:
        epg_name = epg_data["fvAEPg"]["attributes"]["name"]
        tenant_id = (
            epg_data["fvAEPg"]["attributes"]["dn"].split("/tn-")[1].split("/")[0]
        )
        appprof = epg_data["fvAEPg"]["attributes"]["dn"].split('/ap-')[1].split('/')[0]
        # Additional API call to retrieve endpoint count for each EPG
        endpoint_url = f"{apic_url}/api/class/fvCEp.json?query-target-filter=eq(fvCEp.epgDn,'{epg_data}')"
        endpoint_response = requests.get(endpoint_url, headers=headers, verify=False)
        endpoint_data = endpoint_response.json()
        endpoint_count = len(endpoint_data["imdata"] )-1
        # Check if the EPG already exists in the database
        cursor.execute("SELECT MAX(id) FROM EPGs")
        last_inserted_id = cursor.fetchone()[0]
        next_id = last_inserted_id + 1 if last_inserted_id else 1
        try:
            cursor.execute("SELECT * FROM EPGs WHERE EPGName = %s", (epg_name,))
            existing_epg = cursor.fetchone()
        except mysql.connector.Error as e:
            print("Error in EPG exist: function (get_epgs)", e)
            continue

        if existing_epg:
            # If the EPG already exists, update its attributes with the new information
            try:
                cursor.execute(
                    "UPDATE EPGs SET id = %s, TenantId = %s,  EndpointCount = %s, approf = %s WHERE EPGName = %s",
                    (next_id, epg_name, tenant_id, endpoint_count,appprof, epg_name),
                )
            except mysql.connector.Error as e:
                print("Error updating EPG: function (get_epgs)", e)
                continue
        else:
            # If the EPG does not exist, insert it into the database
            try:
                cursor.execute(
                    "INSERT INTO EPGs (id,  EPGName, TenantId, EndpointCount,appprof) VALUES (%s, %s, %s, %s, %s)",
                    (next_id, epg_name, tenant_id, endpoint_count,appprof),
                )
            except mysql.connector.Error as e:
                print("Error inserting EPG: function (get_epgs)", e)
                continue

    # Commit the changes to the database
    mycnx.commit()




"""
Retrieve the bridge domains from the APIC controller and store them in a database table called "BridgeDomains". 
The function uses a global variable called "token" to authenticate the request to the APIC controller.
It creates a cursor object to interact with the database. It then constructs the URL to retrieve the bridge domains from the APIC controller and sets the necessary headers for the request.
The function sends a GET request to the APIC controller and retrieves the response data in JSON format. 
"""

def get_bridge_domains():
    global token
    cursor = mycnx.cursor()
    bd_url = f"{apic_url}/api/class/fvBD.json"
    headers = {"Cookie": f"APIC-Cookie={token}"}

    response = requests.get(bd_url, headers=headers, verify=False)
    bd_data = response.json()

    for bd_entry in bd_data["imdata"]:
        bd_name = bd_entry["fvBD"]["attributes"]["name"]
        bpCast = bd_entry["fvBD"]["attributes"]["bcastP"]
        bdtype = bd_entry["fvBD"]["attributes"]["type"]
        iplearning = bd_entry["fvBD"]["attributes"]["ipLearning"]
        tenant = (
            bd_entry["fvBD"]["attributes"]["dn"].split("/tn-")[1].split("/")[0]
        )

        # Check if the BridgeDomain already exists in the database
        cursor.execute("SELECT MAX(id) FROM BridgeDomains")
        last_inserted_id = cursor.fetchone()[0]
        next_id = last_inserted_id + 1 if last_inserted_id else 1

        try:
            cursor.execute("SELECT * FROM BridgeDomains WHERE BDName = %s", (bd_name,))
            existing_bd = cursor.fetchone()
        except mysql.connector.Error as e:
            print("Error in BridgeDomain exist: function (get_bridge_domains)", e)
            continue

        if existing_bd:
            # If the BridgeDomain already exists, update its attributes with the new information
            try:
                cursor.execute(
                    "UPDATE BridgeDomains SET id = %s, BDName = %s, bdtype = %s, iplearning = %s, bpCast = %s,tenant = %s WHERE BDName = %s",
                    (next_id, bdtype,iplearning, bpCast,tenant,bd_name),
                )
            except mysql.connector.Error as e:
                print("Error updating BridgeDomain: function (get_bridge_domains)", e)
                continue
        else:
            # If the BridgeDomain does not exist, insert it into the database
            try:
                cursor.execute(
                    "INSERT INTO BridgeDomains (id, BDName,bdtype, iplearning,bpcast,tenant) VALUES (%s, %s, %s, %s, %s,%s)",
                    (next_id, bd_name,bdtype, iplearning,bpCast,tenant),
                )
            except mysql.connector.Error as e:
                print("Error inserting BridgeDomain: function (get_bridge_domains)", e)
                continue

    # Commit the changes to the database
    mycnx.commit()





"""
Retrieve the list of tenants from the APIC controller and store them in a database.
@return None
"""

def get_tenants():
    global token
    cursor = mycnx.cursor()
    tenant_url = f"{apic_url}/api/class/fvTenant.json"
    headers = {"Cookie": f"APIC-Cookie={token}"}

    response = requests.get(tenant_url, headers=headers, verify=False)
    tenants_data = response.json()

    for tenant_data in tenants_data["imdata"]:
        tenant_dn = tenant_data["fvTenant"]["attributes"]["dn"]
        tenant_name = tenant_data["fvTenant"]["attributes"]["name"]
        description = tenant_data["fvTenant"]["attributes"].get("descr", "")
        scope = tenant_data["fvTenant"]["attributes"].get("lcOwn", "")

        # Check if the Tenant already exists in the database
        cursor.execute("SELECT MAX(id) FROM Tenants")
        last_inserted_id = cursor.fetchone()[0]
        next_id = last_inserted_id + 1 if last_inserted_id else 1

        try:
            cursor.execute("SELECT * FROM Tenants WHERE TenantId = %s", (tenant_dn,))
            existing_tenant = cursor.fetchone()
        except mysql.connector.Error as e:
            print("Error in Tenant exist: function (get_tenants)", e)
            continue

        if existing_tenant:
            # If the Tenant already exists, update its attributes with the new information
            try:
                cursor.execute(
                    "UPDATE Tenants SET id = %s, TenantName = %s, Description = %s, Scope = %s WHERE TenantId = %s",
                    (next_id, tenant_name, description, scope, tenant_dn),
                )
            except mysql.connector.Error as e:
                print("Error updating Tenant: function (get_tenants)", e)
                continue
        else:
            # If the Tenant does not exist, insert it into the database
            try:
                cursor.execute(
                    "INSERT INTO Tenants (id, TenantId, TenantName, Description, Scope) VALUES (%s, %s, %s, %s, %s)",
                    (next_id, tenant_dn, tenant_name, description, scope),
                )
            except mysql.connector.Error as e:
                print("Error inserting Tenant: function (get_tenants)", e)
                continue

    # Commit the changes to the database
    mycnx.commit()





    """
    This function retrieves details about a subnet and its related endpoints based on a search query.
    :return: the rendered template "subnet_dets.html" along with the query, search results for subnets,
    the number of possible endpoints, the list of unused IPs in the subnet, and the related endpoints.
    """
    
@app.route("/get_details_subnet", methods=["GET","POST"])
def get_dets_subnet():
    if "authenticated" not in session:
        return redirect("/login")
    cursor = mycnx.cursor()
    query = request.args.get("query", "")  # Get the search query from the URL parameter
    possible_end_nbr = calculate_possible_devices(query)

    search_query_subnet = """
        SELECT BD,Tenant,Scope FROM subnets
        WHERE IPsubnet LIKE %s 
    """
    search_values_subnet = tuple(["%" + query + "%"])
    cursor.execute(search_query_subnet, search_values_subnet)
    search_result_subnet = cursor.fetchall()
    
    search_query_endpoint = """
        SELECT IPendpoint from endpoints
        WHERE subnet LIKE %s 
    """
    search_values_endpoint = tuple(["%" + query + "%"])
    cursor.execute(search_query_endpoint, search_values_endpoint)
    rel_endpoints = cursor.fetchall()
    if not rel_endpoints  :
        rel_endpoints = "Subnet Clear or not Available"
    unused_ips = get_unused_ips_in_subnet(query)
    return render_template("subnet_dets.html", query=query, results=search_result_subnet,possible_end_nbr = possible_end_nbr, unused_ips = unused_ips,rel_endpoints = rel_endpoints)



    """
    This function is an endpoint that retrieves details of endpoints based on a search query and
    displays the results in an HTML template.
    :return: The code is returning the rendered template "endpoint_dets.html" with the following
    variables: query, results, and searched_subnet.
    """
    
@app.route("/get_details_endpoint", methods=["GET","POST"])
def get_dets_endpoint():
    if "authenticated" not in session:
        return redirect("/login")
    cursor = mycnx.cursor()
    query = request.args.get("query", "")  # Get the search query from the URL parameter
    searched_subnet = find_subnet(query)
    if searched_subnet == None :
        searched_subnet = "Not Found or Hidden"
    search_query = """
        SELECT RelEPG,relBD,MAC,RelApp FROM endpoints 
        WHERE IPEndpoint LIKE %s 
    """
    search_values = tuple(["%" + query + "%"])

    cursor.execute(search_query, search_values)
    search_result = cursor.fetchall()
    return render_template("endpoint_dets.html", query=query, results=search_result,searched_subnet= searched_subnet)



    """
    This function retrieves details of EPGs from a database based on a search query and renders the
    results in an HTML template.
    :return: the rendered template "epg_dets.html" along with the search query and search results.
    """

@app.route("/get_details_epgs", methods=["GET","POST"])

def get_dets_epg():
    if "authenticated" not in session:
        return redirect("/login")
    cursor = mycnx.cursor()
    query = request.args.get("query", "")  # Get the search query from the URL parameter
    search_query = """
        SELECT * FROM epgs
        WHERE EPGName LIKE %s 
    """
    search_values = tuple(["%" + query + "%"])

    cursor.execute(search_query, search_values)
    search_result = cursor.fetchall()
    return render_template("epg_dets.html", query=query, results=search_result)




    """
    This Python function retrieves details of bridgedomains and their related subnets based on a search
    query.
    :return: The code is returning the rendered template "bd_dets.html" with the following variables:
    - "query": the search query obtained from the URL parameter
    - "results": the search results from the "bridgedomains" table that match the search query
    - "rel_subs": the search results from the "subnets" table that match the search query
    """

@app.route("/get_details_bds", methods=["GET","POST"])

def get_dets_bd():
    if "authenticated" not in session:
        return redirect("/login")
    cursor = mycnx.cursor()
    query = request.args.get("query", "")  # Get the search query from the URL parameter
    search_query_bds = """
        SELECT * FROM bridgedomains
        WHERE BDName LIKE %s 
    """
    search_values_bds = tuple(["%" + query + "%"])

    cursor.execute(search_query_bds, search_values_bds)
    search_result_bds = cursor.fetchall()
    
    search_query_subs= """
        SELECT IPsubnet FROM subnets
        WHERE BD LIKE %s 
    """
    search_values_subs = tuple(["%" + query + "%"])
    cursor.execute(search_query_subs, search_values_subs)
    search_result_subs = cursor.fetchall()
    if not search_result_subs:
        search_result_subs = " Not Available or Empty "
    return render_template("bd_dets.html", query=query, results=search_result_bds, rel_subs = search_result_subs)
    
    
    
    """
    This function performs a search in a database based on a query and returns the results.
    :return: the rendered template "search_results.html" with the search query and search results as
    parameters.
    """ 

@app.route("/search", methods=["GET", "POST"])

def search():
    if "authenticated" not in session:
        return redirect("/login")
    query = request.args.get("query", "")  # Get the search query from the URL parameter
    # Perform the search in the database
    cursor = mycnx.cursor()
    results=""
    result=""
    search_query_endpoint = """
        SELECT * FROM endpoints 
        WHERE IPEndpoint LIKE %s 
    """
    search_values_end = tuple(["%" + query ])
    cursor.execute(search_query_endpoint, search_values_end)
    search_results_end = cursor.fetchall()
    
    search_query_epg = """
        SELECT * FROM epgs 
        WHERE EPGName LIKE %s 
    """
    search_values_epg = tuple(["%" + query ])
    cursor.execute(search_query_epg, search_values_epg)
    search_results_epg = cursor.fetchall()
    
    search_query_tenant = """
        SELECT * FROM tenants 
        WHERE TenantName LIKE %s 
    """
    search_values_ten = tuple(["%" + query ])
    cursor.execute(search_query_tenant, search_values_ten)
    search_results_ten = cursor.fetchall()
    
    search_query_interface = """
        SELECT * FROM interfaces
        WHERE PortName LIKE %s 
    """
    search_values_int = tuple(["%" + query ])
    cursor.execute(search_query_interface, search_values_int)
    search_results_int = cursor.fetchall()
    
    search_query_bridgedomain = """
        SELECT * FROM bridgedomains 
        WHERE BDName LIKE %s 
    """
    search_values_bd = tuple(["%" + query ])
    cursor.execute(search_query_bridgedomain, search_values_bd)
    search_results_bd = cursor.fetchall()
    
    search_query_subnet = """
        SELECT * FROM subnets 
        WHERE IPSubnet LIKE %s 
    """
    search_values_sub = tuple(["%" + query ])
    cursor.execute(search_query_subnet, search_values_sub)
    search_results_sub = cursor.fetchall()
    print (len(search_results_sub))
    if query == "":
        result = "noentry"
    elif search_results_sub  :
        result = "subnet"
        results = search_results_sub
    elif search_results_bd:
        result = "bd"
        results = search_results_bd
    elif search_results_end :
        result = "end"
        results = search_results_end
    elif search_results_epg :
        result = "epg"
        results = search_results_epg
    elif search_results_int :
        result = "inter"
        results = search_results_int
    elif search_results_ten :
        result = "tenant"
        results = search_results_ten

    return render_template("search_results.html", query=query, entry=result, results=results)



    """
    This Python function defines a route "/about" that renders the "about.html" template.
    :return: the rendered template "about.html".
    """

@app.route("/about")
def about():
        return render_template("about.html")


# Define routes for the Flask app
"""
This function is a route handler for the "/base" endpoint of a Flask application.
When a request is made to this endpoint, it renders the "base.html" template and returns the rendered HTML as the response.
"""


@app.route("/base")
def base():
    global user
    return render_template("base.html", user = user)


"""
This is a Flask route handler for the root URL ("/"). It checks if the "username" key is present in the session object and if its value is not equal to "limited". If either of these conditions is not met, it redirects the user to the "/login" URL. Otherwise, it continues with the execution of the route handler.
"""


@app.route("/")
def index():
    if myenv == False:
        return redirect("/setup")
    if "authenticated" not in session:
        return redirect("/login")
    elif not session["authenticated"]:
        return redirect("/limited") 
    else:
        return render_template("index.html")


"""
This function is a route handler for the "/logout" endpoint in a Flask application. 
"""


@app.route("/logout")
def logout():
    session.pop("authenticated", None)
    session.pop("password", None)
    session["username"] = ""
    return redirect("/login")


"""
This is a Flask route function that handles GET and POST requests to the "/endpoints" endpoint. 
"""


@app.route("/endpoints", methods=["GET", "POST"])
def endpoints():
    if "authenticated" not in session or not session["authenticated"]:
        return redirect("/login")
    cursor = mycnx.cursor()
    cursor.execute("SELECT * FROM endpoints ORDER BY id")
    data = cursor.fetchall()
    # Render the endpoints.html template with the endpoint data
    if request.method == "POST":
        if request.form.get("refresh"):
            # Retrieve the endpoint data from the APIC and store it in the database
            get_token(apic_url,session["username"],session["password"])
            get_endpoints()
            return redirect("/endpoints")
        elif request.form.get("logout"):
            # Clear the session and redirect to the login page
            session.pop("authenticated", None)
            return redirect("/login")
        elif request.form.get("home"):
            return redirect("/")
    return render_template("endpoints.html", data=data)



    """
    This function handles the "/interfaces" route, checks if the user is authenticated, retrieves
    interface data from a database, and renders the "interfaces.html" template with the data.
    :return: the rendered template "interfaces.html" with the data variable passed to it.
    """

@app.route("/interfaces", methods=["GET", "POST"])
def interfaces():
    if "authenticated" not in session or not session["authenticated"]:
        return redirect("/login")
    cursor = mycnx.cursor()
    cursor.execute("SELECT * FROM interfaces ORDER BY id")
    data = cursor.fetchall()

    # Render the endpoints.html template with the endpoint data
    if request.method == "POST":
        if request.form.get("refresh"):
            # Retrieve the endpoint data from the APIC and store it in the database
            get_token(apic_url,session["username"],session["password"])
            get_interfaces()
            return redirect("/interfaces")
        elif request.form.get("logout"):
            # Clear the session and redirect to the login page
            session.pop("authenticated", None)
            return redirect("/login")
        elif request.form.get("home"):
            return redirect("/")
    return render_template("interfaces.html", data=data)



    """
    This is a Flask route function that renders a template with interface statistics data and handles
    POST requests for refreshing the data, logging out, and returning to the home page.
    :return: the rendered template "interfacestats.html" with the data variable passed as a parameter.
    """

@app.route("/interfacestats", methods=["GET", "POST"])

def interfacestats():
    if "authenticated" not in session or not session["authenticated"]:
        return redirect("/login")
    cursor = mycnx.cursor()
    cursor.execute("SELECT * FROM interface_stats ORDER BY id")
    data = cursor.fetchall()

    # Render the endpoints.html template with the endpoint data
    if request.method == "POST":
        if request.form.get("refresh"):
            # Retrieve the endpoint data from the APIC and store it in the database
            get_token(apic_url,session["username"],session["password"])
            get_interface_stats()
            get_interfacevalue_stats()
            return redirect("/interfacestats")
        elif request.form.get("logout"):
            # Clear the session and redirect to the login page
            session.pop("authenticated", None)
            return redirect("/login")
        elif request.form.get("home"):
            return redirect("/")
    return render_template("interfacestats.html", data=data)




    """
    This function retrieves data from a MySQL database table called "interfaces_stats" and renders it in
    an HTML template called "interfacestatsdb.html".
    :return: the rendered template "interfacestatsdb.html" with the variables "data" and "e" passed to
    it.
    """

@app.route("/interfacestatsdb", methods=["GET", "POST"])
def interfacestatsdb(): 
    e = None
    cursor = mycnx.cursor()
    try:
        cursor.execute("SELECT * FROM interface_stats ORDER BY id")
        data = cursor.fetchall()
    except mysql.connector.Error as e:
        print("error printing stats : function (interfacestatsdb)")
    if request.form.get("exit"):
        return redirect("/login")
    elif request.form.get("home"):
        return redirect("/limited")
    return render_template("interfacestatsdb.html",data=data  ,e=e)



    """
    This function handles GET and POST requests for the "/interfacesdb" route, retrieves data from the
    "interfaces" table in a database, and renders the "interfacesdb.html" template with the retrieved
    data.
    :return: the rendered template "interfacesdb.html" with the variables "data" and "e" passed to it.
    """

@app.route("/interfacesdb", methods=["GET", "POST"])
def interfacesdb():  # sourcery skip: remove-unreachable-code
    e = None
    cursor = mycnx.cursor()
    try:
        cursor.execute("SELECT * FROM interfaces ORDER BY id")
        data = cursor.fetchall()
    except mysql.connector.Error as e:
        ...
    if request.form.get("exit"):
        return redirect("/login")
    elif request.form.get("home"):
        return redirect("/limited")
    return render_template("interfacesdb.html", data=data, e=e)


"""
This is a Flask route function that handles GET and POST requests to the "/subnets" endpoint. 
"""


@app.route("/subnets", methods=["GET", "POST"])
def subnets():
    if "authenticated" not in session or not session["authenticated"]:
        return redirect("/login")
    cursor = mycnx.cursor()
    query = "SELECT * FROM subnets ORDER BY id"
    cursor.execute(query)
    subnets = cursor.fetchall()
    if request.method == "POST":
        if request.form.get("refresh"):
            # Retrieve the subnets data from the APIC and store it in the database
            get_token(apic_url,session["username"],session["password"])
            get_subnets()
            return redirect("/subnets")
        elif request.form.get("logout"):
            session.pop("authenticated", None)
            return redirect("/login")
        elif request.form.get("home"):
            return redirect("/")
    return render_template("subnets.html", subnets=subnets)


"""
This is a Flask route handler for the "/limited" endpoint. It handles both GET and POST requests.
"""


@app.route("/limited", methods=["GET", "POST"])
def exit():
    if myenv == False:
        return redirect("/setup")
    if request.method == "POST" and request.form.get("exit"):
        session.pop("authenticated",None)
        return redirect("/login")
    return render_template("indexdb.html")


"""
This is a Flask route function that handles GET and POST requests to the "/endpointsdb" endpoint. 
"""


@app.route("/endpointsdb", methods=["GET", "POST"])
def endpointsdb():  # sourcery skip: remove-unreachable-code
    e = None
    cursor = mycnx.cursor()
    try:
        cursor.execute("SELECT * FROM endpoints ORDER BY id")
        data = cursor.fetchall()
    except mysql.connector.Error as e:
        ...
    if request.form.get("exit"):
        return redirect("/login")
    elif request.form.get("home"):
        return redirect("/limited")
    return render_template("endpointsdb.html", data=data, e=e)


"""
This function retrieves subnet information from a database and renders it in a template.
@return None
"""


@app.route("/subnetsdb", methods=["GET", "POST"])
def subnetsdb():
    e = None
    cursor = mycnx.cursor()
    try:
        query = "SELECT * FROM subnets ORDER BY id"
        cursor.execute(query)
        subnets = cursor.fetchall()
    except mysql.connector.Error as e:
        ...
    if request.form.get("exit"):
        return redirect("/login")
    elif request.form.get("home"):
        return redirect("/limited")
    return render_template("subnetsdb.html", subnets=subnets, e=e)


"""
This is a Flask route function that handles GET and POST requests to the '/login' endpoint. 
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    global user
    global apic_url
    if myenv == False:
        return redirect("/setup")
    error = None
    e = None  # Initialize 'e' to None
    if request.method == "POST":
        if request.form.get("limited") == "limited":
            session["authenticated"] = False
            session["username"] = "limited"
            return redirect("/limited")

        username = request.form["username"]
        password = request.form["password"]
        apic_url = request.form.get("apicurl")
        session["username"] = username
        session["password"] = password
        # Check if the credentials are correct
        try:
            get_token(apic_url, username, password)
        except Exception as ex:
            print(ex)
            e = ex  # Assign the exception to 'e'
        if not e:
            session["authenticated"] = True
            user = username
            return redirect("/")

           
        else:
            error = (
                "Unable to connect to the APIC. Check your credentials and try again."
            )


    # Render the login.html template with the error message, if any
    return render_template("login.html", error=error ,  mysqlhost = mysql_host )

"""
This is a Flask route function that handles GET and POST requests to the '/epgs' endpoint. 
"""


@app.route("/epgs", methods=["GET", "POST"])
def epgs():
    if "authenticated" not in session or not session["authenticated"]:
        return redirect("/login")
    cursor = mycnx.cursor()
    query = "SELECT * FROM EPGs ORDER BY id"
    cursor.execute(query)
    epgs_data = cursor.fetchall()
    if request.method == "POST":
        if request.form.get("refresh"):
            # Retrieve the EPGs data from the APIC and store it in the database
            get_token(apic_url,session["username"],session["password"])
            get_epgs()
            return redirect("/epgs")
        elif request.form.get("logout"):
            session.pop("authenticated", None)
            return redirect("/login")
        elif request.form.get("home"):
            return redirect("/")
    return render_template("epgs.html", epgs_data=epgs_data)


"""
This is a Flask route function that handles GET and POST requests to the '/epgsdb' endpoint. 
"""

@app.route("/epgsdb", methods=["GET", "POST"])
def epgsdb():
    e = None
    cursor = mycnx.cursor()
    try:
        query = "SELECT * FROM EPGs ORDER BY id"
        cursor.execute(query)
        epgs_data = cursor.fetchall()
    except mysql.connector.Error as e:
        # Handle the error (if any) here
        print("Error fetching EPGs: function (epgsdb)", e)

    if request.form.get("exit"):
        return redirect("/login")
    elif request.form.get("home"):
        return redirect("/limited")
    return render_template("epgsdb.html", epgs_data=epgs_data, e=e)





"""
This code snippet handles a request to the '/bridgedomains' route. It first checks if the user is logged in, and if not, redirects them to the login page. 
"""

@app.route("/bridgedomains", methods=["GET", "POST"])
def bridgedomains():
    if "authenticated" not in session or not session["authenticated"]:
        return redirect("/login")

    cursor = mycnx.cursor()
    query = "SELECT * FROM BridgeDomains ORDER BY id"
    cursor.execute(query)
    bridgedomains_data = cursor.fetchall()
    if request.method == "POST":
        if request.form.get("refresh"):
            # Retrieve the BridgeDomains data from the APIC and store it in the database
            get_token(apic_url,session["username"],session["password"])
            get_bridge_domains()
            return redirect("/bridgedomains")
        elif request.form.get("logout"):
            session.pop("authenticated", None)
            return redirect("/login")
        elif request.form.get("home"):
            return redirect("/")
    return render_template("bridgedomains.html", bridgedomains_data=bridgedomains_data)


"""
This is a Flask route function that handles GET and POST requests to the '/bridgedomainsdb' endpoint.
"""


@app.route("/bridgedomainsdb", methods=["GET", "POST"])
def bridgedomainsdb():
    e = None
    cursor = mycnx.cursor()
    try:
        query = "SELECT * FROM BridgeDomains ORDER BY id"
        cursor.execute(query)
        bridgedomains_data = cursor.fetchall()
    except mysql.connector.Error as e:
        # Handle the error (if any) here
        print("Error fetching BridgeDomains:", e)
    if request.form.get("exit"):
        return redirect("/login")
    elif request.form.get("home"):
        return redirect("/limited")
    return render_template(
        "bridgedomainsdb.html", bridgedomains_data=bridgedomains_data, e=e
    )


"""
This is a Flask route function that handles GET and POST requests for the '/tenants' endpoint. 
"""


@app.route("/tenants", methods=["GET", "POST"])
def tenants():
    if "authenticated" not in session or not session["authenticated"]:
        return redirect("/login")
    cursor = mycnx.cursor()
    query = "SELECT * FROM Tenants ORDER BY id"
    cursor.execute(query)
    tenants_data = cursor.fetchall()
    if request.method == "POST":
        if request.form.get("refresh"):
            # Retrieve the Tenants data from the APIC and store it in the database
            get_token(apic_url,session["username"],session["password"])
            get_tenants()
            return redirect("/tenants")
        elif request.form.get("logout"):
            session.pop("authenticated", None)
            return redirect("/login")
        elif request.form.get("home"):
            return redirect("/")
    return render_template("tenants.html", tenants_data=tenants_data)


"""
Thi is a Flask route function that handles requests to the '/tenantsdb' endpoint. It supports both GET and POST methods.
"""


@app.route("/tenantsdb", methods=["GET", "POST"])
def tenantsdb():
    e = None
    cursor = mycnx.cursor()
    try:
        query = "SELECT * FROM Tenants ORDER BY id"
        cursor.execute(query)
        tenants_data = cursor.fetchall()
    except mysql.connector.Error as e:
        # Handle the error (if any) here
        print("Error fetching Tenants:", e)

    if request.form.get("exit"):
        return redirect("/login")
    elif request.form.get("home"):
        return redirect("/limited")
    return render_template("tenantsdb.html", tenants_data=tenants_data, e=e)


"""
This is a Flask route that handles a GET and POST request to "/setup". 
If the request method is POST, it retrieves the values from the form fields (mysql_host, mysql_username, mysql_password, apic_url, apic_username, apic_password) and writes them to a file. 
"""


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if request.method == "POST":
        # Get the form data submitted by the user
        mysql_host = request.form.get("mysql_host")
        mysql_username = request.form.get("mysql_username")
        mysql_password = request.form.get("mysql_password")


        # Save the form data to the .env file
        with open(".env", "w") as f:
            f.write(f"MYSQL_HOST={mysql_host}\n")
            f.write(f"MYSQL_USERNAME={mysql_username}\n")
            f.write(f"MYSQL_PASSWORD={mysql_password}\n")

        # Redirect to the homepage or another page after setup
        global myenv
        myenv = True
        return redirect("/login")

    # Render the setup.html template for the user to enter the data
    return render_template("setup.html")




    """
    This function redirects the user to different pages based on their menu selection, depending on
    their authentication status.
    :return: The code is returning a redirect to different routes based on the value of the "menu"
    parameter. If the user is not authenticated, it redirects them to different routes based on the
    value of "menu" and if the user is authenticated, it redirects them to different routes based on the
    value of "menu". If the "menu" parameter does not match any of the specified values, it redirects to
    """


@app.route('/catalog')
def catalog():
    menu = request.args.get("menu", "")
    if "authenticated" not in session:
        return redirect('/login')
    if not session["authenticated"] :
        if  session["username"] == 'limited':
            # Loop through different menus
            if menu == 'home':
                return redirect ('/limited')
            elif menu == 'endpoints':
                return redirect ('/endpointsdb')
            elif menu == 'subnets':
                return redirect ('subnetsdb')
            elif menu == 'epgs':
                return redirect ('/epgsdb')
            elif menu == 'tenants':
                return redirect ('/tenantsdb')
            elif menu == 'bds':
                return redirect ('/bridgedomainsdb')    
            elif menu == 'ifs':
                return redirect ('/interfacesdb') 
            elif menu == 'stats':
                return redirect ('/interfacestatsdb')
            elif menu == 'about':
                return redirect ('/about')
            else:
                    return redirect ('/index')
                    error = "Page Not Found 404"
        return render_template('indexdb.html')
    elif session["authenticated"]:
            if menu == 'home':
                return redirect ('/')
            elif menu == 'endpoints':
                return redirect ('/endpoints')
            elif menu == 'subnets':
                return redirect ('subnets')
            elif menu == 'epgs':
                return redirect ('/epgs')
            elif menu == 'tenants':
                return redirect ('/tenants')
            elif menu == 'bds':
                return redirect ('/bridgedomains')
            elif menu == 'ifs':
                return redirect ('/interfaces')   
            elif menu == 'stats':
                return redirect ('/interfacestats')  
            elif menu == 'about':
                return redirect ('/about')  
            else:
                return redirect ('/index')
    return render_template('index.html')




"""
This code snippet is the main entry point of the application. It initializes the database connection, sets up the API URL and secret key, and starts the application in debug mode.
"""

if __name__ == "__main__":

    # Set the secret key for the application
    app.secret_key = "mysecretkey"
    global myenv
    global apic_url
    global mysqlhost


    myenv = True
    try:
        # Check if the .env file exists
        if not os.path.exists(".env"):
            # Raise an HTTP 404 error
            raise FileNotFoundError(
                "The .env file is missing. Please create the .env file and set up the environment variables."
            )
        # Load environment variables from .env file
        load_dotenv()

        # Define the MySQL connection parameters
        mysql_host = os.getenv("MYSQL_HOST")
        mysql_username = os.getenv("MYSQL_USERNAME")
        mysql_password = os.getenv("MYSQL_PASSWORD")
        mysql_database = "endpointer"


        # Initialize the MySQL database connection
        mycnx = get_database_connection()
        mysqlhost = mysql_host


    except FileNotFoundError as e:
        print("FileNotFoundError:", e)
        myenv = False
    app.run()
    


