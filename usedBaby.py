import requests
from flask import Flask
import json
import mysql.connector
import urllib3
import ipaddress
import time

app = Flask(__name__)

# Disable the InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def find_subnet(ip_address):
    cursor = mycnx.cursor()
    # Query to retrieve the subnets from the "subnets" table
    query = 'SELECT IPsubnet FROM subnets'
    cursor.execute(query)
    subnets = cursor.fetchall()

    # Iterate over each subnet and check if the IP address is within the subnet range
    for subnet in subnets:
        subnet_ip = subnet[0]  # Access the first element of the tuple
        network = ipaddress.IPv4Network(subnet_ip, strict=False)
        network_address = str(network.network_address)
        if ipaddress.ip_address(ip_address) in network:
            return subnet_ip

    return None  # Return None if no matching subnet is found


def get_token(apic_url, username, password):
    print("Connecting to APIC...")
    try:
        # Obtain webtoken
        login_url = f"{apic_url}/api/aaaLogin.json"
        login_payload = {
            "aaaUser": {
                "attributes": {
                    "name": username,
                    "pwd": password
                }
            }
        }

        response = requests.post(login_url, json=login_payload, verify=False)
        # time.sleep(2)  # Introduce a 2-second delay
        print("Connected!")
        token = response.json()["imdata"][0]["aaaLogin"]["attributes"]["token"]
    except Exception as e:
        print(f"An unexpected error occurred during Authentification : {e}")
    return token


# Connect to MySQL and initialize cursor

def initialize_database(host, username, password, database):
    cnx = mysql.connector.connect(
        host=mysql_host,
        user=mysql_username,
        password=mysql_password,
        database=mysql_database
    )
    cursor = cnx.cursor()

# Create table endpoints if dosent exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS endpoints (
        id INT PRIMARY KEY,
        IPEndpoint VARCHAR(255) UNIQUE,
        MAC VARCHAR(255),
        subnet VARCHAR(255),
        RelEPG VARCHAR(255),
        RelAPP VARCHAR(255),
        relBD VARCHAR(255)
    )
''')

    # Create table "subnets" if dosent exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS subnets (
        id INT PRIMARY KEY,
        IPsubnet VARCHAR(255) UNIQUE,
        BD VARCHAR(255),
        Tenant VARCHAR(255),
        Scope VARCHAR(255)
    )
''')
    return cnx


# Get Endpoints from object Store and add them to Database
def get_endpoints(token):
    cursor = mycnx.cursor()

    # Send GET request to retrieve the endpoint data
    endpoint_url = f"{apic_url}/api/node/class/fvIp.json?&order-by=fvIp.modTs|desc"
    headers = {
        "Cookie": f"APIC-Cookie={token}"
    }

    try:
        response = requests.get(endpoint_url, headers=headers, verify=False)
        data = response.json()
    except requests.exceptions.RequestException as e:
        print("Error:", e)
        return

    # Store the endpoint data in the MySQL database
    for item in data["imdata"]:
        attributes = item.get("fvIp", {}).get("attributes", {})
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
        rel_bd = attributes.get("bdDn", "").split(
            "uni/tn-")[1].split("/BD-")[1]
        ip_subnet = find_subnet(ipendpoint)

        # Check if the endpoint already exists in the database
        try:
            cursor.execute(
                "SELECT * FROM endpoints WHERE IPEndpoint = %s", (ipendpoint,))
            existing_endpoint = cursor.fetchone()
        except mysql.connector.Error as e:
            continue

        if existing_endpoint:
            # If the endpoint already exists, update its values
            try:
                update_query = '''
                    UPDATE endpoints SET MAC = %s, subnet = %s, RelEPG = %s, RelAPP = %s, relBD = %s
                    WHERE IPEndpoint = %s
                '''
                update_values = (mac, ip_subnet, rel_epg,
                                 rel_app, rel_bd, ipendpoint)
                cursor.execute(update_query, update_values)
            except mysql.connector.Error as e:
                continue
        else:
            # If the endpoint does not exist, insert it into the database
            try:
                cursor.execute("SELECT MAX(id) FROM endpoints")
                last_inserted_id = cursor.fetchone()[0]
                next_id = last_inserted_id + 1 if last_inserted_id else 1
                insert_query = '''
                    INSERT IGNORE INTO endpoints (id,IPEndpoint, MAC, subnet, RelEPG, RelAPP, relBD)
                    VALUES (%s ,%s, %s, %s, %s, %s, %s)
                '''
                insert_values = (next_id, ipendpoint, mac,
                                 ip_subnet, rel_epg, rel_app, rel_bd)
                cursor.execute(insert_query, insert_values)
            except mysql.connector.Error as e:
                continue

    # Check if there are any removed endpoints in the database
    try:
        cursor.execute("SELECT IPEndpoint FROM endpoints")
        existing_endpoints = [row[0] for row in cursor.fetchall()]
        removed_endpoints = set(existing_endpoints) - set([item.get("fvIp", {}).get(
            "attributes", {}).get("addr", "") for item in data["imdata"]])
        if removed_endpoints:
            cursor.execute(
                "DELETE FROM endpoints WHERE IPEndpoint IN %s", (tuple(removed_endpoints),))
    except mysql.connector.Error as e:
        ...
    # time.sleep(3)  # Introduce a 3-second delay
    print("Learned Endpoints extracted!")
    # Step 3: Updating Database
    print("Updating Database...")
    mycnx.commit()
    # time.sleep(2)  # Introduce a 2-second delay
    print("Database updated!")
    # Commit the changes and close the connection


# Get Subnets from object Store and add them to Database
def get_subnets(token):
    cursor = mycnx.cursor()
    # time.sleep(1)
    # Step 4: Fetching Unused IPs
    print("Fetching Subnets...")
    # Send GET request to retrieve the endpoint data
    subnet_url = f"{apic_url}/api/node/class/fvSubnet.json?&order-by=fvSubnet.modTs|desc"
    headers = {
        "Cookie": f"APIC-Cookie={token}"
    }

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
        insert_query = '''
        INSERT IGNORE INTO subnets (id,IPsubnet, BD, Tenant, Scope)
        VALUES (%s ,%s, %s, %s, %s)
        '''
        insert_values = (next_id, ip, bd, tenant, scope)
        try:
            cursor.execute(insert_query, insert_values)
        except mysql.connector.errors.IntegrityError:
            continue
# Commit the changes
    mycnx.commit()
    # time.sleep(3)  # Introduce a 3-second delay
    print("Subnets fetched!")


# static_data
# Prompt for APIC connection details
apic_url = "https://10.10.20.14"
username = "admin"
password = "C1sco12345"
# Prompt for MySQL database connection details
mysql_host = "127.0.0.1"
mysql_username = "root"
mysql_password = "myadmin1502"
mysql_database = "endpointer"


# Main Script
start_time = time.time()
mycnx = initialize_database(mysql_host, mysql_username,
                            mysql_password, mysql_database)
mytoken = get_token(apic_url, username, password)
get_endpoints(mytoken)
get_subnets(mytoken)
end_time = time.time()
latency = end_time - start_time
print("Database Updated ! Done in :")
print(latency)
print("secs")
mycnx.close()
