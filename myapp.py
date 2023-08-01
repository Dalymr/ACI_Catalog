"""
    The below code is a Flask web application that connects to an APIC (Application Policy
    Infrastructure Controller) to retrieve endpoint and subnet data, stores it in a MySQL database, and
    displays it on different web pages.
    
    :param ip_address: The `ip_address` parameter is the IP address of the endpoint that you want to
    find the subnet for
    :return: The Flask app is being returned.
"""
import requests
import threading

from flask import Flask, render_template, request, session, redirect
from flask_bootstrap import Bootstrap
import mysql.connector
import urllib3
import ipaddress
from acitoolkit import Tenant
import logging

app = Flask(__name__)

# Disable the InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# Implement Bootstrap to App
bootstrap = Bootstrap(app)


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
Connect to the APIC (Application Policy Infrastructure Controller) by sending a login request with the provided username and password.
If successful, retrieve the authentication token from the response and store it in the global variable `token`.
If an error occurs during authentication, print an error message. Finally, return the authentication token.
"""


def get_token(apic_url, username, password):
    print("Connecting to APIC...")
    try:
        # Obtain webtoken
        login_url = f"{apic_url}/api/aaaLogin.json"
        login_payload = {"aaaUser": {"attributes": {"name": username, "pwd": password}}}

        response = requests.post(login_url, json=login_payload, verify=False, timeout=2)
        print("token is fine")
        # time.sleep(2)  # Introduce a 2-second delay
        print("Connected!")
        global token
        token = response.json()["imdata"][0]["aaaLogin"]["attributes"]["token"]
        if not stop_thread_flag:
            threading.Timer(10.0, get_token).start()
    except Exception as authenerror:
        print(f"An unexpected error occurred during Authentification ")
    return token


# Connect to MySQL and initialize cursor
def initialize_database(host, username, password, database):
    cnx = mysql.connector.connect(
        host=mysql_host,
        user=mysql_username,
        password=mysql_password,
        database=mysql_database,
    )
    cursor = cnx.cursor()
    # Create table endpoints if it does not exist
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS endpoints (
            id INT PRIMARY KEY AUTO_INCREMENT,
            IPEndpoint VARCHAR(255) UNIQUE,
            MAC VARCHAR(255),
            RelEPG VARCHAR(255),
            RelAPP VARCHAR(255),
            relBD VARCHAR(255)
        )
    """
    )
    # Create table subnets if it does not exist
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
    # Create table EPGs if it does not exist
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS EPGs (
            id INT PRIMARY KEY AUTO_INCREMENT,
            EPGId VARCHAR(255) UNIQUE,
            EPGName VARCHAR(255),
            TenantId VARCHAR(255),
            EndpointCount INT
        )
    """
    )
    # Create table Tenants if it does not exist
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
    # Create table BridgeDomains if it does not exist
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS BridgeDomains (
            id INT PRIMARY KEY AUTO_INCREMENT,
            BDId VARCHAR(255) UNIQUE,
            BDName VARCHAR(255),
            VRF VARCHAR(255),
            Scope VARCHAR(255)
        )
    """
    )
    # Create table ApplicationProfiles if it does not exist
    cursor.execute(
        """
    CREATE TABLE IF NOT EXISTS ApplicationProfiles (
        id INT PRIMARY KEY AUTO_INCREMENT,
        AppProfileId VARCHAR(255) UNIQUE,
        AppProfileName VARCHAR(255),
        TenantId VARCHAR(255),
        Description VARCHAR(255),
        Scope VARCHAR(255)
    )
"""
    )
    # Returs MySQL connection
    return cnx


"""
This function retrieves the endpoints from a specified API endpoint and inserts them into a database table.
It uses a cursor object to execute SQL queries and a global token variable for authentication.
"""


def get_endpoints():
    cursor = mycnx.cursor()
    global token
    # Send GET request to retrieve the endpoint data
    endpoint_url = f"{apic_url}/api/node/class/fvIp.json?&order-by=fvIp.modTs|desc"
    headers = {"Cookie": f"APIC-Cookie={token}"}
    try:
        response = requests.get(endpoint_url, headers=headers, verify=False)
        data = response.json()
        print("gettin data is fine")
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
        rel_bd = attributes.get("bdDn", "").split("uni/tn-")[1].split("/BD-")[1]
        print("i think im saving in database endpoints no ?")
        # Check if the endpoint already exists in the database
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
            print("getting all endpoints")
        except mysql.connector.Error as e:
            print("error in exist")
            continue
        if existing_endpoint:
            # If the endpoint already exists, update itsattributes with the new information
            try:
                cursor.execute(
                    "UPDATE endpoints SET id = %sMAC = %s, RelEPG = %s, RelAPP = %s, relBD = %s WHERE IPEndpoint = %s",
                    (next_id, mac, rel_epg, rel_app, rel_bd, ipendpoint),
                )
                print("updating something")
            except mysql.connector.Error as e:
                continue
        else:
            # If the endpoint does not exist, insert it into the database
            try:
                cursor.execute(
                    "INSERT INTO endpoints (id, IPEndpoint, MAC, RelEPG, RelAPP, relBD) VALUES (%s, %s, %s, %s, %s, %s)",
                    (next_id, ipendpoint, mac, rel_epg, rel_app, rel_bd),
                )
                print("adding something to database")
            except mysql.connector.Error as e:
                print("error in insertion ", e)
                continue
    mycnx.commit()

    """
    Retrieve subnets from the APIC and save them to a database table.
    @return None
    """


def get_subnets():
    global token
    print("am i adding subnets ?")
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
            print("cant find attrib ?")
            continue
        ip = attributes.get("ip", "")
        scope = attributes.get("scope", "")
        tenant = attributes.get("dn", "").split("/tn-")[1].split("/")[0]
        bd = attributes.get("dn", "").split("/BD-")[1].split("/")[0]
        cursor.execute("SELECT MAX(id) FROM subnets")
        last_inserted_id = cursor.fetchone()[0]
        # Set the initial ID value for the next insert
        next_id = last_inserted_id + 1 if last_inserted_id else 1
        print("i think im saving in database my subnets")
        # Insert the endpoint data into the "endpoints" table
        insert_query = """
        INSERT IGNORE INTO subnets (id,IPsubnet, BD, Tenant, Scope)
        VALUES (%s ,%s, %s, %s, %s)
        """
        insert_values = (next_id, ip, bd, tenant, scope)
        try:
            cursor.execute(insert_query, insert_values)
        except mysql.connector.errors.IntegrityError as e:
            print(" i think i didnt save", e)
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
    response = requests.get(epg_url, headers=headers, verify=False)
    epgs_data = response.json()
    for epg_data in epgs_data["imdata"]:
        epg_dn = epg_data["fvAEPg"]["attributes"]["dn"]
        epg_name = epg_data["fvAEPg"]["attributes"]["name"]
        tenant_id = (
            epg_data["fvAEPg"]["attributes"]["dn"].split("/tn-")[1].split("/")[0]
        )
        # Additional API call to retrieve endpoint count for each EPG
        endpoint_url = f"{apic_url}/api/class/fvCEp.json?query-target-filter=eq(fvCEp.epgDn,'{epg_dn}')"
        endpoint_response = requests.get(endpoint_url, headers=headers, verify=False)
        endpoint_data = endpoint_response.json()
        endpoint_count = len(endpoint_data["imdata"])
        # Check if the EPG already exists in the database
        cursor.execute("SELECT MAX(id) FROM EPGs")
        last_inserted_id = cursor.fetchone()[0]
        next_id = last_inserted_id + 1 if last_inserted_id else 1
        try:
            cursor.execute("SELECT * FROM EPGs WHERE EPGId = %s", (epg_dn,))
            existing_epg = cursor.fetchone()
        except mysql.connector.Error as e:
            print("Error in EPG exist:", e)
            continue

        if existing_epg:
            # If the EPG already exists, update its attributes with the new information
            try:
                cursor.execute(
                    "UPDATE EPGs SET id = %s, EPGName = %s, TenantId = %s,  EndpointCount = %s WHERE EPGId = %s",
                    (next_id, epg_name, tenant_id, endpoint_count, epg_dn),
                )
            except mysql.connector.Error as e:
                print("Error updating EPG:", e)
                continue
        else:
            # If the EPG does not exist, insert it into the database
            try:
                cursor.execute(
                    "INSERT INTO EPGs (id, EPGId, EPGName, TenantId, EndpointCount) VALUES (%s, %s, %s, %s, %s)",
                    (next_id, epg_dn, epg_name, tenant_id, endpoint_count),
                )
            except mysql.connector.Error as e:
                print("Error inserting EPG:", e)
                continue

    # Commit the changes to the database
    mycnx.commit()

    """
    Retrieve the application profiles from the APIC (Application Policy Infrastructure Controller) and store them in a database.
    @return None
    """


def get_application_profiles():
    global token
    cursor = mycnx.cursor()
    app_profile_url = f"{apic_url}/api/class/fvAp.json"
    headers = {"Cookie": f"APIC-Cookie={token}"}

    response = requests.get(app_profile_url, headers=headers, verify=False)
    app_profiles_data = response.json()

    for app_profile_data in app_profiles_data["imdata"]:
        app_profile_dn = app_profile_data["fvAp"]["attributes"]["dn"]
        app_profile_name = app_profile_data["fvAp"]["attributes"]["name"]
        tenant_id = (
            app_profile_data["fvAp"]["attributes"]["dn"].split("/tn-")[1].split("/")[0]
        )
        description = app_profile_data["fvAp"]["attributes"].get("descr", "")
        scope = app_profile_data["fvAp"]["attributes"].get("scope", "")

        # Check if the Application Profile already exists in the database
        cursor.execute("SELECT MAX(id) FROM ApplicationProfiles")
        last_inserted_id = cursor.fetchone()[0]
        next_id = last_inserted_id + 1 if last_inserted_id else 1

        try:
            cursor.execute(
                "SELECT * FROM ApplicationProfiles WHERE AppProfileId = %s",
                (app_profile_dn,),
            )
            existing_app_profile = cursor.fetchone()
        except mysql.connector.Error as e:
            print("Error in Application Profile exist:", e)
            continue

        if existing_app_profile:
            # If the Application Profile already exists, update its attributes with the new information
            try:
                cursor.execute(
                    "UPDATE ApplicationProfiles SET id = %s, AppProfileName = %s, TenantId = %s, Description = %s, Scope = %s WHERE AppProfileId = %s",
                    (
                        next_id,
                        app_profile_name,
                        tenant_id,
                        description,
                        scope,
                        app_profile_dn,
                    ),
                )
            except mysql.connector.Error as e:
                print("Error updating Application Profile:", e)
                continue
        else:
            # If the Application Profile does not exist, insert it into the database
            try:
                cursor.execute(
                    "INSERT INTO ApplicationProfiles (id, AppProfileId, AppProfileName, TenantId, Description, Scope) VALUES (%s, %s, %s, %s, %s, %s)",
                    (
                        next_id,
                        app_profile_dn,
                        app_profile_name,
                        tenant_id,
                        description,
                        scope,
                    ),
                )
            except mysql.connector.Error as e:
                print("Error inserting Application Profile:", e)
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
        bd_dn = bd_entry["fvBD"]["attributes"]["dn"]
        bd_name = bd_entry["fvBD"]["attributes"]["name"]
        vrf = bd_entry["fvBD"]["attributes"]["scope"]

        # Check if the BridgeDomain already exists in the database
        cursor.execute("SELECT MAX(id) FROM BridgeDomains")
        last_inserted_id = cursor.fetchone()[0]
        next_id = last_inserted_id + 1 if last_inserted_id else 1

        try:
            cursor.execute("SELECT * FROM BridgeDomains WHERE BDId = %s", (bd_dn,))
            existing_bd = cursor.fetchone()
        except mysql.connector.Error as e:
            print("Error in BridgeDomain exist:", e)
            continue

        if existing_bd:
            # If the BridgeDomain already exists, update its attributes with the new information
            try:
                cursor.execute(
                    "UPDATE BridgeDomains SET id = %s, BDName = %s, VRF = %s, Scope = %s WHERE BDId = %s",
                    (next_id, bd_name, vrf, bd_dn),
                )
            except mysql.connector.Error as e:
                print("Error updating BridgeDomain:", e)
                continue
        else:
            # If the BridgeDomain does not exist, insert it into the database
            try:
                cursor.execute(
                    "INSERT INTO BridgeDomains (id, BDId, BDName, VRF, Scope) VALUES (%s, %s, %s, %s, %s)",
                    (next_id, bd_dn, bd_name, vrf, bd_dn),
                )
            except mysql.connector.Error as e:
                print("Error inserting BridgeDomain:", e)
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
        scope = tenant_data["fvTenant"]["attributes"].get("scope", "")

        # Check if the Tenant already exists in the database
        cursor.execute("SELECT MAX(id) FROM Tenants")
        last_inserted_id = cursor.fetchone()[0]
        next_id = last_inserted_id + 1 if last_inserted_id else 1

        try:
            cursor.execute("SELECT * FROM Tenants WHERE TenantId = %s", (tenant_dn,))
            existing_tenant = cursor.fetchone()
        except mysql.connector.Error as e:
            print("Error in Tenant exist:", e)
            continue

        if existing_tenant:
            # If the Tenant already exists, update its attributes with the new information
            try:
                cursor.execute(
                    "UPDATE Tenants SET id = %s, TenantName = %s, Description = %s, Scope = %s WHERE TenantId = %s",
                    (next_id, tenant_name, description, scope, tenant_dn),
                )
            except mysql.connector.Error as e:
                print("Error updating Tenant:", e)
                continue
        else:
            # If the Tenant does not exist, insert it into the database
            try:
                cursor.execute(
                    "INSERT INTO Tenants (id, TenantId, TenantName, Description, Scope) VALUES (%s, %s, %s, %s, %s)",
                    (next_id, tenant_dn, tenant_name, description, scope),
                )
            except mysql.connector.Error as e:
                print("Error inserting Tenant:", e)
                continue

    # Commit the changes to the database
    mycnx.commit()


"""
This function is a route handler for the "/search" endpoint. It performs a search query on a database table called "endpoints" based on the provided query parameter.
"""


@app.route("/search", methods=["GET", "POST"])
def search():
    if "username" not in session:
        return redirect("/login")

    query = request.args.get("query", "")  # Get the search query from the URL parameter

    # Perform the search in the database
    cursor = mycnx.cursor()
    search_query = """
        SELECT * FROM endpoints 
        WHERE IPEndpoint LIKE %s OR MAC LIKE %s OR RelEPG LIKE %s OR RelAPP LIKE %s OR relBD LIKE %s
    """
    search_values = tuple(["%" + query + "%"] * 5)
    cursor.execute(search_query, search_values)
    search_results = cursor.fetchall()

    return render_template("search_results.html", query=query, results=search_results)


# Define routes for the Flask app
"""
This function is a route handler for the "/base" endpoint of a Flask application.
When a request is made to this endpoint, it renders the "base.html" template and returns the rendered HTML as the response.
"""


@app.route("/base")
def base():
    return render_template("base.html")


"""
This is a Flask route handler for the root URL ("/"). It checks if the "username" key is present in the session object and if its value is not equal to "limited". If either of these conditions is not met, it redirects the user to the "/login" URL. Otherwise, it continues with the execution of the route handler.
"""


@app.route("/")
def index():
    if "username" not in session or "username" in session == "limited":
        return redirect("/login")
    else:
        return render_template("index.html")


"""
This function is a route handler for the "/logout" endpoint in a Flask application. It sets a global flag `stop_thread_flag` to `True`, indicating that a background thread should stop.
"""


@app.route("/logout")
def logout():
    global stop_thread_flag
    stop_thread_flag = True
    session.pop("username", None)
    return redirect("/login")


"""
This is a Flask route function that handles GET and POST requests to the "/endpoints" endpoint. 
"""


@app.route("/endpoints", methods=["GET", "POST"])
def endpoints():
    if "username" not in session:
        return redirect("/login")
    print("logged in")
    cursor = mycnx.cursor()
    cursor.execute("SELECT * FROM endpoints ORDER BY id")
    data = cursor.fetchall()

    # Render the endpoints.html template with the endpoint data
    if request.method == "POST":
        if request.form.get("refresh"):
            # Retrieve the endpoint data from the APIC and store it in the database
            print(" do i do this ?")
            get_endpoints()
            return redirect("/endpoints")
        elif request.form.get("logout"):
            # Clear the session and redirect to the login page
            session.pop("username", None)
            return redirect("/login")
        elif request.form.get("home"):
            return redirect("/")
    return render_template("endpoints.html", data=data)


"""
This is a Flask route function that handles GET and POST requests to the "/subnets" endpoint. 
"""


@app.route("/subnets", methods=["GET", "POST"])
def subnets():
    if "username" not in session:
        return redirect("/login")
    cursor = mycnx.cursor()
    print("are we subneting ? calling all subnets")
    query = "SELECT * FROM subnets ORDER BY id"
    cursor.execute(query)
    subnets = cursor.fetchall()
    print(subnets)
    if request.method == "POST":
        print("pooooooost")
        if request.form.get("refresh"):
            print("reeferessh")
            # Retrieve the subnets data from the APIC and store it in the database

            print("calling get subnets")
            get_subnets()
            return redirect("/subnets")
        elif request.form.get("logout"):
            session.pop("username", None)
            return redirect("/login")
        elif request.form.get("home"):
            return redirect("/")
    return render_template("subnets.html", subnets=subnets)


"""
This is a Flask route handler for the "/limited" endpoint. It handles both GET and POST requests.
"""


@app.route("/limited", methods=["GET", "POST"])
def exit():
    if request.method == "POST" and request.form.get("exit"):
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
    print("are we subneting ? calling all subnets")
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
    error1 = None
    error = None
    e = None
    if request.method == "POST":
        if request.form.get("limited") == "limited":
            session["username"] = "limited"
            return redirect("/limited")

        username = request.form["username"]
        password = request.form["password"]
        print("hehe")
        # Check if the credentials are correct
        try:
            get_token(apic_url, username, password)
        except requests.exceptions.RequestException as e:
            error1 = "Connection Error: Unable to connect to the APIC."
            print("hi")
        if not (e):
            session["username"] = username
            session["password"] = password
            print("hey")
            return redirect("/")
        else:
            error = "Invalid Credentials. Please try again."
            # Run the get_endpoints function to retrieve the endpoint data and store it in the database
            # Redirect to the endpoints page

    # Render the login.html template with the error message, if any
    return render_template("login.html", e=e, error=error, error1=error1)


"""
This is a Flask route function that handles GET and POST requests to the '/epgs' endpoint. 
"""


@app.route("/epgs", methods=["GET", "POST"])
def epgs():
    if "username" not in session:
        return redirect("/login")
    cursor = mycnx.cursor()
    print("Calling all EPGs")
    query = "SELECT * FROM EPGs ORDER BY id"
    cursor.execute(query)
    epgs_data = cursor.fetchall()
    print(epgs_data)
    if request.method == "POST":
        print("POST request")
        if request.form.get("refresh"):
            print("Refreshing EPGs data")
            # Retrieve the EPGs data from the APIC and store it in the database

            get_epgs()
            return redirect("/epgs")
        elif request.form.get("logout"):
            session.pop("username", None)
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
        print("Error fetching EPGs:", e)

    if request.form.get("exit"):
        return redirect("/login")
    elif request.form.get("home"):
        return redirect("/limited")
    return render_template("epgsdb.html", epgs_data=epgs_data, e=e)


"""
This is a Flask route function that handles GET and POST requests for the '/applicationprofiles' endpoint. It requires the user to be logged in, otherwise it redirects to the '/login' page.
"""


@app.route("/applicationprofiles", methods=["GET", "POST"])
def applicationprofiles():
    if "username" not in session:
        return redirect("/login")
    cursor = mycnx.cursor()
    print("Calling all Application Profiles")
    query = "SELECT * FROM ApplicationProfiles ORDER BY id"
    cursor.execute(query)
    applicationprofiles_data = cursor.fetchall()
    print(applicationprofiles_data)
    if request.method == "POST":
        print("POST request")
        if request.form.get("refresh"):
            print("Refreshing Application Profiles data")
            # Retrieve the Application Profiles data from the APIC and store it in the database

            get_application_profiles()
            return redirect("/applicationprofiles")
        elif request.form.get("logout"):
            session.pop("username", None)
            return redirect("/login")
        elif request.form.get("home"):
            return redirect("/")
    return render_template(
        "applicationprofiles.html", applicationprofiles_data=applicationprofiles_data
    )


"""
This code snippet defines a route in a Flask application. The route is '/appprofilesdb' and it accepts both GET and POST requests.
"""


@app.route("/appprofilesdb", methods=["GET", "POST"])
def appprofilesdb():
    e = None
    cursor = mycnx.cursor()
    try:
        query = "SELECT * FROM ApplicationProfiles ORDER BY id"
        cursor.execute(query)
        app_profiles_data = cursor.fetchall()
    except mysql.connector.Error as e:
        # Handle the error (if any) here
        print("Error fetching Application Profiles:", e)

    if request.form.get("exit"):
        return redirect("/login")
    elif request.form.get("home"):
        return redirect("/limited")
    return render_template(
        "applicationprofilesdb.html", app_profiles_data=app_profiles_data, e=e
    )


"""
This code snippet handles a request to the '/bridgedomains' route. It first checks if the user is logged in, and if not, redirects them to the login page. 
"""


@app.route("/bridgedomains", methods=["GET", "POST"])
def bridgedomains():
    if "username" not in session:
        return redirect("/login")

    cursor = mycnx.cursor()
    print("Calling all bridgedomains")
    query = "SELECT * FROM BridgeDomains ORDER BY id"
    cursor.execute(query)
    bridgedomains_data = cursor.fetchall()
    print(bridgedomains_data)
    if request.method == "POST":
        print("POST request")
        if request.form.get("refresh"):
            print("Refreshing bridgedomains data")
            # Retrieve the BridgeDomains data from the APIC and store it in the database

            get_bridge_domains()
            return redirect("/bridgedomains")
        elif request.form.get("logout"):
            session.pop("username", None)
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
    if "username" not in session:
        return redirect("/login")
    cursor = mycnx.cursor()
    print("Calling all tenants")
    query = "SELECT * FROM Tenants ORDER BY id"
    cursor.execute(query)
    tenants_data = cursor.fetchall()
    print(tenants_data)
    if request.method == "POST":
        print("POST request")
        if request.form.get("refresh"):
            print("Refreshing tenants data")
            # Retrieve the Tenants data from the APIC and store it in the database
            get_tenants()
            return redirect("/tenants")
        elif request.form.get("logout"):
            session.pop("username", None)
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
This function is a decorator that registers a function to be executed before the first request is handled by the server.
"""


def before_first_request():
    # Call the route function once before the first request is served
    return "/login"


"""
This code snippet is the main entry point of the application. It initializes the database connection, sets up the API URL and secret key, and starts the application in debug mode.
"""
if __name__ == "__main__":
    # Define the MySQL connection parameters
    mysql_host = "localhost"
    mysql_username = "root"
    mysql_password = "myadmin1502"
    mysql_database = "endpointer"

    # Initialize the MySQL database connection
    mycnx = initialize_database(
        mysql_host, mysql_username, mysql_password, mysql_database
    )

    # Define the APIC connection parameters
    apic_url = "https://10.10.20.14"
    app.secret_key = "mysecretkey"
    # Run the Flask app
    app.run(debug=True)
