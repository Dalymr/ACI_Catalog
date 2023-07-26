
import collections
import acitoolkit
conn = acitoolkit.connect(host='https://10.10.20.14/',
                          user='admin',
                          password='C1sco12345',
                          verify=False)

epg = acitoolkit.EPG('my-epg')
epg.tenant = 'tenant1'
epg.bd = 'bd1'
epg.add_context('c1')
epg.create(conn)
print("Done")
