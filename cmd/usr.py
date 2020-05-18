import argparse
import xproto as x
import datetime

parser = argparse.ArgumentParser(description='Service script')

parser.add_argument('-d', action="store", dest="data")
parser.add_argument('-r', action="store", dest="req")
args = parser.parse_args()
request = x.parse_request(args.req)

usr = x.load_usr("data/usr.json")
blob = usr.create_blob(self, request, data = None)
#print(req.srcid, req.uid, req.scope, req.ttl.produced, req.ttl.expired)
raw = src.send_request(req)
f = open('data/request', 'wb')
f.write(raw)
f.close()

