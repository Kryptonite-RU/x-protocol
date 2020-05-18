import argparse
import xproto as x
import datetime

parser = argparse.ArgumentParser(description='Service script')

parser.add_argument('-u', action='store', dest="uid", type=int)
parser.add_argument('-d', action="store", dest="scope")
parser.add_argument('-t', action="store", dest="due")
args = parser.parse_args()
due = datetime.datetime.strptime(args.due, '%Y-%m-%d')
ttl = x.TTL(due)


src = x.load_src("data/src.json")
req = x.Request(src.ID, args.uid, args.scope, ttl, 
    key_pair = src.key_pair)
#print(req.srcid, req.uid, req.scope, req.ttl.produced, req.ttl.expired)
raw = src.send_request(req)
f = open('data/request', 'wb')
f.write(raw)
f.close()