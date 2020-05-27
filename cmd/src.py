import argparse
import xproto as x
import datetime
import cmd.default as default

# Three types of operations for service are possible:
# form request
# check blob (signature)
# check response (signature + answer)

parser = argparse.ArgumentParser(description='Service script')
# entities
parser.add_argument('--service', action="store", dest="src")
parser.add_argument('--auth', action="store", dest="AUTH")
# actions
parser.add_argument('--form_request', action="store_true")
parser.add_argument('--check_blob', action="store_true")
parser.add_argument('--check_response', action="store_true")
# data for request
parser.add_argument('--uid', action='store', dest="uid", type=int)
parser.add_argument('--scope', action="store", dest="scope")
parser.add_argument('--due', action="store", dest="due")
parser.add_argument('--output', action="store", default="data/request", dest="out")
# data for checking blob
parser.add_argument('--blob', action="store", default="data/blob", dest="blob")
# data for checking response
parser.add_argument('--response', action="store", default="data/response", dest="resp")

args = parser.parse_args()

if args.src is None:
    src = x.load_src(default.DEFAULT_SERVICE)
else:
    src = x.load_src(args.src)
if args.AUTH is None:
    src.AUTH = x.load_auth(default.DEFAULT_AUTH)
else:
    src.AUTH = x.load_auth(args.AUTH)

if args.form_request:
    due = datetime.datetime.strptime(args.due, '%Y-%m-%d')
    ttl = x.TTL(due)
    req = src.create_request(args.uid, args.scope, ttl)
    x.to_file(args.output, req)
elif args.check_blob:
    d = x.file_to_dict(args.blob)
    blob = x.Blob.from_dict(d)
    if src.check_blob(blob):
        print("Correct signature for blob")
    else:
        print("Incorrect signature for blob")
elif args.check_response:
    d = x.file_to_dict(args.resp)
    resp = x.Response.from_dict(d)
    if src.verify_response(resp):
        print("Correct signature for response")
        if src.check_response(resp):
            print("Blob for this response is correct")
        else:
            print("Blob for this response is incorrect")
    else:
        print("Incorrect signature for response")


