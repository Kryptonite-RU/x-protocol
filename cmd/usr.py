import argparse
import xproto as x
import datetime
import cmd.default as default

# Two types of operations for user are possible:
# form blob 
# check request (signature)

parser = argparse.ArgumentParser(description='User script')
# entities
parser.add_argument('--user', action="store", dest="usr")
parser.add_argument('--auth', action="store", dest="AUTH")
# actions
parser.add_argument('--form_blob', action="store_true")
parser.add_argument('--check_request', action="store_true")
# data for forming blob 
parser.add_argument('--request', action="store", default="data/request", dest="req")
parser.add_argument('--secdata', action="store", dest="secdata")
parser.add_argument('--output', action="store", default="data/blob", dest="output")

args = parser.parse_args()

if args.usr is None:
    usr = x.load_usr(default.DEFAULT_USER)
else:
    usr = x.load_usr(args.usr)
if args.AUTH is None:
    usr.AUTH = x.load_auth(default.DEFAULT_AUTH)
else:
    usr.AUTH = x.load_auth(args.AUTH)

if args.form_blob:
    d = x.file_to_dict(args.req)
    req = x.Request.from_dict(d)
    if args.secdata is None:
        blob = usr.create_blob(req)
    else:
        blob = usr.create_blob(req, data=args.secdata)
    x.to_file(args.output, blob)
elif args.check_request:
    d = x.file_to_dict(args.req)
    req = x.Request.from_dict(d)
    if usr.check_request(req):
        print("Correct signature for request")
    else:
        print("Incorrect signature for request")
