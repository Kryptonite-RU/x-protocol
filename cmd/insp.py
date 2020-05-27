import argparse
import xproto as x
import datetime
import cmd.default as default

# Two types of operations for inspector are possible:
# verify blob (full verification with response as a result)
# add user with personal information 

parser = argparse.ArgumentParser(description='Inspector script')
# entities
parser.add_argument('--inspector', action="store", dest="insp")
parser.add_argument('--auth', action="store", dest="AUTH")
# actions
parser.add_argument('--verify_blob', action="store_true")
parser.add_argument('--add_user', action="store_true")
# data for blob verifications
parser.add_argument('--blob', action="store", default="data/blob", dest="blob")
parser.add_argument('--request', action="store", default="data/request", dest="req")
parser.add_argument('--output', action="store", default="data/response", dest="output")
# data for user registration
parser.add_argument('--uid', action='store', dest="uid", type=int)
parser.add_argument('--secdata', action="store", dest="secdata")

args = parser.parse_args()

# load entities from files
if args.insp is None:
    insp = x.load_insp(default.DEFAULT_INSPECTOR)
else:
    insp = x.load_usr(args.insp)
if args.AUTH is None:
    insp.AUTH = x.load_auth(default.DEFAULT_AUTH)
else:
    insp.AUTH = x.load_auth(args.AUTH)

if args.verify_blob:
    d = x.file_to_dict(args.blob)
    blob = x.Blob.from_dict(d)
    d = x.file_to_dict(args.req)
    req = x.Request.from_dict(d)
    resp = insp.verify_blob(blob, req)
    x.to_file(args.output, resp)
elif args.add_user:
    insp.add_user(args.uid, args.secdata)
