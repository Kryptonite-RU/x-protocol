import argparse
import xproto as x
import datetime
import cmd.default as default

# Two types of operations for user are possible:
# form blob 
# check request (signature)

parser = argparse.ArgumentParser(description='User script')
# entities
parser.add_argument('--user', '-u', action="store", dest="usr")
parser.add_argument('--auth', '-a', action="store", dest="AUTH")
# actions
parser.add_argument('--form', '-f', action="store_true")
parser.add_argument('--check', '-c', action="store_true")
# data for forming blob 
parser.add_argument('--request', '-r', action="store", dest="req")
parser.add_argument('--secdata', '-s', action="store", dest="secdata")
parser.add_argument('--output', '-o', action="store", default="data/blob", dest="output")

parser.add_argument('--verbose', '-v', action="store_true")

args = parser.parse_args()

if args.usr is None:
    usr = x.load_usr(default.DEFAULT_USER)
    if args.verbose:
        print("No User file is explicitly given. Default User file will be used.")
else:
    usr = x.load_usr(args.usr)
if args.AUTH is None:
    usr.AUTH = x.load_auth(default.DEFAULT_AUTH)
    if args.verbose:
        print("No Auth file is explicitly given. Default Auth file will be used.")
else:
    usr.AUTH = x.load_auth(args.AUTH)

if args.form:
    if args.req is None:
        print("Please provide request to answer")
    else:
        d = x.file_to_dict(args.req)
        req = x.Request.from_dict(d)
        try:
            blob = usr.create_blob(req, data=args.secdata)
        except:
            print("Problems with forming Blob. Request might be damaged or wrong")
            blob = None
        if blob is not None:
            x.to_file(args.output, blob)
            print("The blob was succesfully created. Stored in file: ", args.output) 
elif args.check:
    if args.req is None:
        print("Please provide request to check")
    else:
        d = x.file_to_dict(args.req)
        try:
            req = x.Request.from_dict(d)
            if usr.check_request(req):
                print("Correct signature for request")
            else:
                print("Incorrect signature for request")
        except:
            print("Wrong request format. Cannot parse.")
else:
    print("Please add one of the options to the query:")
    print("1. Add --form to form blob")
    print("2. Add --check to check request signature")

