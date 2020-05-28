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
parser.add_argument('--service', '-src', action="store", dest="src")
parser.add_argument('--auth', '-a', action="store", dest="AUTH")
# actions
parser.add_argument('--form', '-f', action="store_true")
parser.add_argument('--check', '-c', action="store_true")
# data for request
parser.add_argument('--uid','-u', action='store', dest="uid", type=int)
parser.add_argument('--scope', '-s', action="store", dest="scope")
parser.add_argument('--due', '-d', action="store", dest="due")
parser.add_argument('--output', '-o', action="store", default="data/request",dest="output")
# data for checking blob
parser.add_argument('--blob', '-b', action="store", dest="blob")
# data for checking response
parser.add_argument('--response', '-r', action="store", dest="response")

parser.add_argument('--verbose', '-v', action="store_true")

args = parser.parse_args()

if args.src is None:
    src = x.load_src(default.DEFAULT_SERVICE)
    if args.verbose:
        print("No Service file is explicitly given. Default service file will be used.")
else:
    src = x.load_src(args.src)
if args.AUTH is None:
    src.AUTH = x.load_auth(default.DEFAULT_AUTH)
    if args.verbose:
        print("No Auth file is explicitly given. Default Auth file will be used.")
else:
    src.AUTH = x.load_auth(args.AUTH)

if args.form:
    due = datetime.datetime.strptime(args.due, '%Y-%m-%d').date()
    ttl = x.TTL(due)
    req = src.create_request(args.uid, args.scope, ttl)
    if args.verbose:
        print("The following request was formed:")
        print("Src ID: ", req.srcid)
        print("User ID: ", req.uid)
        print("Scope: ", req.scope)
        print("Due to: ", req.ttl.expired)
    x.to_file(args.output, req)
    if args.verbose:
        print("The following file for output was used: ", args.output)
    print("Request was succesfully created. Stored in file: ", args.output)
elif args.check:
    if args.blob is not None:
        d = x.file_to_dict(args.blob)
        blob = x.Blob.from_dict(d)
        if args.verbose:
            print("The following blob file is checked: ", args.blob)
        if src.check_blob(blob):
            print("Correct signature for blob")
        else:
            print("Incorrect signature for blob")
    elif args.response is not None:
        d = x.file_to_dict(args.response)
        resp = x.Response.from_dict(d)
        if args.verbose:
            print("The following response file is checked: ", args.response)
        if src.verify_response(resp):
            print("Correct signature for response")
            if src.check_response(resp):
                print("Blob for this response is correct")
            else:
                print("Blob for this response is incorrect")
        else:
            print("Incorrect signature for response")
    else:
        print("No blob or response were given")
        print("Please provide blob or response file to check")
else:
    print("Please add one of the options to the query:")
    print("1. Add --form to form request")
    print("2. Add --check to check blob signature or response signature and answer")

