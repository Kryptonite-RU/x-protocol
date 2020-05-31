import argparse
import xproto as x
import datetime
import cmd.default as default

# Two types of operations for inspector are possible:
# verify blob (full verification with response as a result)
# add user with personal information 

parser = argparse.ArgumentParser(description='Inspector script')
# entities
parser.add_argument('--inspector', '-i', action="store", dest="insp")
parser.add_argument('--auth', '-a', action="store", dest="AUTH")
# actions
parser.add_argument('--verify', action="store_true")
parser.add_argument('--add', action="store_true")
# data for blob verifications
parser.add_argument('--blob', '-b', action="store", dest="blob")
parser.add_argument('--output', '-o', action="store", default = "data/response", dest="output")
# data for user registration
parser.add_argument('--uid', '-u', action='store', dest="uid", type=int)
parser.add_argument('--secdata', '-s', action="store", dest="secdata")
parser.add_argument('--verbose', '-v', action="store_true")

args = parser.parse_args()

# load entities from files
if args.insp is None:
    insp_path = default.DEFAULT_INSPECTOR
    if args.verbose:
        print("No Inspector file is explicitly given. Default Inspector file will be used.")
else:
    insp_path = args.insp

if args.AUTH is None:
    auth_path = default.DEFAULT_AUTH
    if args.verbose:
        print("No Auth file is explicitly given. Default Auth file will be used.")
else:
    auth_path = args.AUTH

insp = x.load_insp(insp_path)
insp.AUTH = x.load_auth(auth_path)

if args.verify:
    if args.blob is None:
        print("Please provide blob to verify")
    else:
        try:
            d = x.file_to_dict(args.blob)
            blob = x.Blob.from_dict(d)
        except:
            print("Error when trying to parse given blob")
            blob = None
        if blob is not None:
            try:
                resp = insp.verify_blob(blob)
                x.to_file(args.output, resp)
                print("The Response was succesfully created. Stored in file: ", args.output) 
            except:
                print("Error when trying to validate blob")
elif args.add:
    if args.secdata is None:
        print("Please provide personal data")
    elif args.uid is None:
        print("Please provide user ID")
    else:
        insp.add_user(args.uid, args.secdata)
else:
    print("Please add one of the options to the query:")
    print(" --verify to verify blob")
    print(" --add to add user to database with personal information")

x.to_file(insp_path, insp)
x.to_file(auth_path, insp.AUTH)
