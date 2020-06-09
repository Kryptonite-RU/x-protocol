import argparse
import xproto as x
import datetime
import sys
import cmd.default as default
from cmd.utils import printv, noexplicit, auth_path

# Two types of operations for inspector are possible:
# verify blob (full verification with response as a result)
# add user with personal information 

def check_args(args):
    if not(args.verify or args.add):
        print("Please add one of the options to the query:")
        print("1. Add --verify to form response")
        print("2. Add --add to add user personal information")
        return False

    if args.verify:
        if args.blob is None:
            print("Please provide blob to verify")
            return False
    else:  # i.e. args.add
        if args.secdata is None:
            print("Please provide personal data")
            return False
        if args.uid is None:
            print("Please provide user ID")
            return False
    return True


def parse_CLI(arguments):
    parser = argparse.ArgumentParser(description='Inspector script')
    # entities
    parser.add_argument('--inspector', '-i', action="store", dest="insp")
    parser.add_argument('--auth', '-a', action="store", dest="AUTH")
    # actions
    parser.add_argument('--verify', action="store_true")
    parser.add_argument('--add', action="store_true")
    # data for blob verifications
    parser.add_argument('--blob', '-b', action="store", dest="blob")
    parser.add_argument('--output', '-o', action="store",  
            default = "data/response", dest="output")
    # data for user registration
    parser.add_argument('--uid', '-u', action='store', dest="uid", type=int)
    parser.add_argument('--secdata', '-s', action="store", dest="secdata")
    parser.add_argument('--verbose', '-v', action="store_true")
    args = parser.parse_args()
    check = check_args(args)
    if check:
        return args
    else:
        return None

# load entities from files
def load_insp(args):
    if args.insp is None:
        insp_path = default.DEFAULT_INSPECTOR
        msg = noexplicit("Inspector")
        printv(msg, args.verbose)
    else:
        insp_path = args.insp

    try:
        insp = x.load_insp(insp_path)
        insp.AUTH = x.load_auth(auth_path(args))
    except:
        print("Error when trying to load Inspector or/and Auth file")
        print("Inspector path: ", insp_path)
        print("Auth path: ", auth_path(args))
        insp = None
    return insp, insp_path


def run_verify(args):
    insp, insp_path = load_insp(args)
    try:
        d = x.file_to_dict(args.blob)
        blob = x.Blob.from_dict(d)
        try:
            resp = insp.verify_blob(blob)
            x.to_file(args.output, resp)
            print("The Response was succesfully created. Stored in file: ", args.output) 
        except:
            print("Error when trying to validate blob")
    except:
        print("Error when trying to parse given blob")

def run_adduser(args):
    insp, insp_path = load_insp(args)
    insp.add_user(args.uid, args.secdata)
    print("User personal data was succesfully added")
    x.to_file(insp_path, insp)
    x.to_file(auth_path(args), insp.AUTH)


if __name__ == "__main__":
    args = parse_CLI(sys.argv[1:])
    if args is not None:
        if args.verify:
            run_verify(args) 
        else:
            run_adduser(args)
