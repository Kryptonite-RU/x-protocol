import argparse
import xproto as x
import datetime
import cmd.default as default
import sys
from cmd.utils import printv, noexplicit, auth_path

# Two types of operations for user are possible:
# form blob 
# check request (signature)
def check_args(args):
    if not(args.form or args.check):
        print("Please add one of the options to the query:")
        print("1. Add --form to form blob")
        print("2. Add --check to check request signature")
        return False

    if (args.req is None):
        print("Please provide request file")
        return False

    return True


def parse_CLI(arguments):
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
    parser.add_argument('--output', '-o', action="store", \
                        default="data/blob", dest="output")
    parser.add_argument('--verbose', '-v', action="store_true")
    args = parser.parse_args()
    check = check_args(args)
    if check:
        return args
    else:
        return None

def load_usr(args):
    if args.usr is None:
        usr_path = default.DEFAULT_USER
        msg = noexplicit("User")
        printv(msg, args.verbose)
    else:
        usr_path = args.usr

    try:
        usr = x.load_usr(usr_path)
        usr.AUTH = x.load_auth(auth_path(args))
    except:
        print("Error when trying to load User or/and Auth file")
        print("User path: ", usr_path)
        print("Auth path: ", auth_path(args))
        usr = None
    return usr, usr_path


def run_check(args):
    usr, usr_path = load_usr(args)
    if usr is None:
        print("No user file is provided.")
        return None
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

def run_form(args):
    usr, usr_path = load_usr(args)
    if usr is None:
        print("No user file is provided.")
        return None
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
            x.to_file(usr_path, usr)
            x.to_file(auth_path(args), usr.AUTH)



if __name__ == "__main__":
    args = parse_CLI(sys.argv[1:])
    if args is not None:
        run_form(args) if args.form else run_check(args)
