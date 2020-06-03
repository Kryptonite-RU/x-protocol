import argparse
import xproto as x
import datetime
import cmd.default as default
import sys
from cmd.utils import printv, noexplicit, auth_path

# Three types of operations for service are possible:
# form request
# check blob (signature)
# check response (signature + answer)

def check_args(args):
    if not(args.form or args.check):
        print("Please add one of the options to the query:")
        print("1. Add --form to form request")
        print("2. Add --check to check blob signature or response signature and answer")
        return False

    if args.form:
        if (args.uid is None or args.scope is None or args.due is None):
            print("Please provide three required options to form request:")
            print("1. UID: user ID;")
            print("2. Scope: personal data scope;")
            print("3. DUE: blob expiration date;")
            return False

    elif args.check:
        if (args.blob is None and args.response is None):
            print("Please provide Blob or Response file to check it")
            return False
    return True


def parse_CLI(arguments):
    parser = argparse.ArgumentParser(description='Service script')
    # entities
    parser.add_argument('--service', '-src', action="store", dest="src")
    parser.add_argument('--auth', '-a', action="store", dest="AUTH")
    # actions
    # one of those must be provided
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
    args = parser.parse_args(arguments)
    check = check_args(args)
    if check:
        return args
    else:
        return None


def load_src(args):
    if args.src is None:
        src_path = default.DEFAULT_SERVICE
        msg = noexplicit("Service")
        printv(msg, args.verbose)
    else:
         src_path = args.src
    try:
        src = x.load_src(src_path)
        src.AUTH = x.load_auth(auth_path(args))
    except:
        print("Error when trying to load Src or/and Auth file")
        print("Service path: ", src_path)
        print("Auth path: ", auth_path(args))
        src = None
    return src


def run_check(args):
    src = load_src(args)
    if src is None:
        print("No service file is provided.")
        return None
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


def run_form(args):
    src = load_src(args)
    if src is None:
        print("No service file is provided.")
        return None
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
    x.to_file(src_path, src)
    x.to_file(auth_path, src.AUTH)


if __name__ == "__main__":
    args = parse_CLI(sys.argv[1:])
    if args is not None:
        run_form(args) if args.form else run_check(args)

 
# 
# x.to_file(src_path, src)
# x.to_file(auth_path, src.AUTH)
