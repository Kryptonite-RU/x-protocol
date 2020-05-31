import argparse
import xproto as x
import datetime
import cmd.default as default

parser = argparse.ArgumentParser(description='Registration script')

parser.add_argument('--service', '-s', action="store_true", dest="src")
parser.add_argument('--user', '-u', action="store_true", dest="usr")
parser.add_argument('--inspector', '-i', action="store_true", dest="insp")
parser.add_argument('--scope', action="store", dest="scope")
parser.add_argument('--auth', '-a', action="store", dest="auth")
parser.add_argument('--key' '-k', action="store", dest="key")
parser.add_argument('--output', '-o', action="store", dest="output")
parser.add_argument('--verbose', '-v', action="store_true")

args = parser.parse_args()

if not(args.src or args.usr or args.insp):
    print("Please provide one entity (service/user/inspector) to create.")
else:
    if args.auth is None:
        auth_path = default.DEFAULT_AUTH
        if args.verbose:
            print("No Auth file is explicitly given. Default Auth file will be used.")
    else:
        auth_path = args.auth

    AUTH = x.load_auth(auth_path)

    if args.key is None:
        keys = x.crypto.KeyPair()
        if args.insp is not None:
            keys2 = x.crypto.KeyPair()
        if args.verbose:
            print("No key file were provided, random key is generated")
    else:
        with open(args.key, mode='rb') as file:
            raw = file.read(32)
            if args.inspector is not None:
                raw2 = file.read(32)
                keys2 = x.crypto.KeyPair(raw_key=raw2)
        keys = x.crypto.KeyPair(raw_key=raw)
        if args.verbose:
            print("Key file ", args.key, " was used to generate the key(s)")
    
    if args.src:
        if args.verbose:
            print("Generating Service file...")
        src = x.Service(keys=keys)
        AUTH.reg_service(src)
        if args.output is not None:
            out_file = args.output
        else:
            out_file = default.DEFAULT_SERVICE
            if args.verbose:
                print("No output path was provided.")
        if args.verbose:    
            print("The following file for output is used: ", out_file)
        x.to_file(out_file, src)
        if args.verbose:
            print("Service file was successfully created.")

    elif args.usr:
        if args.verbose:
            print("Generating User file...")
        usr = x.AgentUser(keys=keys)
        AUTH.reg_user(usr)
        if args.output is not None:
            out_file = args.output
        else:
            out_file = default.DEFAULT_USER 
            if args.verbose:
                print("No output path was provided.")
        if args.verbose:    
            print("The following file for output is used: ", out_file)
        x.to_file(out_file, usr)
        if args.verbose:
            print("User file was successfully created.")

    elif args.insp:
        if args.scope is None:
            print("Please provide inspector's scope.")
        else:
            if args.verbose:
                print("Generating Inspector file...")
            insp = x.Inspector(args.scope, keys_sign=keys, keys_vko=keys2)
            AUTH.reg_inspector(insp)
            if args.output is not None:
                out_file = args.output
            else:
                out_file = default.DEFAULT_INSPECTOR 
                if args.verbose:
                    print("No output path was provided.")
            if args.verbose:    
                print("The following file for output is used: ", out_file)
            x.to_file(out_file, insp)
            if args.verbose:
                print("Inspector file was successfully created.")
    x.to_file(auth_path, AUTH)
