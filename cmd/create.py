import argparse
import xproto as x
import datetime
import cmd.default as default
import sys
from cmd.utils import printv, auth_path


def check_args(args):
    if not(args.src or args.usr or args.insp):
        print("Please provide one entity (service/user/inspector) to create.")
        return False
    if args.insp and (args.scope is None):
        print("Please provide inspector's scope.")
        return False
    return True


def create_keys(args):
    if args.key is None:
        keys = [x.crypto.KeyPair()]
        if args.insp is not None:
            keys.append(x.crypto.KeyPair())
        printv("No key file was provided, random key is generated", args.verbose)
    else:
        with open(args.key, mode='rb') as file:
            raw = file.read(32)
            keys = [x.crypto.KeyPair(raw_key=raw)]
            if args.insp is not None:
                raw2 = file.read(32)
                keys.append(x.crypto.KeyPair(raw_key=raw2))
        printv("Key file ", args.key, " was used to generate the key(s)", args.verbose)
    return keys
    


def create_inspector(args, AUTH):
    printv("Generating Inspector file...", args.verbose)
    keys = create_keys(args)
    insp = x.Inspector(args.scope, keys_sign=keys[0], keys_vko=keys[1])
    AUTH.reg_inspector(insp)
    if args.output is not None:
        out_file = args.output
    else:
        out_file = default.DEFAULT_INSPECTOR 
        printv("No output path was provided.", args.verbose)
    printv("The following file for output is used: ", out_file, args.verbose)
    x.to_file(out_file, insp)
    printv("Inspector file was successfully created.", args.verbose)

def create_user(args, AUTH):
    printv("Generating User file...", args.verbose)
    keys = create_keys(args)
    usr = x.AgentUser(keys=keys[0])
    AUTH.reg_user(usr)
    if args.output is not None:
        out_file = args.output
    else:
        out_file = default.DEFAULT_USER 
        printv("No output path was provided.",args.verbose)
    printv("The following file for output is used: ", out_file, args.verbose)    
    x.to_file(out_file, usr)
    printv("User file was successfully created.", args.verbose)


def create_service(args, AUTH):
    printv("Generating Service file...",args.verbose)
    keys = create_keys(args)
    src = x.Service(keys=keys[0])
    AUTH.reg_service(src)
    if args.output is not None:
        out_file = args.output
    else:
        out_file = default.DEFAULT_SERVICE
        printv("No output path was provided.",args.verbose)
    printv("The following file for output is used: ", out_file, args.verbose)    
    x.to_file(out_file, src)
    printv("Service file was successfully created.",args.verbose)



def parse_CLI(arguments):
    parser = argparse.ArgumentParser(description='Registration script')
    parser.add_argument('--service', '-s', action="store_true", dest="src")
    parser.add_argument('--user', '-u', action="store_true", dest="usr")
    parser.add_argument('--inspector', '-i', action="store_true", dest="insp")
    parser.add_argument('--scope', '-S', action="store", dest="scope")
    parser.add_argument('--auth', '-a', action="store", dest="AUTH")
    parser.add_argument('--key' '-k', action="store", dest="key")
    parser.add_argument('--output', '-o', action="store", dest="output")
    parser.add_argument('--verbose', '-v', action="store_true")
    args = parser.parse_args(arguments)
    check = check_args(args)
    if check:
        return args
    else:
        return None

if __name__ == "__main__":
    args = parse_CLI(sys.argv[1:])
    if args is not None:
        AUTH = x.load_auth(auth_path(args))
        if args.src:
            create_service(args, AUTH)
        elif args.usr:
            create_user(args, AUTH)
        else:
            create_inspector(args, AUTH)
        x.to_file(auth_path(args),AUTH) 
