import argparse
import xproto as x
import datetime
import cmd.default as default

# Three types of operations for service are possible:
# form request
# check blob (signature)
# check response (signature + answer)

parser = argparse.ArgumentParser(description='Parser script')
# entities
parser.add_argument('--service', '-src', action="store", dest="src")
parser.add_argument('--user', '-u', action="store", dest="usr")
parser.add_argument('--inspector', '-i', action="store", dest="insp")
parser.add_argument('--auth', '-a', action="store", dest="AUTH")
parser.add_argument('--request', '-req', action="store", dest="req")
parser.add_argument('--blob', '-b', action="store", dest="blob")
parser.add_argument('--response', '-resp', action="store", dest="response")

parser.add_argument('--database', '-db', action="store_true")
parser.add_argument('--keys', '-k', action="store_true")

args = parser.parse_args()

if args.src is not None:
    try:
        src = x.load_src(args.src)
        print("Service ID: ", src.ID)
        if args.keys:
            print("Service public key: ", src.key_pair.public.key)
        if args.database:
            print()
            print()
            print("SERVICE DATABASE")
            print()
            for k in src.database.keys():
                print(k)
                print()
                print(src.database[k])
                print()
                print()
    except:
        print("Wrong service file was given.")
elif args.usr is not None:
    try:
        usr = x.load_usr(args.usr)
        print("User ID: ", usr.ID)
        if args.keys:
            print("User public key: ", usr.key_pair.public.key)
        if args.database:
            print()
            print()
            print("USER DATABASE")
            print()
            for k in usr.database.keys():
                print(k)
                print()
                print(usr.database[k])
                print()
                print()
    except:
        print("Wrong user file was given.")
elif args.insp is not None:
    try:
        insp = x.load_insp(args.insp)
        print("Inspector ID: ", insp.ID)
        print("Inspector scope: ", insp.scope)
        if args.keys:
            print("Inspector public (VKO): ", insp.vko_pair.public.key)
            print("Inspector public  (sign): ", insp.sign_pair.public.key)
        if args.database:
            print()
            print()
            print("INSPECTOR DATABASE")
            print()
            for k in insp.database.keys():
                print(k)
                print()
                print(insp.database[k])
                print()
                print()
    except:
        print("Wrong inspector file was given.")
elif args.AUTH is not None:
    try:
        auth = x.load_auth(args.auth)
        if args.database:
            pass
    except:
        print("Wrong AUTH file was given.")
elif args.req is not None:
    try:
        req = x.Request.from_dict(x.file_to_dict(args.req))
        print(req)
    except:
        print("Wrong Request file was given.")
elif args.blob is not None:
    try:
        blob = x.Blob.from_dict(x.file_to_dict(args.blob))
        print(blob)
    except:
        print("Wrong Blob file was given.")
elif args.response is not None:
    try:
        resp = x.Response.from_dict(x.file_to_dict(args.response))
        print(resp)
    except:
        print("Wrong Response file was given.")
