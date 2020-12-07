import cmd.default as default

def printv(*arg):
    if arg[-1]:
        print(*arg[:-1])

def noexplicit(entity):
    res = "No " + entity + " file is explicitly given."
    res += "Default " + entity + " file will be used."
    return res

def auth_path(args):
    if args.AUTH is None:
        auth_path = default.DEFAULT_AUTH
        msg = noexplicit("Auth")
        printv(msg, args.verbose)
    else:
        auth_path = args.AUTH
    return auth_path

