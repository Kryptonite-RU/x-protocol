import argparse
import sys
import xproto as x
import cmd.default as default
from cmd.utils import printv, noexplicit, auth_path

def parse_CLI(arguments):
    parser = argparse.ArgumentParser(description='AuthCenter script')
    parser.add_argument('--verbose', '-v', action="store_true")
    parser.add_argument('--output', '-o', action="store", dest="output")

    args = parser.parse_args()
    check = check_args(args)
    if check:
        return args
    else:
        return None


def check_args(args):
    return True


def run_create(args):
    if args.output is not None:
        out_file = args.output
    else:
        out_file = default.DEFAULT_AUTH
        printv("No output path was provided.", args.verbose)
    if args.verbose:    
        print("The following file for output is used: ", out_file)
    printv("Creating auth center file.", args.verbose)
    AUTH = x.AuthCenter()
    x.to_file(out_file, AUTH)
    printv("Auth Center file was succesfully generated.", args.verbose)


if __name__ == "__main__":
    args = parse_CLI(sys.argv[1:])
    if args is not None:
        run_create(args)
