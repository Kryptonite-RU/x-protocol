import argparse
import xproto as x
import cmd.default as default

parser = argparse.ArgumentParser(description='AuthCenter script')
parser.add_argument('--verbose', '-v', action="store_true")
parser.add_argument('--output', '-o', action="store", dest="output")

args = parser.parse_args()

if args.output is not None:
    out_file = args.output
else:
    out_file = default.DEFAULT_AUTH
    if args.verbose:
        print("No output path was provided.")
if args.verbose:    
    print("The following file for output is used: ", out_file)

if args.verbose:
    print("Creating auth center file.")
AUTH = x.AuthCenter()
x.to_file(out_file, AUTH)
if args.verbose:
    print("Auth Center file was succesfully generated.")

