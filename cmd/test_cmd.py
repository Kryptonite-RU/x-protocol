import argparse
import datetime

parser = argparse.ArgumentParser(description='Ping script')

parser.add_argument('-u', action='store', dest="uid", type=int)
parser.add_argument('-d', action="store", dest="scope")
parser.add_argument('-t', action="store", dest="due")
args = parser.parse_args()

due = datetime.datetime.strptime(args.due, '%Y-%m-%d')
print(args.uid, type(args.uid))
print(args.scope, type(args.scope))
print(args.due, type(due))