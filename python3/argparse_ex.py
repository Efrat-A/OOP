import argparse
import sys


def fib(n):
    a, b = 0, 1
    for i in range(n):
        a,b = b, a+b
    return a

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
   #adding a group
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-v','--vebose', action='store_true')
    group.add_argument('-q','--quiet',action='store_true')

    parser.add_argument("num", help='the fibonacci you wish to calc', type=int)
    parser.add_argument("-o","--output", help='output to file',action="store_true")


    args = parser.parse_args()
    
    print ("the n fib num is %d" % fib(args.num))
    if args.verbose
    sys.exit(0)
