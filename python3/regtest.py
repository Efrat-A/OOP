import re
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('word', help='word to find')
    parser.add_argument('fname',help='specify file to find')
    args = parser.parse_args()
    
    f= open(args.fname)
    n = 0
    for line in f.readlines():
        line = line.strip('\n\r')
        n += 1
        r = re.search(args.word, line, re.M|re.I)
        if r:
            print(str(n) + ': ' + line)
    f.close()
    
    # myreg = re.compile(pattern)
    # res = myreg.match(string)


def m():
    line = "I think I understand regular expressions"

    matchResult = re.match('think', line, re.M|re.I)
    if matchResult:
        print("match found: "+ matchResult.group())
    else:
        print("match failed")

    searchRes = re.search('think', line, re.M|re.I)
    if searchRes:
        print("search found: "+searchRes.group())
    else:
        print("search failed")

if __name__ == '__main__':
    main()
