import os
def Exists(oldFunc):
    def inside(filename):
        if (os.path.exists(filename)):
            oldFunc(filename)
        else:
            print ('The file does not exist')
    return inside

def outputline(infile):
   with open(infile,'r') as f:
       print (f.readlines())

func = Exists(outputline)
func('decoretor')
func('doesnt.py')


def firat(olffunc):
    def second(arg):
        res = second

        return res+1
    return second

