
# python 2.7 
##################################################
# check None val with : is :
##################################################


##################################################
### never set dafault value of list like: l=[]  ##
##################################################
# it will create new list each time
# solution is to set to None and in the begining of the func  l = [] if l is None else l

def f(p=[]):  # BAD
    p.append(0)
    return p
'''
>>> f()
[0]
>>> f()
[0,0]
'''

def f(p=None):
    p = [] if p is None else p
    p.append(0)
    return p

'''
>>> f()
[0]
>>> f()
[0]
'''

#
#  *args - tuple
#  **kargs - dictionary
#
def sum_two_or_more(num1, num2, *args):
    res = num1 + num2
    for num in args:
        res += num
    return res
'''
>>> sum_two_or_more(1,2)
3
>>> sum_two_or_more(1,2,4,5)
15
'''
