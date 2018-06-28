import numpy as np
import time

l=[0]*200000
t1 = time.time()
for i in xrange(0,len(l)):  l[i]+=2
t1 = time.time() - t1
print 'Time taken xrange  %fms' % t1

l=[0]*200000
t1 = time.time()
l = map(lambda x: x+2, l)
t1 = time.time() - t1
print 'Time taken map  %fms' % t1

L = np.array( [0]*200000 )
t2 = time.time()
L += 2
t2 = time.time() - t2
print 'Time taken numpy %fms' % t2

