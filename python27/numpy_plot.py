import numpy as np
import random

import matplotlib.pyplot as plt
##for the notebook - webpage ploting
#%matplotlib inline

################################################
# plot sin(4x)*exp(-x),  cos(4x)*exp(-x) from 0 to 5
###############################################

x = np.linspace(0,5,100) #create 100 points from 0 to 5, linearly spaced 

y = np.sin(4*x)*np.exp(-x)

z = np.cos(4*x)*np.exp(-x)

plt.figure() # can do (1) identification if there'll be other figures

# instead of creating a plot line we can use scatter
# color can get a list of colors !!
# pt.scatter(x,y,...)
# pt.bar (x,y)
# pt.barh (x,y)  # horizental bar graph

plt.plot(x,y,'r--', label='$e^{-x} sin(4x)$') # red, dashed line, label in the legend
#plt.plot(x,z)
plt.plot(x,z,label='$e^{-x} * cos(4x)$',linewidth=2.0) # $and {}, makes it look like math equation

plt.xlabel('x')
plt.ylabel('value')

# plt.xlim(-1,1)  # axis limits  xlim, ylim

plt.legend()

#save it
plt.savefig('myfigure.png')
plt.show()


# analyze in pandas

