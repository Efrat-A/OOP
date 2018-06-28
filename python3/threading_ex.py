#from threading import Thread
import time
import threading


#extra - using lock
tlock = threading.Lock()


def timer(name,delay,repeat):
    print ('timer; %s started' % name)
    tlock.acquire()   # wait on lock
    print ('timer; %s acquired the lock' % name)
    while repeat > 0:
        time.sleep(delay)
        print ('%s: %s' % (name, time.ctime(time.time())))
        repeat -= 1
    print ('timer; %s is releasing the lock' % name)
    tlock.release()  #release lock
    print('timer; %s complete' % name)


def main():
    t1 = threading.Thread(target=timer, args=('timer1',1,5))
    t2 = threading.Thread(target=timer, args=('timer2',2,5))
    t1.start()
    t2.start()
    print('bye bye')

if __name__ == '__main__':
    main()
