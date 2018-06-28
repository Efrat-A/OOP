import threading
import time


class asyncWrite(threading.Thread):
    def __init__(self,text, out):
        threading.Thread.__init__(self)
        self.text = text
        self.out = out

    def run(self):
        f = open(self.out, 'a')
        f.write(self.text + '\n')
        f.close()
        time.sleep(2)
        print ('finished background file write to %s' % self.out)



def main():
    message = input ("enter string to store: ")
    bg = asyncWrite(message,'out.txt')
    bg.start()
    print ('continue')
    print ('conti1nue')
    print ('co1ntinue')
    print ('con1tinue')
    print ('continu1e')
    bg.join()
    print ('bye bye')


if __name__ == '__main__':
    main()
