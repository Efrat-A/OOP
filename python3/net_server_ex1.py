import socket

# server side, udp and  tcp
# returns the input capitalised

def main_udp():
    host = '127.0.0.1'
    port = 5021
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((host,port))

        print ('server started')
        while True:
            data ,addr = s.recvfrom(1024)
            data = data.decode('utf-8')
            print ('%s recv from user: %s' % (data,str(addr)))
            data = data.upper()
            print ('sending: %s' % data)
            s.sendto(data.encode('utf-8'), addr)
        s.close()
        s = None
    except Exception as ex:
        print (ex)
        pass
    finally:
        print('closing server')
        if s: 
            s.close()

def main_tcp():
    host = '127.0.0.1'
    port = 5021
    c = None
    try:
        s = socket.socket()
        s.bind((host,port))

        s.listen(1) # one connection at a time
        c, addr = s.accept()

        print ('connection from %s' % str(addr))
        while True:
            data = c.recv(1024).decode('utf-8')
            if not data:
                break
            print ('recv from user: %s' % data)
            data = data.upper()
            print ('sending: %s' % data)
            c.send(data.encode('utf-8'))
        c.close()
        c=None
    except Exception as ex:
        print (ex)
        pass
    finally:
        print('closing server')
        if c: 
            c.close()
# main_tcp()
main_udp()

