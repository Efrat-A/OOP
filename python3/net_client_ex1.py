import socket

# clinet side, udp, tcp

def main_udp():
    host = '127.0.0.1'
    port = 5022 #has to be different
    server = ('127.0.0.1',5021)
    try:
        #exacly like in server
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((host,port))
        #
        msg = input('->')
        while msg != 'q':
            s.sendto(msg.encode('utf-8'), server)
            data, addr = s.recvfrom(1024)
            data = data.decode('utf-8')
            print ('recieved: %s' % data)
            msg = input('->')
    except Exception as ex:
        print( ex)
        pass
    finally:
        if s:
            s.close()
        print('client done')


def main_tcp():
    host = '127.0.0.1'
    port = 5021
    try:
        s = socket.socket()
        s.connect((host,port))

        msg = input('->')
        while msg != 'q':
            s.send(msg.encode('utf-8'))
            data = s.recv(1024).decode('utf-8')
            print ('recieved: %s' % data)
            msg = input('->')
    except Exception as ex:
        print( ex)
        pass
    finally:
        s.close()
        print('client error')

# main_tcp()
main_udp()

