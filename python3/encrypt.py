import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random


def encrypt (key,filename):
    chunksize = 64*1024
    outputfile = '(encrypted)%s' % filename
    filesize = str(os.path.getsize(filename)).zfill(16)
    IV = Random.new().read(16)

    encryptor = AES.new(key, AES.MODE_CBC, IV)

    with open(filename, 'rb') as inf:
        with open(outputfile, 'wb') as outfile:
            outfile.write(filesize.encode('utf-8'))
            outfile.write(IV)
            while   True:
                chunk = inf.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) %16 != 0:
                    chunk += b' ' * (16 - (len(chunk)%16))

                outfile.write(encryptor.encrypt(chunk))


def decrypt(key, filename):
    chunksize = 64*1024
    outputfile =filename[11:]
    with open(filename, 'rb') as inf:
        filesize = int(inf.read(16))
        IV = inf.read(16)

        decryptor = AES.new(key, AES.MODE_CBC, IV)

        with open(outputfile, 'wb') as outfile:
            while   True:
                chunk = inf.read(chunksize)
                if len(chunk) ==0:
                    break
                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(filesize)  # out of data, trucate the data into its original size
            #get rid of padding.. 


def getkey(password):
    hasher = SHA256.new(password.encode('utf-8'))
    return hasher.digest()

def main ():
    choise = input('(E) encrypt or (D)ecrypt? : ')
    if choise == 'E':
        filename = input('file to encrypt : ')
        pas =input('password : ')
        encrypt(getkey(pas), filename)
        print ('Fin')
    elif choise == 'D':
        filename =input('file : ')
        pas = input('pass : ')
        decrypt(getkey(pas), filename)
        print ('Fin')
    else:
        print ('No option selected, closinig.. ')

main()
