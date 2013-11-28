#!/usr/bin/env python
"""
Diffie-hellman user1
"""

import socket
import random
from common import *
import ConfigParser

"""
Class that do diffie-Hellman key exchange
"""
def main():
    config = ConfigParser.ConfigParser()		# main 
    config.read('config.cfg')
    host = config.get('networking', 'ip')
    port = int(config.get('networking', 'port'))
    backlog = 5
    size = 1024
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host,port))
    s.listen(backlog)

    client, address = s.accept()

    config1 = ConfigParser.ConfigParser()
    config1.read('config_user1.cfg')
    d=int(config1.get('crypto_key_current', 'current_d'))
    n=int(config1.get('crypto_key_current', 'current_n'))
    e=int(config1.get('crypto_pub_other','other_e'))
    N=int(config1.get('crypto_pub_other','other_n'))

    sa_sign=RSASign(d,n)
    rsa_verify=RSAVerify(e,N)


    data_c1 = client.recv(size)
    prime_num=int(rsa_verify.recv_and_verify(data_c1))
    print "Prime _number Received            :",prime_num                                                      # final modulus value

    generator=find_generator(prime_num)
    priv_key_of_current=random.randint(10000,100000)
    key_by_current=modfun(generator,priv_key_of_current,prime_num)


    data_s1=str(rsa_sign.sign_and_send(key_by_current))
    if data_c1:
        client.send(data_s1)
        print "Key by current Send                 :",key_by_current

    data_c2=client.recv(size)
    key_from_other=int(rsa_verify.recv_and_verify(data_c2))
    print "Key from other Received           :",key_from_other

    if data_c2:
        final_key_current=modfun(key_from_other,priv_key_of_current,prime_num)
        data_s2=str(rsa_sign.sign_and_send(final_key_current))
        client.send(data_s2)
        print "Final key from current Send         :",final_key_current

    data_c3=client.recv(size)
    final_key_other=int(rsa_verify.recv_and_verify(data_c3))
    print "final key from other Received     :", final_key_other

    client.close()

    if final_key_current==final_key_other:
        print "Key Exchange done!!!"
    else:
        print "Oops,Key exchange failed.\nTry again!"

if __name__ == "__main__":
    main()
