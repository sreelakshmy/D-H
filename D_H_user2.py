#!/usr/bin/env python
"""
Diffie-hellman user2
"""
import socket
import random
from common import *
import ConfigParser
def main():                                                                             # main 
    config = ConfigParser.ConfigParser()
    config.read('config.cfg')
    host = config.get('networking', 'ip')
    port = int(config.get('networking', 'port'))

    lower_range=int(config.get('crypto','lower_range_DH'))
    upper_range=int(config.get('crypto','upper_range_DH'))

    prime_num=int(generate_prime(lower_range,upper_range))

    size = 1024
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host,port))

    generator=find_generator(prime_num)
    priv_key_of_current=random.randint(10000,10000)
    key_by_current=modfun(generator,priv_key_of_current,prime_num)

    config1 = ConfigParser.ConfigParser()
    config1.read('config_user2.cfg')
    d=int(config1.get('crypto_key_current', 'current_d'))
    n=int(config1.get('crypto_key_current', 'current_n'))
    e=int(config1.get('crypto_pub_other','other_e'))
    N=int(config1.get('crypto_pub_other','other_n'))

    rsa_sign=RSASign(d,n)
    rsa_verify=RSAVerify(e,N)

    data_c1=str(rsa_sign.sign_and_send(prime_num))
    s.send(data_c1)
    print "Prime number Send                    :",prime_num

    data_s1 = s.recv(size)
    key_from_other=int(rsa_verify.recv_and_verify(data_s1))
    print "key from other Received              :", key_from_other

    final_key_current=modfun(key_from_other,priv_key_of_current,prime_num)

    data_c2=str(rsa_sign.sign_and_send(key_by_current))
    if data_s1:
        s.send(data_c2)
        print "Key from current Send                  :",key_by_current

    data_s2 = s.recv(size)
    final_key_other=int(rsa_verify.recv_and_verify(data_s2))
    print "Final Key from other Received        :",final_key_other

    data_c3=str(rsa_sign.sign_and_send(final_key_current))
    if data_s2:
        s.send(data_c3)
        print "Final key from current Send            :",final_key_current
    s.close()

    if final_key_other==final_key_current:
            print "Key Exchange done!!!"
    else:
            print "Oops,Key exchange failed.\nTry again!"


if __name__ == "__main__":
    main()
