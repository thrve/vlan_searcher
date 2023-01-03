#!/usr/bin/env python3


import re
import subprocess as sp
import argparse
import signal
import readline
import pexpect
import os


username = os.getenv('LOGIN')
password = os.getenv('PASSWORD')



parser = argparse.ArgumentParser(description='vlansearcher')

parser.add_argument('ip', help='IP address or hostname')
parser.add_argument('-s', dest='st', help='Lower range threshold')
parser.add_argument('-f', dest='fn', help='Upper range threshold')

args = parser.parse_args()


def signal_handler(sig, frame):
    print('\r')
    exit(0)


signal.signal(signal.SIGINT, signal_handler)


class IPChecker():

    ip_re = re.compile(r'(:?(2[0-4]\d|25[0-5]|[01]?\d\d?)\.){3}(2[0-4]\d|25[0-5]|[01]?\d\d?)$')
    hostname_re = re.compile(r'(:?\d\d-[A-Z]+-[A-Z]+\d+-[A-Z]+-\d$)')

    def __init__(self, ip_add):
        if not re.match(self.ip_re,ip_add) and not re.match(self.hostname_re, ip_add):
            print(f'\r{ip_add} cannot be an IP address or hostname.\r')
            exit(0)
        else:
            self.address = ip_add

    def availability(self, address):
        status, result = sp.getstatusoutput('ping -c1 -w2 ' + str(address))
        if status != 0:
            print(f'\rThe {address} is unavailable.\r')
            return 1
        else:
            return 0

class Answer():

    answer_re = re.compile(r'^[yYnN]$')

    def __init__(self, question):
        self.text = question

    def question(self, text):
        while True:
            answer = input(f'\r{text}? y/n: ')
            if not re.match(self.answer_re, answer):
                print('\rValue invalid')
                continue
            else:
                if answer.lower() == 'n':
                    return 1
                else:
                    return 0


if __name__ == '__main__':

    def value_swapper(start, finish):

        print('\rThe beginning of the range is larger than its end.')
        while True:
            answer = Answer('Swap values')
            status = answer.question(answer.text)
            if status == 1:
                exit(0)
            else:
                return finish, start
    
    def stfn_input(start, finish):

        vlan_re = re.compile(r'(?:[1-9]\d{,2}|[1-3]\d{3}|40(?:[0-8]\d|9[0-4]))$')
        while True:
            start = input('start number: ')
            finish = input('finish number: ')
            if not re.match(vlan_re, start) or not re.match(vlan_re, finish):
                print('\rInvalid vlan\r')
                exit(1)
            if finish < start:
                start, finish = value_swapper(start, finish)
                break
            else:
                break
        return start, finish

    def show_vlan(ip, username, password):

        with pexpect.spawn(f'telnet {ip}') as telnet:
             result = ''
             index = telnet.expect(['login', '[Uu]sername', 'User [Nn]ame:'])
             telnet.sendline(username)
             telnet.expect('assword:')
             telnet.sendline(password)
             telnet.expect(['[#>]'])
             telnet.sendline('show vlan')
             while True:
                 index = telnet.expect(['[Mm]ore', '[#>]', '[Ee]rror'])
                 if index == 2:
                    print('\rOS or the vendor is not yet suported\r')
                    exit(1)
                 elif index == 0:
                     telnet.sendline(' ')
                     output = telnet.before.decode('utf-8')
                     result += output
                 else:
                     break

             result = result.split()
             result = [i for i in result if re.findall(r'^\d{1,4}$', i)]
             result = [int(i) for i in result]
        
        return result

    ip_check = IPChecker(args.ip)
    
    if ip_check.availability(ip_check.address) == 1:
        exit(0)

    st = args.st
    fn = args.fn

    if st is None or fn is None:
        print('\rNot enough arguments\r')
        st, fn = stfn_input(st, fn)


    if not re.match(vlan_re, st) or not re.match(vlan_re, fn):
        print('Invalid vlan\r')
        exit(1)
    else:
        if int(st) > int(fn):
            st, fn = value_swapper(st, fn)


    used_vlans = show_vlan(args.ip, username, password)
    result_list = list(set(used_vlans) ^ set(range(1, 4095)))
    result_list = [i for i in result_list if i >= int(st) and i <= int(fn)]

    if len(result_list) == 0:
        print('\rIn the selected range, all vlan numbers are busy')
        exit(0)
    else:
        count = 0
        for i in result_list:
            print(f'{i:>4d}', end=' ')
            count += 1
            if count % 20 == 0:
                print('\r')
    print('\r')
