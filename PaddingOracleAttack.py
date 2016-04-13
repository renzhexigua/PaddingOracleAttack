#!/usr/bin/env python
#-*- coding:utf-8 -*-

import re
import binascii

ivFakes = []
ivStd = 'cac544d7942e50e1a0afa156c803d115'
validPad = '10101010101010101010101010101010'

cipher = 'cac544d7942e50e1a0afa156c803d115'\
         '084b0199778f14767cbdc989872a1f7d'\
         'a59da498c81017fd2adc534610b412e4'\
         '8f50d05513a440425f5ca434e5cb29c6'\
         'b9110412ebeb347ee63a6b1849794f92'
cipherblock = re.findall(r'(.{32})', cipher)[:-1]

with open('proj4-log.txt') as f:
    for line in f:
        if '404' in line.split(' ')[-1].strip():
            mat = re.search(r'GET /(?P<iv>\S+) HTTP', line).group('iv')
            if '20' not in mat:
                ivFakes.append(mat[:32])
    ivFakes.pop(0)

def xorStrings(xs, ys):
    ret = ""
    xL = re.findall(r'(.{2})', xs)
    yL = re.findall(r'(.{2})', ys)
    for x, y in zip(xL, yL):
        xor = format(int(x, 16) ^ int(y, 16), '#04x')[2:]
        ret += xor
    return ret

def hex2str(s):
    return binascii.a2b_hex(s).decode()
        
for iv, cb in zip(ivFakes, cipherblock):
    interVal = xorStrings(iv, validPad)
    print("interVal\t", interVal)
    plainHex = xorStrings(interVal, cb)
    print("PlainHex->\t", plainHex)
    print("PlainText-->\t", hex2str(plainHex))
