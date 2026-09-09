#!/usr/bin/env python3
import sys
def v(n):
 b=[]
 while n>127: b.append((n&127)|128); n>>=7
 return bytes(b+[n])
def f(num,data): return v((num<<3)|2)+v(len(data))+data
tag=sys.argv[1].encode()
anyv=f(1,tag)
record=v(2<<3)+v(9)+f(3,b'INFO')+f(5,anyv)
scope=f(2,record)
resource=f(2,scope)
sys.stdout.buffer.write(f(1,resource))
