#!/usr/bin/env python3
# SPDX-License-Identifier: 0BSD
"""Independent, offline URMA multipart proof reader (Python stdlib only).
No chain-inclusion claim. Uses public test crypto arithmetic, not constant-time.
Sources must be trusted local directories; never runs Git or application payloads.
"""
import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path
import tempfile

P = 2**256-2**32-977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
C, F, MAX = 262132, 511, 8553279476


class Invalid(Exception): pass
class Incomplete(Exception): pass
class Candidate(Exception): pass
class Capacity(Exception): pass


def require(condition, message):
    if not condition: raise Invalid(message)


def sha(b): return hashlib.sha256(b).digest()
def uint(n,k): return n.to_bytes(k,'little')
def tagged(tag,b):
    h=sha(tag.encode());return sha(h+h+b)


def point_add(a,b):
    if a is None:return b
    if b is None:return a
    x,y=a;u,v=b
    if x==u and (y+v)%P==0:return None
    m=((3*x*x)*pow(2*y,-1,P) if a==b else (v-y)*pow(u-x,-1,P))%P
    z=(m*m-x-u)%P
    return z,(m*(x-z)-y)%P


def point_mul(n,a=G):
    r=None
    while n:
        if n&1:r=point_add(r,a)
        a=point_add(a,a);n>>=1
    return r


def lift(x):
    require(x<P,'x outside field')
    y=pow((x*x*x+7)%P,(P+1)//4,P)
    require(y*y%P==(x*x*x+7)%P,'not a curve point')
    return x, P-y if y&1 else y


def compact(n):
    if n<253:return bytes([n])
    if n<=65535:return b'\xfd'+uint(n,2)
    if n<=2**32-1:return b'\xfe'+uint(n,4)
    return b'\xff'+uint(n,8)


def vector(b):return compact(len(b))+b


class Reader:
    def __init__(self,b):self.b=b;self.pos=0
    def take(self,n):
        require(n>=0 and self.pos+n<=len(self.b),'truncated bytes')
        r=self.b[self.pos:self.pos+n];self.pos+=n;return r
    def number(self,n):return int.from_bytes(self.take(n),'little')
    def count(self):
        tag=self.number(1)
        if tag<253:return tag
        n=self.number({253:2,254:4,255:8}[tag])
        require(n>={253:253,254:65536,255:2**32}[tag],'noncanonical compact size')
        return n
    def vec(self):return self.take(self.count())
    def end(self):require(self.pos==len(self.b),'trailing bytes')


def transaction(raw):
    require(len(raw)<=4_000_000,'local raw transaction capacity')
    r=Reader(raw);version=r.take(4);witness=raw[4:6]==b'\x00\x01'
    if witness:r.take(2)
    start=r.pos;count=r.count();require(1<=count<=len(raw)//41,'input count')
    inputs=[(r.take(32),r.number(4),r.vec(),r.take(4)) for _ in range(count)]
    n=r.count();require(1<=n<=len(raw)//9,'output count')
    outputs=[(r.number(8),r.vec()) for _ in range(n)]
    end=r.pos
    stacks=[]
    if witness:
        for _ in inputs:
            k=r.count();require(k<=len(raw),'stack count');stacks.append([r.vec() for _ in range(k)])
    lock=r.take(4);r.end()
    txid=sha(sha(version+raw[start:end]+lock))
    return {'txid':txid,'version':version,'inputs':inputs,'outputs':outputs,'stacks':stacks,'lock':lock}


def push(b):
    if len(b)==1 and 1<=b[0]<=16:return bytes([0x50+b[0]])
    if b==b'\x81':return b'\x4f'
    if len(b)<=75:return bytes([len(b)])+b
    if len(b)<=255:return b'\x4c'+bytes([len(b)])+b
    return b'\x4d'+uint(len(b),2)+b


def envelope(script):
    require(42<=len(script)<=262144+3*((262144+519)//520)+42,'script length')
    author=script[1:33]
    require(script[:1]==b'\x20' and script[33:41]==b'\xac\x00\x63\x04URMA','script prefix')
    r=Reader(script[41:]);parts=[]
    while True:
        op=r.number(1)
        if op==0x68:break
        if 1<=op<=75:b=r.take(op)
        elif op in (0x4c,0x4d):b=r.take(r.number(1 if op==0x4c else 2))
        elif 0x51<=op<=0x60:b=bytes([op-0x50])
        elif op==0x4f:b=b'\x81'
        else:raise Invalid('record push opcode')
        require(1<=len(b)<=520,'segment bounds');parts.append(b)
    r.end();record=b''.join(parts)
    require(len(record)<=262144,'public record cap')
    canonical=push(author)+b'\xac\x00\x63'+push(b'URMA')+b''.join(push(record[i:i+520]) for i in range(0,len(record),520))+b'\x68'
    require(script==canonical,'noncanonical segmentation')
    return author,record


def verify(reveal,commit):
    t=transaction(reveal);c=transaction(commit)
    require(t['version']==uint(2,4) and len(t['inputs'])==len(t['outputs'])==1,'reveal shape')
    txid,vout,scriptsig,seq=t['inputs'][0]
    require(not scriptsig and txid==c['txid'] and vout<len(c['outputs']),'actual commit outpoint')
    amount,prevscript=c['outputs'][vout];value,payout=t['outputs'][0]
    require((len(payout)==22 and payout[:2]==b'\x00\x14') or (len(payout)==34 and payout[:2]==b'\x51\x20'),'return output')
    require(value<=amount and len(prevscript)==34 and prevscript[:2]==b'\x51\x20','prevout')
    require(len(t['stacks'])==1 and len(t['stacks'][0])==3,'witness shape')
    sig,script,control=t['stacks'][0]
    require(len(sig)==64 and len(control)==33 and control[0]&0xfe==0xc0,'signature/control/leaf version')
    author,record=envelope(script);require(control[1:]==author,'internal author')
    a=lift(int.from_bytes(author,'big'));leaf=tagged('TapLeaf',b'\xc0'+vector(script))
    tweak=int.from_bytes(tagged('TapTweak',author+leaf),'big');require(tweak<N,'tweak')
    q=point_add(a,point_mul(tweak));require(q is not None,'infinite output key')
    require(q[0].to_bytes(32,'big')==prevscript[2:] and q[1]&1==control[0]&1,'commitment')
    msg=(b'\x00'+t['version']+t['lock']+sha(txid+uint(vout,4))+sha(uint(amount,8))+sha(vector(prevscript))
         +sha(seq)+sha(uint(value,8)+vector(payout))+b'\x02'+bytes(4)+leaf+b'\x00'+b'\xff'*4)
    digest=tagged('TapSighash',b'\x00'+msg)
    r=int.from_bytes(sig[:32],'big');s=int.from_bytes(sig[32:],'big')
    require(r<P and s<N,'signature scalar range')
    e=int.from_bytes(tagged('BIP0340/challenge',sig[:32]+author+digest),'big')%N
    point=point_add(point_mul(s),point_mul(N-e,a))
    require(point is not None and not point[1]&1 and point[0]==r,'author signature')
    return t['txid'],author,record


def geometry(length):
    require(0<=length<=MAX,'object length');n=max(1,(length+C-1)//C);return n,(n+F-1)//F


def decode(b):
    require(8<=len(b)<=262144 and b[:5]==b'URMA\x00' and b[6:8]==bytes(2),'prefix/cap')
    r=Reader(b);r.take(8);kind=b[5]
    if kind==7:
        i=r.number(4);require(i<(MAX+C-1)//C,'data index');return kind,(i,r.take(len(b)-12))
    if kind==8:
        j=r.number(2);k=r.number(2);first=r.number(4)
        require(j<F and 1<=k<=F and first==j*F,'leaf geometry')
        require(len(b)==16+64*k,'leaf exact length')
        entries=[(r.take(32),r.take(32)) for _ in range(k)];r.end();return kind,(j,entries)
    require(kind==9,'kind')
    length=r.number(8);digest=r.take(32);n=r.number(4);m=r.number(2)
    require((n,m)==geometry(length) and r.number(2)==0,'root geometry/reserved')
    profile=r.take(8);require(len(b)==64+64*m,'root exact length')
    entries=[(r.take(32),r.take(32)) for _ in range(m)];r.end()
    return kind,(length,digest,n,m,profile,entries)


def reconstruct(root_txid,fetch,max_bytes=64*1024*1024,max_nodes=4096,destination=None):
    def get(txid,expected_hash=None):
        try:
            reveal,commit=fetch(txid)
            actual,author,record=verify(reveal,commit)
            require(actual==txid,'candidate TXID')
            require(expected_hash is None or sha(record)==expected_hash,'candidate record hash')
        except Invalid as e:raise Candidate(str(e)) from e
        kind,body=decode(record)
        return author,kind,body
    author,kind,root=get(root_txid);require(kind==9,'root kind')
    length,digest,n,m,profile,refs=root
    if length>max_bytes or n+m+1>max_nodes:raise Capacity('local byte/node capacity')
    seen={root_txid}
    def distinct(txid):
        require(txid not in seen,'duplicate/cyclic reference');seen.add(txid)
    for txid,_ in refs:distinct(txid)
    with tempfile.TemporaryFile() as inventory, tempfile.TemporaryFile() as output:
        for j,ref in enumerate(refs):
            a,k,body=get(*ref);require(a==author and k==8,'leaf author/type')
            index,entries=body;require(index==j and len(entries)==min(F,n-j*F),'leaf position/count')
            for txid,h in entries:distinct(txid);inventory.write(txid+h)
        inventory.seek(0);whole=hashlib.sha256();total=0
        for i in range(n):
            a,k,body=get(inventory.read(32),inventory.read(32));require(a==author and k==7,'part author/type')
            index,payload=body;require(index==i and len(payload)==min(C,length-i*C),'part position/length')
            output.write(payload);whole.update(payload);total+=len(payload)
        require(total==length and whole.digest()==digest,'whole payload digest/length')
        if destination is not None:
            output.seek(0)
            with tempfile.NamedTemporaryFile(dir=destination.parent) as staged:
                shutil.copyfileobj(output,staged,length=32768);staged.flush();os.fsync(staged.fileno())
                os.link(staged.name,destination)
        return {'length':total,'sha256':whole.hexdigest(),'profile_hex':profile.hex(),'author':author.hex(),
                'chain_inclusion_checked':False}


def read_bounded(path,limit):
    with path.open('rb') as f:b=f.read(limit+1)
    if len(b)>limit:raise Capacity('local input byte capacity')
    return b


def corpus(directory):
    m=json.loads((directory/'manifest.json').read_text());proofs={p['name']:p for p in m['proofs']}
    for case in m['records']:
        try:decode(read_bounded(directory/case['record']['file'],262145));outcome='valid'
        except Invalid:outcome='invalid'
        require(outcome==case['outcome'],case['name'])
    for case in m['proofs']:
        try:
            txid,author,record=verify(read_bounded(directory/case['reveal']['file'],4_000_000),read_bounded(directory/case['commit']['file'],4_000_000))
            require(txid[::-1].hex()==case['txid'] and author.hex()==case['author'] and sha(record).hex()==case['record']['sha256'],'proof answer')
            outcome='valid'
        except Invalid:outcome='invalid'
        require(outcome==case['outcome'],case['name'])
        if outcome=='valid':
            try:decode(record);layout='valid'
            except Invalid:layout='invalid'
            require(layout==case.get('record_outcome','valid'),case['name']+' layout')
    for case in m['graphs']:
        available={bytes.fromhex(proofs[n]['txid'])[::-1]:proofs[n] for n in case['available']}
        def fetch(txid):
            if txid not in available:raise Incomplete(txid[::-1].hex())
            p=available[txid];return read_bounded(directory/p['reveal']['file'],4_000_000),read_bounded(directory/p['commit']['file'],4_000_000)
        try:
            result=reconstruct(bytes.fromhex(proofs[case['root']]['txid'])[::-1],fetch)
            require(result['length']==case['length'] and result['sha256']==case['sha256'],'graph answer');outcome='complete'
        except Candidate:outcome='invalid_candidate'
        except Invalid:outcome='invalid_object'
        except Incomplete:outcome='incomplete'
        require(outcome==case['outcome'],case['name']+': '+outcome)
    return {k:len(m[k]) for k in ['records','proofs','graphs']}


def directory_source(directory):
    base=(directory/'tx').resolve()
    def read_tx(txid):
        path=base/(txid[::-1].hex()+'.bin')
        if not path.exists():raise Incomplete(txid[::-1].hex())
        require(not path.is_symlink() and path.resolve().parent==base,'proof path escape')
        return read_bounded(path,4_000_000)
    def fetch(txid):
        reveal=read_tx(txid)
        try:
            t=transaction(reveal);require(len(t['inputs'])==1,'reveal inputs')
        except Invalid as e:raise Candidate(str(e)) from e
        return reveal,read_tx(t['inputs'][0][0])
    return fetch


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--corpus',type=Path);mode.add_argument('--directory',type=Path)
    parser.add_argument('--root');parser.add_argument('--output',type=Path)
    parser.add_argument('--max-bytes',type=int,default=64*1024*1024)
    parser.add_argument('--max-nodes',type=int,default=4096)
    args=parser.parse_args()
    if args.corpus:result=corpus(args.corpus)
    else:
        if not args.root or len(args.root)!=64:parser.error('--root requires a display-order TXID')
        root=bytes.fromhex(args.root)[::-1]
        result=reconstruct(root,directory_source(args.directory),args.max_bytes,args.max_nodes,args.output)
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':main()
