#!/usr/bin/env python3
# SPDX-License-Identifier: 0BSD
"""Independent URMA revision 0.4 multipart known answers. No Rust/network calls."""
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location('primitives', Path(__file__).with_name('generate-vectors.py'))
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
v.OUT = Path(__file__).resolve().parents[1] / 'tests/vectors/multipart'
C, F = 262132, 511
LIMIT = 8553279476
MAX_PARTS = (LIMIT+C-1)//C
manifest = {'protocol': 'URMA', 'wire_version': 0, 'document_revision': '0.4',
            'license': 'CC0-1.0', 'records': [], 'proofs': [], 'graphs': [], 'geometry': []}
v.manifest = manifest


def reference(name):
    proof = next(p for p in manifest['proofs'] if p['name'] == name)
    return bytes.fromhex(proof['txid'])[::-1] + bytes.fromhex(proof['record']['sha256'])


def data(index, payload):
    return v.prefix(7) + v.uint(index, 4) + payload


def leaf(index, refs):
    return v.prefix(8) + v.uint(index, 2) + v.uint(len(refs), 2) + v.uint(index*F, 4) + b''.join(refs)


def root(length, digest, refs, profile=b'\x00'*8):
    count = max(1, (length+C-1)//C)
    return (v.prefix(9) + v.uint(length, 8) + digest + v.uint(count, 4)
            + v.uint(len(refs), 2) + b'\x00\x00' + profile + b''.join(refs))


def record(name, value, outcome='valid'):
    manifest['records'].append({'name': name, 'outcome': outcome, 'record': v.save(name+'.record', value)})


def proof(name, value, **kwargs):
    v.proof(name, value, **kwargs)
    item = manifest['proofs'][-1]
    del item['record_hex']
    item['record'] = v.save(name+'.record', value)
    return name


def graph(name, payload, *, change_parts=None, change_leaf=None, change_root=None,
          part_author=3, omit=(), outcome='complete'):
    original_parts = [payload[i:i+C] for i in range(0, len(payload), C)] or [b'']
    parts = [data(i, part) for i, part in enumerate(original_parts)]
    if change_parts:
        parts = change_parts(parts)
    names = [proof(name+f'-part-{i}', part, key=part_author) for i, part in enumerate(parts)]
    leaf_value = leaf(0, [reference(n) for n in names])
    if change_leaf:
        leaf_value = change_leaf(leaf_value, names)
    leaf_name = proof(name+'-leaf', leaf_value)
    names.append(leaf_name)
    root_value = root(len(payload), v.sha(payload), [reference(leaf_name)], b'opaque?!')
    if change_root:
        root_value = change_root(root_value, names)
    root_name = proof(name+'-root', root_value)
    names.append(root_name)
    manifest['graphs'].append({'name': name, 'root': root_name, 'available': [n for n in names if not any(n.endswith(s) for s in omit)],
                               'outcome': outcome, 'length': len(payload), 'sha256': v.sha(payload).hex()})


def mutate(value, offset, replacement):
    return value[:offset] + replacement + value[offset+len(replacement):]


def main():
    v.OUT.mkdir(parents=True, exist_ok=True)
    refs = [v.uint(i+1,32) + v.sha(v.uint(i,4)) for i in range(F)]
    records = {
        'data-min': data(0,b''), 'data-max': data(MAX_PARTS-1,b'\xa5'*C),
        'leaf-min': leaf(0,refs[:1]), 'leaf-max': leaf(F-1,refs),
        'root-min': root(0,v.sha(b''),refs[:1]), 'root-max': root(LIMIT,bytes(32),refs[:((LIMIT+C-1)//C+F-1)//F]),
    }
    for name, value in records.items():
        record(name, value)
        proof('proof-'+name, value)
    bad = {
        'data-short': records['data-min'][:-1], 'data-over': data(0, bytes(C+1)),
        'data-index': data(MAX_PARTS,b''), 'data-index-overflow': data(2**32-1,b''),
        'leaf-short': records['leaf-min'][:-1], 'leaf-trailing': records['leaf-min']+b'\x00',
        'leaf-padding': records['leaf-max']+bytes(48), 'leaf-count-zero': leaf(0,[]),
        'leaf-count-over': leaf(0,refs+[refs[0]]), 'leaf-index-over': leaf(F,refs[:1]),
        'leaf-first': mutate(records['leaf-min'],12,v.uint(1,4)),
        'root-short': records['root-min'][:-1], 'root-trailing': records['root-min']+b'\x00',
        'root-header-short': records['root-min'][:63], 'root-length-over': mutate(records['root-max'],8,v.uint(LIMIT+1,8)),
        'old-geometry-root': mutate(root(65536,bytes(32),refs[:1]),48,v.uint(3,4)),
        'root-overflow': mutate(records['root-max'],8,v.uint(2**64-1,8)),
        'root-count-zero': mutate(records['root-min'],48,bytes(4)),
        'root-count-over': mutate(records['root-max'],48,v.uint(F*F+1,4)),
        'root-leaves-zero': mutate(records['root-min'],52,bytes(2)),
        'root-leaves-over': mutate(records['root-max'],52,v.uint(F+1,2)),
        'root-reserved': mutate(records['root-min'],54,b'\x01'),
        'unknown-kind': v.prefix(255), 'unknown-version': mutate(records['root-min'],4,b'\x01'),
    }
    for kind in ['data-min','leaf-min','root-min']:
        bad[kind+'-flags'] = mutate(records[kind],6,b'\x01')
    for name,value in bad.items(): record(name,value,'invalid')
    for length in [0,1,C-1,C,C+1,510*C,511*C,511*C+1,512*C,LIMIT,LIMIT+1,2**64-1]:
        case={'length':length,'outcome':'valid' if length<=LIMIT else 'invalid','scope':'arithmetic only; not materialized'}
        if length<=LIMIT:
            n=max(1,(length+C-1)//C);m=(n+F-1)//F
            case.update(parts=n,leaves=m,last_part_bytes=length-(n-1)*C,last_leaf_entries=n-(m-1)*F)
        manifest['geometry'].append(case)
    for name,payload in [('empty',b''),('one',b'x'),('c-minus-one',b'z'*(C-1)),('exact-c',b'z'*C),('two',b'z'*C+b'x'),
                         ('opaque-manifest',records['root-min'])]:
        graph(name,payload)
    graph('missing-part',b'x',omit=('part-0',),outcome='incomplete')
    graph('missing-leaf',b'x',omit=('-leaf',),outcome='incomplete')
    graph('root-count-mismatch',b'x',change_root=lambda r,n:mutate(r,48,v.uint(2,4)),outcome='invalid_object')
    graph('leaf-first-mismatch',b'x',change_leaf=lambda r,n:mutate(r,12,v.uint(1,4)),outcome='invalid_object')
    for p in manifest['proofs']:
        if p['name'] in ['root-count-mismatch-root','leaf-first-mismatch-leaf']:p['record_outcome']='invalid'
    graph('wrong-author',b'x',part_author=7,outcome='invalid_object')
    graph('wrong-digest',b'x',change_root=lambda r,n:mutate(r,16,bytes(32)),outcome='invalid_object')
    graph('wrong-data-length',b'xx',change_parts=lambda p:[p[0][:-1]],outcome='invalid_object')
    graph('wrong-data-index',b'x',change_parts=lambda p:[mutate(p[0],8,v.uint(1,4))],outcome='invalid_object')
    graph('wrong-leaf-index',b'x',change_leaf=lambda r,n:leaf(1,[reference(n[0])]),outcome='invalid_object')
    graph('swapped-parts',b'z'*C+b'x',change_leaf=lambda r,n:leaf(0,[reference(n[1]),reference(n[0])]),outcome='invalid_object')
    graph('duplicate-parts',b'z'*C+b'x',change_leaf=lambda r,n:leaf(0,[reference(n[0]),reference(n[0])]),outcome='invalid_object')
    graph('root-to-data',b'x',change_root=lambda r,n:root(1,v.sha(b'x'),[reference(n[0])]),outcome='invalid_object')
    graph('wrong-child-hash',b'x',change_leaf=lambda r,n:mutate(r,48,bytes(32)),outcome='invalid_candidate')
    graph('wrong-leaf-hash',b'x',change_root=lambda r,n:mutate(r,96,bytes(32)),outcome='invalid_candidate')
    value=records['data-max']
    proof('proof-noncanonical-segments',value,script_transform=lambda s:s[:41]+v.push(value[:500])+b''.join(v.push(value[i:i+520]) for i in range(500,len(value),520))+b'\x68',outcome='invalid')
    proof('proof-extra-opcode',records['root-min'],script_transform=lambda s:s+b'\x61',outcome='invalid')
    (v.OUT/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({k:len(manifest[k]) for k in ['records','proofs','graphs','geometry']}))

if __name__=='__main__':main()
