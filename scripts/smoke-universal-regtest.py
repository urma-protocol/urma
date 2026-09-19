#!/usr/bin/env python3
import json, os, pathlib, socket, subprocess, time
ROOT = pathlib.Path(__file__).resolve().parents[1]
BIN = ROOT / 'target/debug/urma'
ARTIFACTS = ROOT / 'artifacts/urma-universal-v0'
ARTIFACTS.mkdir(parents=True, exist_ok=True)
LAB = ROOT / 'target/urma-universal-lab' / str(time.time_ns())
LAB.mkdir(parents=True, mode=0o700)
os.chmod(LAB, 0o700)
os.environ['TMPDIR'] = str(LAB)
results = {'lab':str(LAB), 'checks':[]}
def cmd(args, expected=(0,)):
    p = subprocess.run([str(a) for a in args], cwd=ROOT, capture_output=True, text=True)
    if p.returncode not in expected:
        raise RuntimeError(f'{args[0:4]} exit {p.returncode}: {p.stderr[-2000:]} {p.stdout[-1000:]}')
    return p.stdout

def urma(*args, expected=(0,)):
    return json.loads(cmd([BIN, *args], expected=expected))

with socket.socket() as s:
    s.bind(('127.0.0.1',0)); port=s.getsockname()[1]
data=LAB/'node'; data.mkdir(mode=0o700)
daemon=subprocess.Popen(['bitcoind',f'-datadir={data}','-regtest','-server=1','-txindex=1','-networkactive=0','-listen=0','-connect=0','-dnsseed=0','-discover=0',f'-rpcport={port}'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
def rpc(method,*args):
    values=[json.dumps(a) if not isinstance(a,str) else a for a in args]
    output=cmd(['bitcoin-cli',f'-datadir={data}','-regtest',f'-rpcport={port}',method,*values])
    try:return json.loads(output)
    except json.JSONDecodeError:return output.strip()
node=['--chain','bitcoin-regtest','--rpc-url',f'http://127.0.0.1:{port}','--cookie',data/'regtest/.cookie']
password=LAB/'test-password'; password.write_text('Public isolated regtest password only 2026'); password.chmod(0o600)
vault=LAB/'test-vault'; phrase=LAB/'test-phrase'
access=['--vault',vault,'--password-file',password]
def check(name):results['checks'].append(name); print(name,flush=True)
def publish(group,plan,approval,label):
    report={}
    for step in range(100):
        report=urma(*group,'resume',*node,'--plan',plan,'--approve',approval,'--journal',LAB/f'{label}-journal.json',expected=(0,1))
        if report['confirmed']:return report
        rpc('generatetoaddress',1,address)
    raise RuntimeError(f'{label} stalled: {report}')
try:
    for _ in range(100):
        try:rpc('getblockchaininfo');break
        except RuntimeError:time.sleep(.1)
    else:raise RuntimeError('node startup')
    urma('key','create','--vault',vault,'--password-file',password,'--recovery-out',phrase,'--name','isolated-regtest')
    address=urma('wallet','address',*access,'--chain','bitcoin-regtest')['receive_address']
    rpc('generatetoaddress',102,address)
    status=urma('wallet','status',*access,*node)
    assert status['spendable_confirmed_balance']>0 and status['network_verified']
    check('identity vault + verified wallet spendable UTXOs')
    text=LAB/'post.txt'; text.write_text('URMA universal CLI isolated regtest')
    record=LAB/'post.record'; plan=LAB/'wire-plan.json'
    urma('wire','encode','--kind','post','--input',text,'--output',record)
    prepared=urma('wire','plan',*access,*node,'--record',record,'--output',plan,'--fee-rate','1','--max-fee','100000')
    report=publish(['wire'],plan,prepared['plan_id'],'wire')
    check('Wire immutable plan + confirmation-gated publish/resume')
    index=LAB/'wire-index.json'
    sync=urma('wire','index',*node,'--index',index,'--start-height','102')
    feed=urma('wire','read','feed','--index',index)
    assert len(feed['records'])==1
    assert feed['records'][0]['author']==status['author']
    last=rpc('getbestblockhash');rpc('invalidateblock',last)
    rollback=urma('wire','index',*node,'--index',index,'--start-height','102')
    assert rollback['rolled_back']>0
    assert len(urma('wire','read','feed','--index',index)['records'])==0
    rpc('reconsiderblock',last)
    urma('wire','index',*node,'--index',index,'--start-height','102')
    assert len(urma('wire','read','feed','--index',index)['records'])==1
    check('Wire confirmed author index + actual reorg rollback/reconsider')
    secret=LAB/'archive-recovery';urma('key','recovery-generate','--key',secret)
    source=LAB/'documents';source.mkdir();(source/'one.txt').write_text('private source bytes');(source/'empty').write_bytes(b'');(source/'empty-dir').mkdir()
    bundle=LAB/'archive-bundle'; local=LAB/'archive-local'; onchain=LAB/'archive-chain'
    inv=urma('archive','files','ingest','--input',source,'--key',secret,'--output',bundle,'--collection','regtest-collection')
    urma('archive','files','recover','--bundle',bundle,'--key',secret,'--output',local)
    assert (local/'documents/one.txt').read_bytes()==(source/'one.txt').read_bytes()
    plan=LAB/'archive-plan.json'
    prepared=urma('archive','files','plan',*access,*node,'--bundle',bundle,'--key',secret,'--output',plan,'--fee-rate','1','--max-fee','1000000')
    report=publish(['archive','files'],plan,prepared['plan_id'],'archive')
    recovered=urma('archive','files','recover-chain',*node,'--key',secret,'--output',onchain,'--start-height','102')
    assert (onchain/'documents/one.txt').read_bytes()==(source/'one.txt').read_bytes()
    assert (onchain/'documents/empty').read_bytes()==b'' and (onchain/'documents/empty-dir').is_dir()
    check('Archive files/directories/empty entries: local + chain discovery recovery without bundle')
    session=LAB/'session.json';session.write_text(json.dumps({'kind':'session','id':'local-capture','state':'closed','assertions':{'context':'synthetic regtest only'},'originals':['one.txt'],'derivatives':[]}))
    capture=LAB/'capture-bundle'; out=LAB/'capture-local'
    urma('capture','ingest','--input',source/'one.txt','--key',secret,'--output',capture,'--collection','capture-test','--session',session)
    urma('capture','recover','--bundle',capture,'--key',secret,'--output',out)
    assert (out/'one.txt').read_bytes()==(source/'one.txt').read_bytes()
    capture_plan=LAB/'capture-plan.json'
    prepared=urma('capture','plan',*access,*node,'--bundle',capture,'--key',secret,'--output',capture_plan,'--max-fee','1000000')
    publish(['capture'],capture_plan,prepared['plan_id'],'capture')
    capture_chain=LAB/'capture-chain'
    urma('capture','recover-chain',*node,'--key',secret,'--catalog',prepared['catalog'],'--output',capture_chain,'--start-height','102')
    assert (capture_chain/'one.txt').read_bytes()==(source/'one.txt').read_bytes()
    check('Capture session/profile: local + confirmed chain recovery through same private engine')
    repo=LAB/'git-source'; cmd(['git','init','--initial-branch=main',repo])
    cmd(['git','-C',repo,'config','user.name','URMA regtest'])
    cmd(['git','-C',repo,'config','user.email','regtest@example.invalid'])
    (repo/'hello.txt').write_text('first committed version')
    cmd(['git','-C',repo,'add','hello.txt']);cmd(['git','-C',repo,'commit','-m','first'])
    (repo/'hello.txt').write_text('final HEAD bytes')
    cmd(['git','-C',repo,'commit','-am','current head'])
    original_head=cmd(['git','-C',repo,'rev-parse','HEAD']).strip()
    (repo/'hello.txt').write_text('dirty excluded bytes')
    git_plan=LAB/'git-plan'
    prepared=urma('git','prepare','--repo',repo,'--output',git_plan,*access,*node,'--max-fee','1000000')
    reviewed=urma('git','review','--plan',git_plan)
    inspected=urma('git','inspect','--plan',git_plan)
    approval=inspected['plan_id']
    for step in range(30):
        result=urma('git','resume','--plan',git_plan,'--approve',approval,*node,expected=(0,1))
        assert result['plan_id']==approval
        if result['complete']:break
        rpc('generatetoaddress',1,address)
    else:raise RuntimeError('Git publication stalled')
    root=result['root_txid']
    clone=LAB/'git-clone';urma('git','clone',root,clone,*node)
    assert (clone/'hello.txt').read_text()=='final HEAD bytes'
    assert cmd(['git','-C',clone,'rev-parse','HEAD']).strip()==original_head
    assert cmd(['git','-C',clone,'rev-list','--count','HEAD']).strip()=='1'
    assert cmd(['git','-C',clone,'status','--porcelain']).strip()==''
    (clone/'hello.txt').write_text('editable local checkout')
    assert 'hello.txt' in cmd(['git','-C',clone,'status','--porcelain'])
    export=LAB/'git-proof';urma('git','recover',root,'--output',export,*node)
    cache=export/'object.bin'
    if cache.exists():cache.unlink()
    urma('git','verify','--snapshot',export)
    check('Git HEAD-only PACK: review + publish/resume + editable clone + offline raw-proof verification without payload cache')
finally:
    try:rpc('stop')
    except RuntimeError:daemon.terminate()
    daemon.wait(timeout=15)
    (ROOT/'artifacts/urma-universal-v0/cli-smoke-results.json').write_text(json.dumps(results,indent=2)+'\n')
