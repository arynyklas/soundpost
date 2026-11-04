import json,struct,math,re,collections
def f(b): return struct.unpack('>d',bytes.fromhex(b.rjust(16,'0')))[0]
def bits(x): return struct.pack('>d',x).hex()
INF=math.inf
def isinf(x): return x==INF or x==-INF
def kinc(inc,s,c):
    t=s+inc
    if isinf(t): c=0.0
    elif abs(s)>=abs(inc): c+=(s-t)+inc
    else: c+=(inc-t)+s
    return t,c
def div(a,b):
    try: return a/b
    except ZeroDivisionError: return math.nan if a==0 or a!=a else math.copysign(INF,a)
def mul(a,b):
    return a*b
def mean310(xs):
    s=0.0;mean=0.0;cnt=0.0;c=0.0;inc=False
    for x in xs:
        cnt+=1
        if not inc:
            ns,nc=kinc(x,s,c)
            if cnt==1 or not isinf(ns):
                s,c=ns,nc;continue
            inc=True;mean=s/(cnt-1);c/=cnt-1
        if isinf(mean):
            if isinf(x) and (mean>0)==(x>0): continue
            if not isinf(x) and x==x: continue
        cm=mean+c
        mean,c=kinc(x/cnt-cm/cnt,mean,c)
    return mean+c if inc else (s+c)/cnt
def mean3135(xs):
    s=xs[0];cnt=1.0;mean=0.0;c=0.0;inc=False
    for i,x in enumerate(xs[1:]):
        cnt=float(i+2)
        if not inc:
            ns,nc=kinc(x,s,c)
            if not isinf(ns):
                s,c=ns,nc;continue
            inc=True;mean=s/(cnt-1);c/=cnt-1
        q=(cnt-1)/cnt
        mean,c=kinc(x/cnt,q*mean,q*c)
    return mean+c if inc else s/cnt+c/cnt
def old(xs,p):
    # current implementation reproduction skipped
    pass
def window(case):
    T=int(case['time']);q=case['query']
    m=re.match(r'avg_over_time\(m\[(\d+)(ms|s|m|h)\]\)',q)
    out=[]
    if m:
        n=int(m.group(1))*{'ms':10**6,'s':10**9,'m':60*10**9,'h':3600*10**9}[m.group(2)]
        for s in case['series']:
            return [f(x['float_bits']) for x in s['samples'] if T-n<int(x['time'])<=T]
    else:
        v=[]
        for s in case['series']:
            ss=[x for x in s['samples'] if T-300*10**9<int(x['time'])<=T]
            if ss: v.append(f(ss[-1]['float_bits']))
        return v
rows=json.load(open('scratch22/avgrows.json'))
res=collections.Counter();bad=[]
for r in rows:
    xs=window(r['case'])
    ref=r['reference']['series']
    if not xs: continue
    want=ref[0]['samples'][0]['float_bits'] if ref else None
    fn=mean310 if r['profile'].endswith('3.1.0') else mean3135
    got=bits(fn(xs))
    k=(r['profile'][-5:],r['case']['id'][:2],r['case']['query'][:3])
    res[k,got==want]+=1
    if got!=want: bad.append((r['case']['id'],r['profile'],xs,got,want))
for k,v in sorted(res.items()): print(k,v)
print(bad[:3])

fail=set(l.strip() for l in open('scratch22/failing.txt'))
print('----')
sel=collections.defaultdict(list)
for r in rows:
    key=r['profile'][len('promql-prometheus-'):]+'/'+r['case']['id']
    xs=window(r['case'])
    if key in fail and xs:
        sel[(r['profile'][-5:],r['case']['query'][:3])].append((len(xs),key,r['case']['query'],[bits(x) for x in xs],r['case']['time'],r['reference']['series'][0]['samples'][0]['float_bits'],[ (s['samples'][0]['time']) for s in r['case']['series']][:2]))
for k,v in sel.items():
    v.sort(); print(k,len(v)); 
    for e in v[:2]: print('  ',e)

print('=====')
def oldmean(xs,p):
    n=float(len(xs)); s=0.0;c=0.0
    for x in xs: s,c=kinc(x,s,c)
    comb=s+c
    if not isinf(comb):
        return s/n+c/n if p.endswith('3.13.5') else comb/n
    if any(isinf(x) or x!=x for x in xs): return comb/n
    m=xs[0]
    for i,x in enumerate(xs[1:]):
        k=float(i+2); m+=x/k-m/k
    return m
seen=collections.defaultdict(dict)
for r in rows:
    if not r['case']['id'].startswith('po'): continue
    xs=window(r['case'])
    key=(r['case']['id'],tuple(map(bits,xs)),r['case']['query'][:3])
    seen[key][r['profile'][-5:]]=(r['reference']['series'][0]['samples'][0]['float_bits'], bits(oldmean(xs,r['profile'])))
n=0
for k,v in seen.items():
    if len(v)==2 and v['3.1.0'][0]!=v['.13.5'][0] and v['3.1.0'][1]!=v['3.1.0'][0] and v['.13.5'][1]!=v['.13.5'][0]:
        print(k,v); n+=1
        if n>6: break
print(n)

print('#####')
for key in [('ffe005419221015d', '4004000000000000', 'ffe005419221015d', '7fdfaf5f8d197479', '3ff0000000000000', '7fd1ccf385ebc8a0'),('7fc55c576d815726', '7fd1ccf385ebc8a0', '7fe1ccf385ebc8a0', '7feab36d48e1acf0', '7fee42d130773b76', '7fcf543bf5f0e638', '7feab36d48e1acf0', 'ffee42d130773b76', '7fdfaf5f8d197479')]:
  for r in rows:
    if r['case']['id'].startswith('po') and tuple(map(bits,window(r['case'])))==key:
        print(r['profile'][-5:],r['case']['id'],r['case']['query'],r['case']['time'],[ (s['samples'][0]['time'],len(s['samples'])) for s in r['case']['series']][:3], r['reference']['series'][0]['samples'][0]['float_bits'])
