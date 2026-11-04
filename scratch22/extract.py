import json,collections
d=json.load(open('internal/conformance/query/testdata/native-promql-observations.json'))
rows=[r for r in d['rows'] if r['case']['query'] in ('avg(m)',) or r['case']['query'].startswith('avg_over_time')]
print(len(rows))
c=collections.Counter((r['profile'],r['case']['id'][:3],r['case']['query'].split('(')[0]) for r in rows)
for k,v in sorted(c.items()): print(k,v)
r=[x for x in rows if x['case']['id']=='po-0016'][0]
print(json.dumps(r['case'])[:1500]); print(json.dumps(r['reference'])[:800])
json.dump(rows,open('scratch22/avgrows.json','w'))
