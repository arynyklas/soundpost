# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Development-only metadata authoring; reads locked source facts, never emits an evaluator."""
import hashlib, itertools, json, pathlib, re, runpy, tarfile
ROOT = pathlib.Path(__file__).resolve().parents[3]
OUT = pathlib.Path(__file__).with_name('promql.json')
def digest(s): return hashlib.sha256(s.encode()).hexdigest()
def load(pin):
    with tarfile.open(ROOT / '.superpowers/sdd/approved-product/oracle-source-cache' / ('promql-prometheus-'+pin+'.tar.gz')) as t:
        prefix=t.getnames()[0]+'/'
        return {m.name[len(prefix):]:t.extractfile(m).read().decode('utf8','replace') for m in t.getmembers() if m.isfile() and m.name.endswith(('.go','.y'))}
def ref(src,path,needle=None):
    text=src[path]; line=1 if needle is None else text[:text.index(needle)].count('\n')+1
    return path+':'+str(line)+'@'+digest(text)
# These are independently authored behavioral summaries, not copied source comments or tables.
RULES = {
'abs':'Absolute value of each float; ignore native histograms; preserve labels except metric name.',
'absent':'Return one sample of value 1 only for empty input; derive compatible equality labels from the argument selector, excluding metric name.',
'absent_over_time':'Return 1 only when the selected window has no float or histogram samples; derive selector equality labels.',
'avg_over_time':'Equal-weight arithmetic mean of samples, not time-weighted; histogram mean uses histogram arithmetic; a mixed float/histogram window is removed with warning.',
'count_over_time':'Count both float and histogram observations in the selected window; emit a float.',
'present_over_time':'Emit float 1 for each nonempty window, counting either sample kind.',
'last_over_time':'Choose latest sample of either kind and retain metric name; timestamp of output is evaluation time.',
'first_over_time':'Choose earliest sample of either kind in the left-open range; retain metric name.',
'sum_over_time':'Add samples with compensated float accumulation or native histogram addition; mixed sample kinds remove the result with warning.',
'min_over_time':'Minimum float, ignoring histograms; NaN wins only when all floats are NaN; histogram-only windows are absent.',
'max_over_time':'Maximum float, ignoring histograms; NaN wins only when all floats are NaN; histogram-only windows are absent.',
'quantile_over_time':'Quantile over sorted float observations with linear interpolation; ignore histograms; empty is absent, NaN quantile gives NaN, out-of-range quantiles give signed infinity and warning.',
'mad_over_time':'Median absolute deviation over float observations; ignore histograms.',
'stddev_over_time':'Population standard deviation of float observations; ignore histograms.',
'stdvar_over_time':'Population variance of float observations; ignore histograms.',
'changes':'Count changes between adjacent observations; float/histogram transitions count, two float NaNs do not count, and equal histogram values do not change solely because of counter/gauge flavor.',
'resets':'Count float decreases and native histogram resets; sample-kind transitions count; histogram reset includes incompatible schema or disappeared/decreased populations.',
'delta':'Extrapolate first-to-last gauge change across range endpoints; support floats or histograms, remove mixed windows with warning.',
'idelta':'Difference of last two gauge samples; support two floats or two histograms, remove mixed last-pair kinds with warning.',
'rate':'Counter-corrected increase extrapolated to window edges divided by range seconds; at least two observations; support native histogram counters with reset/schema handling; remove mixed sample-kind windows with warning.',
'increase':'Counter-corrected extrapolated range increase, equivalent to rate times range seconds; histogram-aware; mixed windows removed with warning.',
'irate':'Counter-corrected increase of last two observations divided by their timestamp difference; mixed last-pair kinds removed with warning.',
'deriv':'Least-squares slope of float values against seconds; at least two floats; histograms ignored; infinity arithmetic can yield NaN.',
'predict_linear':'Least-squares float trend projected by scalar seconds from evaluation time; histogram samples ignored.',
'double_exponential_smoothing':'Holt linear smoothing of floats with smoothing and trend factors strictly between zero and one; insufficient float observations absent; invalid factors are errors.',
'clamp':'Clamp floats to inclusive scalar bounds; min greater than max yields empty vector; NaN bound produces NaN; histograms ignored.',
'clamp_min':'Replace floats below scalar minimum by minimum; ignore histograms.',
'clamp_max':'Replace floats above scalar maximum by maximum; ignore histograms.',
'round':'Round floats to nearest multiple of optional scalar (default 1), ties toward positive infinity; ignore histograms.',
'scalar':'Exactly one float sample converts to scalar; zero/multiple samples or a histogram-only vector produce NaN.',
'vector':'Convert scalar into one unlabeled float sample.',
'pi':'Return scalar mathematical pi.',
'time':'Return evaluation timestamp in seconds, not wall-clock execution time.',
'timestamp':'Return original selected sample timestamp in seconds for either sample kind.',
'label_replace':'For full regex matches on source label, expand capture references into destination label; nonmatches unchanged; validate regex and destination label; both sample kinds preserved.',
'label_join':'Join requested source label values with the separator into destination label; missing source labels are empty; preserve sample kind; validate destination.',
'info':'Join data labels from matching info series using identifying job/instance labels; reconcile overlapping info samples by recency; selector and matching constraints differ from general binary joins.',
'histogram_count':'Emit native histogram count as float; ignore float input.',
'histogram_sum':'Emit native histogram sum as float; ignore float input.',
'histogram_avg':'Emit native histogram sum/count; zero-count histogram gives NaN; ignore float input.',
'histogram_stddev':'Estimate native histogram observation standard deviation using bucket representatives; ignore floats.',
'histogram_stdvar':'Estimate native histogram observation variance using bucket representatives; ignore floats.',
'histogram_quantile':'Compute quantile from classic cumulative buckets grouped without le or from each native histogram; repair classic monotonicity, interpolate by bucket schema; invalid q and malformed buckets have distinct annotations; native/classic collisions do not yield two results.',
'histogram_fraction':'Estimate fraction between lower and upper scalar bounds using native histogram bucket interpolation (and classic buckets where supported by profile); distinguish empty, NaN bounds, infinities and equal bounds.',
'histogram_quantiles':'Evaluate multiple scalar quantiles for classic/native histograms and add quantile values in the requested label; validate destination label; variadic scalar arguments.',
'sort':'Order instant float samples ascending, NaNs first; histograms omitted; range results retain label ordering rather than value ordering.',
'sort_desc':'Order instant float samples descending, NaNs last; histograms omitted; range results retain label ordering.',
'sort_by_label':'Natural ascending ordering by requested labels, with full label-set tie break; preserve both sample kinds.',
'sort_by_label_desc':'Natural descending ordering by requested labels, with full label-set tie break; preserve both sample kinds.',
'start':'Scalar outer query start time in seconds; in @ context start() is an ungated preprocessor rather than a function call.',
'end':'Scalar outer query end time in seconds; in @ context end() is an ungated preprocessor rather than a function call.',
'step':'Scalar query step in seconds; duration-expression context has the independent promql-duration-expr gate.',
'range':'Scalar outer query range in seconds; duration-expression context has the independent promql-duration-expr gate.',
'min_of':'Minimum of two scalars; duration-expression context has the independent promql-duration-expr gate.',
'max_of':'Maximum of two scalars; duration-expression context has the independent promql-duration-expr gate.'}
for name in ['acos','acosh','asin','asinh','atan','atanh','ceil','cos','cosh','exp','floor','ln','log10','log2','sin','sinh','sqrt','tan','tanh','sgn','deg','rad']:
    RULES[name]='Apply '+name+' to each float using IEEE-754 math (deg/rad convert units; sgn returns sign with NaN propagation); ignore native histograms; remove metric name.'
for name in ['days_in_month','day_of_month','day_of_week','day_of_year','hour','minute','month','year']:
    RULES[name]='Extract UTC '+name+' from float seconds since Unix epoch; optional vector defaults to vector(time()); ignore histograms; remove metric name.'
for name in ['first','last','max','min']:
    RULES['ts_of_'+name+'_over_time']='Return seconds timestamp of '+name+' float observation in window; extrema ties select latest timestamp; ignore histograms; histogram-only window absent.'
FAMILIES = {
'lexical':'Whitespace and comments separate tokens; distinguish decimal/hexadecimal/Inf/NaN numbers, signed unary forms, duration units, quoted/raw strings and escapes, identifiers and quoted UTF-8 names; malformed encodings/escapes/numbers are lexical errors.',
'precedence':'Power associates right, then multiplicative/atan2, additive, comparisons, and/unless, or; unary minus binds below power; parentheses override precedence.',
'selector':'Matchers are conjunctive; absent label equals empty string; regexes are fully anchored RE2 and match newlines; bare matcher selector requires at least one matcher that cannot match empty; metric name is __name__ matching.',
'lookback':'Instant selector chooses last sample at or before target time within lookback, with exact lookback boundary included; stale NaN suppresses series and is never ordinary NaN data.',
'range-window':'Range selector takes timestamps in (target-range,target]; no lookback substitution for ordinary range selectors; stale markers excluded; source sample timestamps retained internally.',
'subquery':'Evaluate expression on its own globally aligned resolution grid, independent of parent start; omitted resolution uses evaluation interval; range is left-open/right-closed; nested @ and offset retain their own time anchors.',
'at-offset':'@ accepts finite representable timestamp or start()/end(); it fixes selector/subquery anchor across outer steps; offset shifts anchor backward, negative offset forward; @ and offset order has same meaning; duplicates and invalid attachment are errors.',
'grid':'Range query evaluates start+n*step while <=end; step must be positive and start<=end; scalar/vector valid range roots; matrix/string range roots rejected; timestamps represented at pinned millisecond precision.',
'ieee':'Preserve signed zero, infinities and ordinary NaN arithmetic/comparisons; stale bit pattern 0x7ff0000000000002 denotes missingness, not numeric NaN; histogram counts and buckets retain their own exact representation.',
'arithmetic':'Float + - * / % ^ and atan2 use IEEE-754 behavior; histograms allow histogram +/- histogram, histogram*scalar both orders and histogram/scalar only with histogram left; negative scaling changes counter flavor to gauge; invalid kind/operator pairs removed with info.',
'comparison':'Float comparison filters lhs or emits 0/1 with bool; scalar/scalar comparison requires bool; histogram equality/inequality only compare two histograms; other histogram comparisons removed with info; bool drops metric name.',
'vector-match':'Default match ignores metric name; on matches selected labels, ignoring excludes labels; one-to-one default, group_left/right permit one-to-many and copy requested labels; many-to-many arithmetic/comparison or nonunique result labels are errors.',
'set-operators':'and/or/unless use label-set matching, preserve sample values and kinds; many-to-many matching allowed; no scalar operands, bool or grouping modifiers.',
'name-removal':'Arithmetic and most functions drop metric name; filter comparison normally keeps lhs name except on, group_right keeps rhs name; delayed-name-removal defers stripping until final result and affects collisions/regex selection.',
'ordering':'Instant vectors are unordered except explicit ordering functions/operators; range series sorted by labels; sample timestamps ascend; topk/bottomk order within groups is value-based for instant queries; annotation representation has profile-specific dedup/merge behavior and must not be sorted arbitrarily.',
'histogram-layout':'Exponential histograms reconcile to compatible coarser schemas and zero thresholds; incompatible custom/exponential layouts remove with annotations; pin-specific custom-bound reconciliation and counter reset collisions are separate evidence obligations.',
'annotations':'Warning and info severity, affected source ranges and metric context are observable; removal is not an evaluator error; annotation accumulation/deduplication differs between pins.',
'errors':'Separate lexical, syntax, type/arity, disabled-feature, invalid-regex/label, duplicate-labelset, many-to-many/multiple-match, invalid-parameter, invalid-time, sample-budget, timeout/cancel and storage errors; no error becomes empty successful vector.',
'duration-expression':'Duration expressions use arithmetic/parentheses and step(), range(), min_of(), max_of() under promql-duration-expr independent of function registry Experimental; detect nonpositive range/resolution, overflow and division/modulo by zero.',
'extended-range':'anchored extends preceding sample and is restricted to rate/increase/delta/changes/resets; smoothed uses boundary interpolation and is restricted to rate/increase/delta; gate required; unsupported parent functions error.',
'fill':'fill/fill_left/fill_right are gated binary matching modifiers supplying missing-side values; must distinguish unmatched series from present NaN and respect matching/group cardinality.',
'start-timestamps':'use-start-timestamps changes counter extrapolation using stored start timestamp metadata, independently of st-storage/st-synthesis ingestion switches.'}
AGGS={
'sum':'Sum floats or add histograms; mixed group removed with warning.', 'avg':'Arithmetic mean floats or histograms; mixed group removed with warning.',
'count':'Count all float/histogram samples into a float.', 'group':'Emit float 1 for every nonempty group.',
'min':'Minimum float, ignoring histograms with info; all-NaN group yields NaN.', 'max':'Maximum float, ignoring histograms with info; all-NaN group yields NaN.',
'stddev':'Population float standard deviation; ignore histograms with info.', 'stdvar':'Population float variance; ignore histograms with info.',
'quantile':'Scalar quantile with linear interpolation over floats; ignore histograms; out-of-range q gives signed infinity, NaN q NaN and warning.',
'count_values':'Count occurrences by string label; format float or histogram values as distinct label values; validate destination label.',
'topk':'Select k largest float samples per group; ignore histograms with info; k<=0 empty; truncate finite k to integer; NaN least preferred.',
'bottomk':'Select k smallest float samples per group; ignore histograms with info; k<=0 empty; truncate finite k to integer; NaN least preferred.',
'limitk':'Deterministic hash-based subset of k samples per group preserving float/histogram values; experimental gate; k<=0 empty.',
'limit_ratio':'Deterministic hash-based subset by ratio; negative ratio selects complement; clamp beyond [-1,1] with warning; both sample kinds retained.'}
def main():
    data={'schema':'soundpost-promql-independent-audit-v1','author':'Aryn Yklas','license':'Apache-2.0','complete':False,'profiles':[],'obligations':[],'flag_classifications':[],'configuration':[],'feature_sets':[],'case_descriptions':[],'unresolved':[],'source_discovery':[],'version_changes':[]}
    bindings=json.loads((ROOT/'conformance/query/promql-syntax-bindings.json').read_text())['bindings']
    functions_by_pin={}
    for pin in ['3.1.0','3.13.5']:
        src=load(pin); profile='promql-prometheus-'+pin
        data['profiles'].append({'id':profile,'commit':{'3.1.0':'7086161a93b262aa0949dbf2aba15a5a7b13e0a3','3.13.5':'f497435984d1ca1d84cda5ed309387ac2eb1f8f6'}[pin],'evaluator_binding':'pending','corpus_reuse':False,'license_review':'No upstream corpus copied; only names, signatures, locations and hashes extracted.'})
        def add(key,kind,sig,rule,path,needle=None,gate=''):
            oid=profile+'/'+key
            cases={k:oid+'/'+k for k in ['positive','negative','interaction']}
            for k,cid in cases.items(): data['case_descriptions'].append({'id':cid,'profile':profile,'purpose':k,'description':({'positive':'Observe '+rule,'negative':'Reject invalid input or distinguish nonapplicability without inventing a numeric sample for '+sig,'interaction':'Exercise '+sig+' with ordinary NaN, stale, signed zero, float/native mixtures, empty input, name collisions and gate contexts where applicable.'}[k]),'status':'independently-authored-description; not executed'})
            b=[x['case_id'] for x in bindings if x['obligation']==oid]
            data['obligations'].append({'id':oid,'kind':kind,'profile':profile,'gate':gate,'signature':sig,'semantic_rule':rule,'source_refs':[ref(src,path,needle)],'implementation':'pending-evaluator-binding','positive_cases':[cases['positive']],'negative_cases':[cases['negative']],'interaction_cases':[cases['interaction']],'syntax_case_refs':b,'syntax_refs_are_evaluation_evidence':False})
            if kind in ['function-signature','aggregation','semantic-family']:
                data['obligations'][-1]['source_refs'].extend([ref(src,'promql/functions.go'),ref(src,'promql/engine.go')])
        for key,rule in FAMILIES.items():
            if pin=='3.1.0' and key in ['duration-expression','extended-range','fill','start-timestamps']:continue
            path='promql/parser/generated_parser.y' if key in ['lexical','precedence','selector','duration-expression'] else 'promql/engine.go'
            gate={'duration-expression':'promql-duration-expr','extended-range':'promql-extended-range-selectors','fill':'promql-binop-fill-modifiers','start-timestamps':'use-start-timestamps','name-removal':'promql-delayed-name-removal'}.get(key,'')
            add('semantics/'+key,'semantic-family',key,rule,path,gate=gate)
        for name,body in re.findall(r'^\s*"([^"]+)": \{(.*?)^\s*\},',src['promql/parser/functions.go'],re.M|re.S):
            args=re.search(r'ArgTypes:\s*\[\]ValueType\{([^}]*)\}',body).group(1)
            args=[a.strip().replace('ValueType','').lower() for a in args.split(',') if a.strip()]
            ret=re.search(r'ReturnType:\s*ValueType(\w+)',body).group(1).lower()
            vm=re.search(r'Variadic:\s*(-?\d+)',body); variadic=int(vm.group(1)) if vm else 0
            gate='promql-experimental-functions' if 'Experimental: true' in body or re.search(r'Experimental:\s+true',body) else ''
            sig=name+'('+','.join(args)+')->'+ret+'; variadic='+str(variadic)
            rule=RULES.get(name)
            if not rule:
                data['unresolved'].append({'profile':profile,'id':'function/'+name,'detail':'Behavioral rule not classified; inspect function implementation before accepting.'});continue
            add('function/'+name,'function-signature',sig,rule,'promql/parser/functions.go','"'+name+'":',gate)
            o=data['obligations'][-1];o['argument_types']=args;o['return_type']=ret;o['variadic']=variadic
            o['arity_domain_note']='A negative variadic marker repeats the final declared type and permits zero repeats; positive variadic is the number of optional trailing arguments.'
            if name=='histogram_fraction' and pin=='3.1.0':o['semantic_rule']='Estimate fraction between scalar bounds using native histogram bucket interpolation only; ignore float samples. Empty histogram and NaN bounds yield NaN; distinguish +/-Inf and equal/reversed bounds.'
            example_args={'vector':'signal','matrix':'signal[6m]','scalar':'0.5','string':'"zone"'}
            query=name+'('+','.join(example_args[a] for a in args)+')'
            for case in data['case_descriptions'][-3:]:
                case['example_query']=query if case['purpose']!='negative' else name+'("wrong-type", "extra")'
                case['fixture']='Independently authored signal{zone="east"} float series at 0s=2, 60s=4, 120s=3, with optional native histogram peer; evaluate at 120s. Type-directed query is a signature probe, not a claimed numeric golden.'
            o['arity_domain']={'minimum':len(args)-variadic if variadic>0 else len(args)-1 if variadic<0 else len(args),'maximum':None if variadic<0 else len(args),'boundary_cases':['minimum-1','minimum','maximum','maximum+1','wrong-type-each-position']}
            if name in ['step','range','min_of','max_of']:
                o['registry_experimental_flag']=gate
                o['gate']='promql-duration-expr'
                o['gate_contexts']={'duration-expr-production':'promql-duration-expr','registry-declaration-only':'promql-experimental-functions'}
                o['gate_note']='Reserved zero/two-argument forms reduce through duration_expr, including expression position. The registry Experimental bit is not sufficient to classify their actual parse gate. Both-switch cross-product must be tested.'
                o['source_refs'].append(ref(src,'promql/parser/generated_parser.y','duration_expr   :'))
        functions_by_pin[pin]=[o['signature'] for o in data['obligations'] if o['profile']==profile and o['kind']=='function-signature']
        for name,rule in AGGS.items():add('aggregation/'+name,'aggregation',name+'([parameter,] instant-vector) [by|without(labels)]',rule+' Group by retains listed labels; without removes listed labels and metric name; absent grouping yields one global group.','promql/engine.go',gate='promql-experimental-functions' if name in ['limitk','limit_ratio'] else '')
        for opname in ['add','sub','mul','div','mod','pow','atan2','eq','ne','gt','lt','ge','le']:
            for left,right in itertools.product(['float','histogram'],repeat=2):
                comparison=opname in ['eq','ne','gt','lt','ge','le']
                valid=(left==right=='float' or (left==right=='histogram' and opname in ['add','sub','eq','ne']) or (left!=right and opname=='mul') or (left=='histogram' and right=='float' and opname=='div'))
                rule=('Apply numeric float operator; comparisons filter lhs unless bool emits 0/1.' if left==right=='float' else 'Compare full compacted histograms for equality/inequality; preserve lhs histogram on passing filter.' if comparison and valid else 'Combine compatible histogram layouts for addition/subtraction; subtraction is gauge; emit layout/reset annotations when required.' if left==right=='histogram' and valid else 'Scale every bucket, count and sum; negative factor makes gauge; histogram divided by zero yields special infinite/NaN populations.' if valid else 'Remove this element and add incompatible sample-type info; do not coerce histogram to float.')
                add('operator/'+opname+'/'+left+'-'+right,'operator-overload',opname+'('+left+','+right+')',rule,'promql/engine.go','func vectorElemBinop')
        for opname in ['and','or','unless']:
            add('operator/'+opname,'set-operator',opname+'(vector,vector)',FAMILIES['set-operators'],'promql/engine.go')
        for typ,rule in {
            'scalar':'Single IEEE float at each evaluation timestamp; scalar/scalar comparison requires bool.',
            'string':'Quoted literal string; permitted as function argument, not numeric vector/matrix; range root rejected.',
            'instant-vector':'At most one sample per resulting label set per step; sample kind is float or native histogram.',
            'range-vector':'Per-series ordered samples in left-open/right-closed window; only vector selectors/subqueries produce it; not valid binary operand.'
        }.items():add('type/'+typ,'value-type',typ,rule,'promql/parser/parse.go')
        if pin=='3.13.5':
            for opname in ['trim-upper','trim-lower']:
                add('operator/'+opname,'operator-overload',opname+'(histogram,float)','Trim histogram buckets at scalar boundary. Only histogram lhs and float rhs are supported; other sample-kind combinations remove with incompatible-type info. Exact boundary bucket splitting/NaN/custom-layout behavior is separately unresolved.','promql/engine.go','case parser.TRIM_UPPER:')
            add('modifier/fill-typecheck','modifier','fill/fill_left/fill_right','Fill modifiers require two instant-vector operands; set operators reject fill; disabled promql-binop-fill-modifiers rejects syntax. Scalar/vector filling is a type error, not ordinary scalar broadcasting.','promql/parser/parse.go','filling in missing series only allowed','promql-binop-fill-modifiers')
        grammar=src['promql/parser/generated_parser.y']
        for production in re.findall(r'^([a-z][a-z_0-9]*)\s*:',grammar,re.M):
            # Parser test-description entrypoints are development input, not user query grammar.
            is_fixture=production.startswith(('series_','histogram_','bucket_','counter_reset')) or production in ['int','uint']
            data['source_discovery'].append({'profile':profile,'kind':'grammar-production','symbol':production,'classification':'development-fixture-input' if is_fixture else 'query-syntax','maps_to':['semantics/lexical','semantics/precedence','semantics/selector','semantics/at-offset','semantics/subquery'],'reason':'Description/fixture reader is not the public expression entrypoint.' if is_fixture else 'Syntax obligation is owned by independent parser cases; this mapping does not assert evaluator execution.','source_ref':ref(src,'promql/parser/generated_parser.y',production)})
        head=grammar.split('%%')[0]
        tokens=[]
        for block in re.findall(r'%token\s*(.*?)(?=%|//|$)',head,re.S):tokens.extend(re.findall(r'\b[A-Z][A-Z_0-9]*\b',block))
        for token in sorted(set(tokens)):data['source_discovery'].append({'profile':profile,'kind':'token','symbol':token,'classification':'lexical-or-parser-entry-token','maps_to':['semantics/lexical'],'source_ref':ref(src,'promql/parser/generated_parser.y',token)})
        source=src['cmd/prometheus/main.go']; switches=source[source.index('func (c *flagConfig) setFeatureListOptions'):source.index('func main()')]
        features=[]
        for match in re.finditer(r'case "([^"]+)":(.*?)(?=\n\s*case |\n\s*default:)',switches,re.S):
            name,body=match.groups(); semantic=name in ['promql-experimental-functions','promql-delayed-name-removal','promql-duration-expr','promql-extended-range-selectors','promql-binop-fill-modifiers','use-start-timestamps','type-and-unit-labels']
            no_op='no-op' in body
            row={'profile':profile,'name':'enable-feature/'+name,'classification':'semantic' if semantic else 'nonsemantic-no-op' if no_op else 'nonsemantic-query-input' if name in ['native-histograms','ooo-native-histograms','created-timestamp-zero-ingestion','st-storage','st-synthesis','type-and-unit-labels','otlp-deltatocumulative','otlp-native-delta-ingestion','extra-scrape-metrics'] else 'nonsemantic-process','default':False,'source_ref':ref(src,'cmd/prometheus/main.go','case "'+name+'":'),'reason':'Changes accepted language or evaluation over the same authorized input.' if semantic else 'Upstream explicitly does not change behavior for this switch.' if no_op else 'Changes acquisition/storage/metadata of input, not language evaluation for identical supplied samples.' if name in ['native-histograms','ooo-native-histograms','created-timestamp-zero-ingestion','st-storage','st-synthesis','type-and-unit-labels','otlp-deltatocumulative','otlp-native-delta-ingestion','extra-scrape-metrics'] else 'Changes introspection, scheduling, persistence, UI or transport; not expression values for identical input.'}
            data['flag_classifications'].append(row)
            if semantic:features.append(name)
        # Read all actual registrations, including Hidden(), instead of treating default help as complete.
        found={}
        for match in re.finditer(r'\.Flag\(\s*"([^"]+)"',source):
            name=match.group(1); tail=source[match.end():]; stop=re.search(r'\n\s*\n',tail); block=tail[:stop.start()] if stop else tail[:1000]
            default=re.search(r'\bDefault\((.*?)\)\.',block,re.S)
            found[name]={'profile':profile,'name':name,'classification':'semantic-configuration' if name in ['query.lookback-delta','query.max-samples','query.timeout','enable-feature'] else 'nonsemantic-query-input' if name.startswith('scrape.') else 'nonsemantic-process','default_expression':default.group(1) if default else 'false (zero-valued bool binding)' if re.search(r'\bBool(?:Var)?\(',block) else 'registration has no explicit Default; see bound variable initialization','hidden':bool(re.search(r'\bHidden\(\)',block)),'source_ref':ref(src,'cmd/prometheus/main.go',match.group(0)),'reason':'Changes selected samples, language gates or observable query budget failure.' if name in ['query.lookback-delta','query.max-samples','query.timeout','enable-feature'] else 'Scrape-side sample acquisition, outside evaluation over fixed input.' if name.startswith('scrape.') else 'Process, storage, notification, scheduling, transport or UI setting; fixed-input PromQL value semantics unchanged.'}
        helpfile='oracle-da1630-help.txt' if pin=='3.1.0' else 'oracle-dc3031-help.txt'
        helptext=(ROOT/'.superpowers/sdd/approved-product'/helpfile).read_text()
        for name,default in re.findall(r'--(?:\[no-\])?([\w.-]+)([^\n]*)',helptext):
            if name not in found:found[name]={'profile':profile,'name':name,'classification':'nonsemantic-introspection' if name in ['help','help-long','help-man','version'] else 'nonsemantic-process','default_expression':default.strip(),'source_ref':helpfile+':'+str(helptext[:helptext.index('--'+ ('[no-]' if '--[no-]'+name in helptext else '')+name)].count('\n')+1)+'@'+digest(helptext),'reason':'Binary help/flag-library process control; no expression value changes for fixed input.'}
        data['flag_classifications'].extend(found.values())
        # Content-bound semantic projection: independent toggles have no parser/engine mutual exclusion.
        for bits in itertools.product([False,True],repeat=len(features)):
            enabled=sorted(f for f,b in zip(features,bits) if b); disabled=sorted(set(features)-set(enabled)); payload={'profile':profile,'enabled':enabled,'disabled':disabled,'source_sha256':{p:digest(src[p]) for p in ['cmd/prometheus/main.go','promql/parser/functions.go','promql/parser/generated_parser.y','config/config.go']}}
            data['feature_sets'].append({'id':profile+'/semantic-sha256-'+digest(json.dumps(payload,sort_keys=True,separators=(',',':'))),'profile':profile,'enabled':enabled,'disabled':disabled,'identity_payload':payload,'identity_scope':'query-language semantic gates and exact source/default registries; acquisition/process switches are explicitly projected out','disabled_cases':{g:[profile+'/gate/'+g+'/disabled'] for g in disabled}})
        for g in features:
            data['case_descriptions'].append({'id':profile+'/gate/'+g+'/disabled','profile':profile,'description':'Disable '+g+' while all other semantic gates are enabled; reject gated syntax/function or observe the baseline ungated name/time behavior.','status':'independently-authored-description; not executed'})
        for name,default,domain in [
            ('query.lookback-delta','5m',{'valid':'nonnegative duration at engine boundary; zero engine option falls back to default','boundaries':['0','1ms','5m-1ms','5m','5m+1ms','maximum duration'],'interactions':['sample at target-lookback','sample one millisecond before bound','stale within lookback']}),
            ('query.timeout','2m',{'valid':'duration accepted by flag parser; nonpositive yields immediately expiring context','boundaries':['-1ms','0','1ms','2m'],'interactions':['cancellation before scan','timeout during subquery']}),
            ('query.max-samples','50000000',{'valid':'integer sample memory budget','boundaries':['0','1','limit-1','limit','limit+1'],'interactions':['histogram memory weighted samples','subquery peak memory','aggregation release']}),
            ('global.evaluation_interval','1m',{'valid':'positive duration; default subquery resolution derives from this value','boundaries':['0 invalid','1ms','1m'],'interactions':['subquery implicit resolution','explicit resolution overrides']}),
            ('engine.enable-at-modifier','true',{'valid':[False,True],'boundaries':[False,True],'interactions':['@start()','@end()','@numeric']}),
            ('engine.enable-negative-offset','true',{'valid':[False,True],'boundaries':[False,True],'interactions':['offset 0','offset -1ms','@ offset order']})]:
            data['configuration'].append({'profile':profile,'name':name,'default':default,'domain':domain,'source_ref':ref(src,'cmd/prometheus/main.go' if name.startswith(('query.','engine.')) else 'config/config.go'),'classification':'semantic'})
        # Enumerate relevant configuration fields as facts, not a fictional copied config universe.
        config=src['config/config.go']
        relevant=['evaluation_interval','scrape_interval','scrape_timeout','scrape_protocols','metric_name_validation_scheme','metric_name_escaping_scheme','honor_labels','honor_timestamps','track_timestamps_staleness','metric_relabel_configs','relabel_configs','sample_limit','label_limit','label_name_length_limit','label_value_length_limit','native_histogram_bucket_limit','native_histogram_min_bucket_factor','always_scrape_classic_histograms','scrape_native_histograms','convert_classic_histograms_to_nhcb','out_of_order_time_window','external_labels']
        for name in relevant:
            if name=='evaluation_interval':continue
            if 'yaml:"'+name not in config:continue
            data['configuration'].append({'profile':profile,'name':name,'classification':'nonsemantic-fixed-input-acquisition','reason':'Changes which samples/labels are admitted, represented or retained; owned input is already materialized. Does not modify evaluation over identical input.','default_source':ref(src,'config/config.go','yaml:"'+name),'boundary_domains':['unset/inherited','explicit default','zero or empty where valid','minimum valid','invalid below minimum','configured cap-1/cap/cap+1 where numeric'],'scope':'acquisition evidence, not an enabled language gate'})
        ann=src['util/annotations/annotations.go']
        for name in re.findall(r'^\s*(\w+(?:Warning|Info))\s*=\s*fmt\.Errorf',ann,re.M):
            data['source_discovery'].append({'profile':profile,'kind':'annotation-category','symbol':name,'classification':'observable-diagnostic','maps_to':['semantics/annotations','semantics/histogram-layout','semantics/arithmetic'],'source_ref':ref(src,'util/annotations/annotations.go',name)})
        add('diagnostic/accumulation','annotation-behavior','warning/info deduplication','Annotations are keyed by rendered error text. '+('Duplicate key replaces previous annotation; map iteration has no stable upstream ordering.' if pin=='3.1.0' else 'Duplicate key invokes specialized Merge when implemented, otherwise keeps one annotation; map iteration has no stable upstream ordering.')+' Warning/info lists are split by severity; limits append omitted-count summary. Preserve captured ordered oracle diagnostics; do not invent a deterministic source order.','util/annotations/annotations.go','func (a *Annotations) Add')
    a=set(functions_by_pin['3.1.0']);b=set(functions_by_pin['3.13.5'])
    data['version_changes']=[{'kind':'function-signature-added','signature':s} for s in sorted(b-a)]+[{'kind':'function-signature-removed','signature':s} for s in sorted(a-b)]
    data['version_changes'] += [{'kind':'semantic-change','description':s} for s in ['3.13.5 adds duration expression, extended range, binary fill, type/unit diagnostics and start timestamp engine contexts.','native-histograms and ooo-native-histograms switches become no-ops; native scrape configuration controls acquisition in 3.13.5.','3.13.5 annotation categories add histogram mixed-range, sort-in-range, NaN quantile/fraction, reset-collision and custom-bucket-reconciliation observations.','3.13.5 introduces histogram trim operators </ and >/; overload and finite/zero/infinite boundary rules are independently classified.']]
    runpy.run_path(str(OUT.with_name('promql-details.py')))['close'](data,ROOT,load,ref)
    data['obligations'].sort(key=lambda x:x['id']);data['flag_classifications'].sort(key=lambda x:(x['profile'],x['name']))
    OUT.write_text(json.dumps(data,indent=2)+'\n',encoding='utf8')
    print(json.dumps({'artifact':str(OUT),'obligations':len(data['obligations']),'flags':len(data['flag_classifications']),'feature_sets':len(data['feature_sets']),'unresolved':len(data['unresolved'])}))
if __name__=='__main__': main()
