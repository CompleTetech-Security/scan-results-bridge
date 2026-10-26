"""Optional dev check; uses only the vendored official schema, no remote refs."""
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import jsonschema
import scan_results_bridge as c
from test_bridge import report
root=Path(__file__).resolve().parents[1]
schema=json.loads((root/'schemas/sarif-schema-2.1.0.json').read_text(encoding='utf-8'))
validator=jsonschema.Draft4Validator(schema,format_checker=jsonschema.FormatChecker())
for source in (False,True):
    for status in ('unknown','potentially_affected'):
        rows=c.normalize(report(status,source),'contract-v1.0',True)
        validator.validate(c.to_sarif(rows,True))
validator.validate(c.to_sarif([],False))
first=report();first['results']=[]
second=report();second['results']=[];second['complete']=False
second['rules']['snapshot_id']='synthetic-2'
second['limitations']=['Synthetic private limitation']
for reports in ([first], [second], [first,second], [report(source=True),first]):
    rows=[];completions={};envelopes=[]
    for value in reports:
        rows.extend(c.normalize(value,'contract-v1.0',True))
        identity=(value['tool']['name'],value['tool']['version'])
        completions[identity]=completions.get(identity,True) and value['complete']
        envelopes.append(c.report_envelope(value,'contract-v1.0'))
    validator.validate(c.to_sarif(rows,all(v['complete'] for v in reports),completions,envelopes))
print('Nine synthetic SARIF variants validated against bundled official OASIS schema.')
