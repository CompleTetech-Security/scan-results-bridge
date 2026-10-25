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
print('Five synthetic SARIF variants validated against bundled official OASIS schema.')
