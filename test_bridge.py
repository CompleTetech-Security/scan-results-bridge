"""Synthetic reports; no targets, uploads or credentials."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import scan_results_bridge as c


def report(status='unknown', source=False):
    evidence=[{'id':'e1','kind':'source','state':'candidate','detail':'token=SECRET https://private.invalid?q=SECRET','path':'src/worker α.js','line':4}] if source else []
    evidence.append({'id':'v1','kind':'version','state':'present','detail':'24.22.0 operator reported'})
    row=c.make_result('private-asset','node','CVE-2026-111497',status,version='24.22.0',sources=['https://nodejs.org/en/blog/vulnerability/october-2026-security-releases'],version_assessment='affected' if status=='potentially_affected' else 'unknown',evidence=evidence,recommendation='Inspect C:/private/path token=SECRET')
    return c.make_report('synthetic-check','1.0.0','synthetic-1','2026-10-25',[row])


class BridgeTests(unittest.TestCase):
    def cli(self,*args):
        with contextlib.redirect_stdout(io.StringIO()) as out,contextlib.redirect_stderr(io.StringIO()) as err:
            with patch('socket.socket',side_effect=AssertionError('network forbidden')):
                code=c.main(list(args))
        return code,out.getvalue(),err.getvalue()

    def test_private_tool_versions_reject_even_empty_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'input.json'
            for empty in (False,True):
                value=report();value['tool']['version']='https://private.invalid/?token=SYNTHETIC_SECRET'
                if empty:value['results']=[]
                path.write_text(json.dumps(value),encoding='utf-8')
                for fmt in ('sarif','ndjson'):
                    code,out,_=self.cli('--input',str(path),'--format',fmt)
                    self.assertEqual((2,''),(code,out))

    def test_corroborating_source_locations_and_report_limitations(self):
        value=report(source=True);first=c.normalize(value,'contract-v1.0',True)[0]
        corroborating=copy.deepcopy(value['results'][0]['evidence'][0]);corroborating['id']='e2'
        value['results'][0]['evidence'].append(corroborating)
        second=c.normalize(value,'contract-v1.0',True)[0]
        self.assertEqual(first['location'],second['location'])
        self.assertEqual(first['fingerprint'],second['fingerprint'])
        value['limitations']=['private limitation SECRET']
        third=c.normalize(value,'contract-v1.0',True)[0]
        self.assertNotEqual(second['evidence_sha256'],third['evidence_sha256'])
        self.assertNotIn('SECRET',json.dumps(third))
        self.assertEqual(2,len(c.deduplicate([second,third])))

    def test_source_opt_in_and_inventory_never_fabricates_location(self):
        for source in (True,False):
            value=report(source=source)
            rows=c.normalize(value,'contract-v1.0')
            self.assertIsNone(rows[0]['location'])
            self.assertEqual(source,rows[0]['location_redacted'])
            rows=c.normalize(value,'contract-v1.0',True)
            sarif=c.to_sarif(rows,True)
            result=sarif['runs'][0]['results'][0]
            self.assertEqual(source,'locations' in result)
            if source:self.assertEqual('src/worker%20%CE%B1.js',result['locations'][0]['physicalLocation']['artifactLocation']['uri'])

    def test_privacy_projection_and_fingerprints_stable_across_status(self):
        first=c.normalize(report(source=True),'contract-v1.0')[0]
        later=report('potentially_affected',True)
        second=c.normalize(later,'contract-v1.0')[0]
        self.assertEqual(first['fingerprint'],second['fingerprint'])
        text=json.dumps(c.to_sarif([first],True))
        for secret in ('SECRET','private.invalid','private-asset','C:/private/path','worker'):
            self.assertNotIn(secret,text)
        self.assertEqual('candidate',first['evidence']['evidence'][0]['state'])
        self.assertEqual('not_tested',first['exploitability'])

    def test_duplicates_order_and_conflicts_are_distinct(self):
        value=report();value['results']*=2
        self.assertEqual(1,len(c.normalize(value,'contract-v1.0')))
        self.assertEqual(2,c.normalize(value,'contract-v1.0')[0]['occurrences'])
        other=report('potentially_affected')['results'][0]
        value['results'].append(other)
        left=c.normalize(value,'contract-v1.0');value['results'].reverse()
        self.assertEqual(left,c.normalize(value,'contract-v1.0'))
        self.assertEqual(2,len(left))

    def test_invalid_contract_and_semantic_contradictions_reject(self):
        for key,item in [('schema_version','2.0'),('complete','true')]:
            value=report();value[key]=item
            with self.assertRaises(ValueError):c.normalize(value,'contract-v1.0')
        for key,item in [('exploitability','confirmed'),('status','safe')]:
            value=report();value['results'][0][key]=item
            with self.assertRaises(ValueError):c.normalize(value,'contract-v1.0')
        value=report();value['results'][0]['status']='likely_exposed'
        with self.assertRaises(ValueError):c.normalize(value,'contract-v1.0')
        for path in ('/tmp/file','../file','C:/file','x\\y','x//y','https://private.invalid'):
            self.assertIsNone(c.source_location(path,1))
        self.assertIsNone(c.source_location('src/file',True))

    def test_policy_exit_codes_ndjson_and_incomplete_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'input.json'
            for status,policy,code in [('unknown','none',0),('unknown','unknown',1),('potentially_affected','findings',1),('unknown','findings',0)]:
                path.write_text(json.dumps(report(status)),encoding='utf-8')
                actual,out,err=self.cli('--input',str(path),'--format','ndjson','--fail-on',policy)
                self.assertEqual((code,''),(actual,err));rows=[json.loads(line) for line in out.splitlines()]
                self.assertEqual('summary',rows[-1]['record_type'])
            value=report();value['complete']=False;value['results']=[]
            path.write_text(json.dumps(value),encoding='utf-8')
            code,out,_=self.cli('--input',str(path),'--format','ndjson')
            self.assertEqual(2,code);self.assertFalse(json.loads(out)['complete'])

    def test_output_protection_standalone_and_no_clobber(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);path=root/'input.json';path.write_text(json.dumps(report()),encoding='utf-8')
            for force in ([],['--force']):
                self.assertEqual(2,self.cli('--input',str(path),'--output',str(path),*force)[0])
            output=root/'out.json';output.write_text('existing',encoding='utf-8')
            self.assertEqual(2,self.cli('--input',str(path),'--output',str(output))[0])
            self.assertEqual('existing',output.read_text())
            self.assertEqual(0,self.cli('--input',str(path),'--output',str(output),'--force')[0])
            executable=root/'standalone.py';executable.write_bytes(Path(c.__file__).read_bytes())
            result=subprocess.run([sys.executable,str(executable),'--input',str(path)],capture_output=True,text=True)
            self.assertEqual(0,result.returncode);self.assertEqual('2.1.0',json.loads(result.stdout)['version'])

    def test_malformed_bounds_and_duplicate_keys_reject_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'input.json'
            for text in ('{"complete":true,"complete":false}','{"complete":NaN}', '['*60+'0'+']'*60):
                path.write_text(text,encoding='utf-8');code,out,_=self.cli('--input',str(path));self.assertEqual((2,''),(code,out))
            path.write_bytes(b' '*(4*1024**2+1));self.assertEqual(2,self.cli('--input',str(path))[0])

    def test_canonical_versions_sources_ids_and_fingerprint_updates(self):
        value=report();first=c.normalize(value,'contract-v1.0')[0]
        value['results'][0]['component']['version']='24.22.1'
        value['results'][0]['component']['build_source']='upstream'
        second=c.normalize(value,'contract-v1.0')[0]
        self.assertEqual(first['fingerprint'],second['fingerprint'])
        self.assertNotEqual(first['evidence_sha256'],second['evidence_sha256'])
        row=copy.deepcopy(value['results'][0]);row['version_assessment']='affected'
        value['results'].append(row)
        row=copy.deepcopy(row);row['sources']=['https://example.invalid/other'];value['results'].append(row)
        self.assertEqual(3,len(c.normalize(value,'contract-v1.0')))
        value['results'][0]['rule_id']='vendor:rule'
        self.assertIn('vendor:rule',[r['rule_id'] for r in c.normalize(value,'contract-v1.0')])

    def test_same_line_candidates_and_distinct_export_artifacts_keep_identity(self):
        rows=[dict(copyescape_status="unknown",copyescape_exploitability="not_tested",label="src/copy.sh",component="docker-cli",copyescape_evidence_type="lexical_workflow_candidate",source_path="src/copy.sh",source_line=2,source_candidate=n) for n in (1,2)]
        value=dict(tool="copyescape-check",tool_version="1.1.0",schema_version="1.1",complete=True,results=rows)
        normalized=c.normalize(value,"copyescape-v1.1")
        self.assertEqual(2,len({row["fingerprint"] for row in normalized}))
        for index,row in enumerate(rows):row.update(copyescape_evidence_type="docker_version_export",source_instance=str(index+1)*64,source_candidate=0)
        self.assertEqual(2,len({row["fingerprint"] for row in c.normalize(value,"copyescape-v1.1")}))
        value=report();other=copy.deepcopy(value);other['rules']['snapshot_id']='synthetic-2'
        first=c.normalize(value,'contract-v1.0')[0];second=c.normalize(other,'contract-v1.0')[0]
        self.assertEqual(first['fingerprint'],second['fingerprint'])
        self.assertNotEqual(first['evidence_sha256'],second['evidence_sha256'])

    def test_nonfinite_exponent_and_per_tool_empty_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);path=root/'input.json'
            data=dict(tool='node2shell-check',tool_version='1.0.0',complete=True,results=[dict(node2shell_status='unknown',node2shell_exploitability='not_tested',other=float('inf'))])
            path.write_text(json.dumps(data).replace('Infinity','1e999'),encoding='utf-8')
            code,out,_=self.cli('--input',str(path),'--input-schema','node2shell-v1')
            self.assertEqual((2,''),(code,out))
            data['results'][0].pop('other');data['results'][0]['k'*16385]=0
            path.write_text(json.dumps(data),encoding='utf-8')
            self.assertEqual(2,self.cli('--input',str(path),'--input-schema','node2shell-v1')[0])
            first=report();first['results']=[]
            second=report();second['tool']['name']='other-check';second['complete']=False
            second['results']=[]
            path.write_text(json.dumps(first),encoding='utf-8');other=root/'other.json';other.write_text(json.dumps(second),encoding='utf-8')
            code,out,_=self.cli('--input',str(path),'--input',str(other))
            self.assertEqual(2,code)
            runs={run['tool']['driver']['name']:run for run in json.loads(out)['runs']}
            self.assertTrue(runs['synthetic-check']['invocations'][0]['executionSuccessful'])
            self.assertFalse(runs['other-check']['invocations'][0]['executionSuccessful'])

    def test_legacy_profiles_fail_closed_and_preserve_unknown(self):
        for profile,(tool,prefix,rule) in c.PROFILES.items():
            value=dict(tool=tool,tool_version='1.0.0',complete=True,results=[{prefix+'status':'unknown',prefix+'exploitability':'not_tested','label':'private'}])
            if profile == 'flowise-v1': value['results'][0]['version_status'] = value['results'][0].pop('status')
            if profile.endswith('v1.1'):value['schema_version' if profile=='copyescape-v1.1' else 'report_schema_version']='1.1'
            elif profile!='node2shell-v1':value['schema_version']=1
            row=c.normalize(value,profile)[0]
            self.assertEqual('unknown',row['status']);self.assertEqual(rule,row['rule_id'])
            value['tool']='wrong'
            with self.assertRaises(ValueError):c.normalize(value,profile)


if __name__=='__main__':unittest.main()
