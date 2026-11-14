import sys, unittest, zipfile, io
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from deep_scan import deep_analyze

def apk(pkg, nested=None):
    s=io.BytesIO()
    with zipfile.ZipFile(s,'w') as z:
        z.writestr('AndroidManifest.xml',f'<manifest package="{pkg}"/>')
        if nested: z.writestr('assets/embedded.apk',nested)
    return s.getvalue()
class DeepTests(unittest.TestCase):
    def test_clean_apk_no_canned_stage_or_commands(self):
        r=deep_analyze(apk('org.demo.harmless'),'safe.apk')
        self.assertEqual(r['stage_count'],1)
        self.assertEqual(r['command_indicators'],[])
        self.assertEqual(r['configured_endpoints'],[])
    def test_embedded_apk_is_recursively_analyzed(self):
        r=deep_analyze(apk('org.demo.wrapper',apk('org.demo.second')),'outer.apk')
        self.assertEqual(r['stage_count'],2)
        self.assertEqual(r['stages'][1]['metadata']['package'],'org.demo.second')
        self.assertIn('Embedded APK',str(r['loader_notes']))
if __name__=='__main__':unittest.main()
