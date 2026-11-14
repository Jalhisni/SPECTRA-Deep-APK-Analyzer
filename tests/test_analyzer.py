import io, struct, sys, unittest, zipfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from analyzer import analyze_apk, inspect_manifest, decode_axml, parse_dex, APKError

def make_dex(vals, refs):
    """Minimal DEX-format lookup tables, not an executable Android program."""
    allstr=list(dict.fromkeys(vals+[t for cl,m in refs for t in [cl,m]]))
    types=list(dict.fromkeys(cl for cl,m in refs))
    d=bytearray(112)
    d[:8]=b'dex\n035\x00'
    off=112
    ss=len(allstr);struct.pack_into('<II',d,0x38,ss,off);d+=b'\x00'*(ss*4);off+=ss*4
    struct.pack_into('<II',d,0x40,len(types),off)
    for t in types:d+=struct.pack('<I',allstr.index(t));off+=4
    struct.pack_into('<II',d,0x58,len(refs),off)
    for cl,m in refs:d+=struct.pack('<HHI',types.index(cl),0,allstr.index(m));off+=8
    for idx,s in enumerate(allstr):
        b=s.encode('utf-8');struct.pack_into('<I',d,112+idx*4,off)
        if len(b)>=128:raise AssertionError('test string too long')
        d+=bytes([len(b)])+b+b'\x00';off=len(d)
    struct.pack_into('<I',d,0x20,len(d))
    return bytes(d)

def make_apk(manifest,dex=b''):
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w') as z:
        z.writestr('AndroidManifest.xml',manifest)
        if dex:z.writestr('classes.dex',dex)
    return out.getvalue()

class TestScanner(unittest.TestCase):
    def test_benign_manifest(self):
        data=make_apk(b'<manifest package="com.safe.demo" xmlns:android="http://schemas.android.com/apk/res/android"><uses-sdk android:targetSdkVersion="35"/><application/></manifest>',make_dex(['Hello world'],[]))
        r=analyze_apk(data,'benign.apk')
        self.assertEqual(r['metadata']['package'],'com.safe.demo')
        self.assertEqual(r['assessment']['review_score'],0)
        self.assertEqual(r['indicators'],[])
        self.assertEqual(r['coverage']['dex_files'],1)
        self.assertEqual(r['findings'],[])
    def test_suspicious_correlation_from_content(self):
        m=b'''<manifest package="com.test.observe" xmlns:android="http://schemas.android.com/apk/res/android"><uses-permission android:name="android.permission.CAMERA"/><uses-permission android:name="android.permission.INTERNET"/><uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/><uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/><application><service android:name=".ObserveService" android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"/></application></manifest>'''
        d=make_dex(['https://watcher.invalid/collect','TYPE_VIEW_TEXT_CHANGED','multipart/form-data'],[
          ('Landroid/hardware/Camera;','open'),('Landroid/accessibilityservice/AccessibilityService;','onAccessibilityEvent'),
          ('Ljava/net/HttpURLConnection;','setDoOutput'),('Ljava/io/FileInputStream;','read'),
          ('Landroid/app/AlarmManager;','setRepeating')])
        r=analyze_apk(make_apk(m,d),'suspect.apk')
        ids=[x['id'] for x in r['findings']]
        self.assertIn('camera',ids)
        self.assertIn('accessibility',ids)
        self.assertIn('upload',ids)
        self.assertIn('possible_keylogging',ids)
        self.assertIn('possible_exfil',ids)
        self.assertIn('possible_camera_exfil',ids)
        self.assertEqual(r['coverage']['dex_method_refs'],5)
        self.assertIn('not confirmed',str(r['findings']).lower())
        self.assertEqual(r['assessment']['priority'],'High')
    def test_bad_input(self):
        with self.assertRaises(APKError):analyze_apk(b'not an APK')
    def test_no_manifest(self):
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w') as z:z.writestr('README','x')
        report=analyze_apk(out.getvalue())
        self.assertTrue(report['warnings'])
        self.assertEqual(report['assessment']['review_score'],0)
    def test_no_canned_results(self):
        m=b'<manifest package="nothing"/>'
        r=analyze_apk(make_apk(m,make_dex(['not at all malicious'],[])))
        self.assertEqual(len(r['findings']),0)
        self.assertEqual(len(r['indicators']),0)

if __name__=='__main__':unittest.main()

def synthetic_binary_manifest():
    """Generate minimal genuine AXML container for decoding regression test."""
    names=['manifest','uses-permission','application','package','com.test.binary','name',
           'http://schemas.android.com/apk/res/android','android.permission.CAMERA']
    n={s:i for i,s in enumerate(names)}
    string_payload=bytearray()
    offsets=[]
    for s in names:
        b=s.encode();assert len(b)<128
        offsets.append(len(string_payload));string_payload+=bytes([len(s),len(b)])+b+b'\x00'
    while len(string_payload)%4:string_payload+=b'\x00'
    sp_hsz=28;start=sp_hsz+len(names)*4
    sp_size=start+len(string_payload)
    pool=bytearray(struct.pack('<HHI',1,sp_hsz,sp_size))
    pool+=struct.pack('<IIIII',len(names),0,0x100,start,0)
    pool+=b''.join(struct.pack('<I',o) for o in offsets)
    pool+=string_payload
    def start_el(name, attrs):
        ext=struct.pack('<IIHHHHHH',0xffffffff,n[name],20,20,len(attrs),0,0,0)
        for ans,k,v in attrs:
            ext+=struct.pack('<IIIHBBI',n[ans] if ans else 0xffffffff,n[k],n[v],8,0,3,n[v])
        return struct.pack('<HHI',0x102,16,16+len(ext))+struct.pack('<II',0,0xffffffff)+ext
    def end_el(name):
        return struct.pack('<HHI',0x103,16,24)+struct.pack('<II',0,0xffffffff)+struct.pack('<II',0xffffffff,n[name])
    chunks=[bytes(pool),start_el('manifest',[(None,'package','com.test.binary')]),
            start_el('uses-permission',[('http://schemas.android.com/apk/res/android','name','android.permission.CAMERA')]),
            end_el('uses-permission'),start_el('application',[]),end_el('application'),end_el('manifest')]
    inner=b''.join(chunks)
    return struct.pack('<HHI',3,8,8+len(inner))+inner

class TestBinaryXml(unittest.TestCase):
    def test_decode_binary_axml(self):
        meta,permissions,components=inspect_manifest(synthetic_binary_manifest())
        self.assertEqual(meta['package'],'com.test.binary')
        self.assertEqual(permissions,['android.permission.CAMERA'])
        self.assertEqual(components,[])
