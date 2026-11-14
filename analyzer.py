"""SPECTRA APK Static Analyzer - offline, read-only, evidence-based review.

This is NOT a malware verdict engine. It never runs analyzed APKs and never contacts
remote services. Individual signatures are hypotheses for analyst validation.
"""
from __future__ import annotations
import hashlib, io, ipaddress, json, re, struct, zipfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import PurePosixPath
from xml.etree import ElementTree as ET

MAX_ENTRIES=15000
MAX_UNCOMPRESSED=350*1024*1024
MAX_SINGLE=55*1024*1024
MAX_DEX=12
A_NS='{http://schemas.android.com/apk/res/android}'

class APKError(Exception):
    pass

def read_u16(b, offset):
    return struct.unpack_from('<H', b, offset)[0]
def read_u32(b, offset):
    return struct.unpack_from('<I', b, offset)[0]
def read_uleb(data, pos):
    value=0
    for i in range(5):
        if pos>=len(data): raise ValueError('Truncated uleb128')
        v=data[pos];pos+=1
        value|=(v&0x7f)<<(7*i)
        if v<0x80:return value,pos
    raise ValueError('Invalid uleb128')

def parse_dex(data, location):
    """Read DEX string and method-reference tables (no code execution)."""
    if len(data)<112 or data[:4]!=b'dex\n':
        return {'strings':[], 'methods':[], 'warnings':[f'{location}: unsupported or invalid DEX header']}
    try:
        ss,so=read_u32(data,0x38),read_u32(data,0x3c)
        ts,to=read_u32(data,0x40),read_u32(data,0x44)
        ms,mo=read_u32(data,0x58),read_u32(data,0x5c)
        if ss>2000000 or ts>200000 or ms>1000000: raise ValueError('Excessive DEX table entries')
        if so+ss*4>len(data) or to+ts*4>len(data) or mo+ms*8>len(data): raise ValueError('DEX table outside file')
        strings=[]
        for i in range(ss):
            off=read_u32(data,so+4*i)
            if off>=len(data): strings.append('');continue
            _,p=read_uleb(data,off)
            end=data.find(b'\x00',p,min(len(data),p+4096))
            if end<0: end=min(len(data),p+4096)
            strings.append(data[p:end].decode('utf-8','replace'))
        types=[]
        for i in range(ts):
            ix=read_u32(data,to+4*i)
            types.append(strings[ix] if ix<len(strings) else '')
        methods=[]
        for i in range(ms):
            ci,_,ni=struct.unpack_from('<HHI',data,mo+i*8)
            if ci<len(types) and ni<len(strings):methods.append(types[ci]+'->'+strings[ni])
        return {'strings':strings,'methods':methods,'warnings':[]}
    except (ValueError,struct.error,OverflowError) as exc:
        return {'strings':[],'methods':[],'warnings':[f'{location}: DEX parser: {str(exc)[:120]}']}

# Compact Android binary XML (AXML) reader, used when androguard isn't installed.
def decode_axml(blob):
    if blob.lstrip().startswith(b'<'):
        return ET.fromstring(blob)
    if len(blob)<8 or read_u16(blob,0)!=3:raise ValueError('Unsupported AndroidManifest binary XML')
    # Android RES_XML_TYPE=0x0003; RES_STRING_POOL_TYPE=0x0001
    root=ET.Element('manifest'); stack=[]; strings=[]; p=8
    def u8len(buf, at):
        a=buf[at]; at+=1
        if a&0x80: a=((a&0x7f)<<8)|buf[at];at+=1
        return a,at
    def u16len(buf,at):
        a=read_u16(buf,at);at+=2
        if a&0x8000: a=((a&0x7fff)<<16)|read_u16(buf,at);at+=2
        return a,at
    def str_at(idx):
        return strings[idx] if 0<=idx<len(strings) else ''
    while p+8<=len(blob):
        ct,hs,sz=struct.unpack_from('<HHI',blob,p)
        if sz<8 or p+sz>len(blob):raise ValueError('Invalid binary XML chunk')
        if ct==0x0001:
            if p+28>len(blob): raise ValueError('Invalid string pool')
            cnt=read_u32(blob,p+8); flags=read_u32(blob,p+16); soff=read_u32(blob,p+20)
            if cnt>300000 or hs+cnt*4>sz:raise ValueError('Oversized string pool')
            for n in range(cnt):
                off=read_u32(blob,p+hs+n*4); v=p+soff+off
                if v>=p+sz: strings.append('');continue
                if flags&0x100:
                    _,v=u8len(blob,v);bytelen,v=u8len(blob,v)
                    strings.append(blob[v:min(v+bytelen,p+sz)].decode('utf-8','replace'))
                else:
                    strlen,v=u16len(blob,v)
                    strings.append(blob[v:min(v+strlen*2,p+sz)].decode('utf-16le','replace'))
        elif ct==0x0102: # START_ELEMENT (ResXMLTree_attrExt)
            if p+36>len(blob):raise ValueError('Truncated element')
            ns,name,attr_start,attr_size,attr_count=struct.unpack_from('<IIHHH',blob,p+16)
            name=str_at(name)
            if not name: name='unknown'
            node=ET.Element(name)
            # attributeStart relative to start of attrExt (p+16)
            attrp=p+16+attr_start
            if attr_size<20 or attr_count>5000 or attrp+attr_count*attr_size>p+sz:raise ValueError('Invalid attributes')
            for n in range(attr_count):
                ap=attrp+n*attr_size
                an,ak,raw=struct.unpack_from('<III',blob,ap)
                dtype=blob[ap+15]
                val=read_u32(blob,ap+16)
                key=str_at(ak)
                if not key:continue
                if an!=0xffffffff:
                    namespace=str_at(an)
                    if namespace: key='{'+namespace+'}'+key
                if raw!=0xffffffff: v=str_at(raw)
                elif dtype==3:v=str_at(val)
                elif dtype==18:v='true' if val else 'false'
                elif dtype in (16,17):v=str(val)
                elif dtype==1:v='@0x%08x'%val
                else:v='0x%08x'%val
                node.set(key,v)
            if stack:stack[-1].append(node)
            else:root=node
            stack.append(node)
        elif ct==0x0103 and stack:stack.pop()
        p+=sz
    if root.tag!='manifest':raise ValueError('Could not parse AndroidManifest.xml')
    return root

def get_attr(node,key,default=''):
    return node.attrib.get(A_NS+key,node.attrib.get(key,default))

def inspect_manifest(blob):
    root=decode_axml(blob)
    app=root.find('application')
    permissions=sorted(set(get_attr(n,'name') for n in root if n.tag.startswith('uses-permission') and get_attr(n,'name')))
    components=[]
    if app is not None:
        for node in app:
            if node.tag not in ('service','receiver','provider','activity','activity-alias'):continue
            intents=[]
            for it in node.findall('intent-filter'):
                for ch in it:
                    if ch.tag in ('action','category'):intents.append(get_attr(ch,'name'))
            components.append({'kind':node.tag,'name':get_attr(node,'name'),'permission':get_attr(node,'permission'),
                               'exported':get_attr(node,'exported','unspecified'),'actions':intents[:100]})
    meta={'package':get_attr(root,'package'),'version_name':get_attr(root,'versionName'),
          'version_code':get_attr(root,'versionCode'),
          'min_sdk':get_attr(root.find('uses-sdk'),'minSdkVersion') if root.find('uses-sdk') is not None else '',
          'target_sdk':get_attr(root.find('uses-sdk'),'targetSdkVersion') if root.find('uses-sdk') is not None else '',
          'debuggable':get_attr(app,'debuggable') if app is not None else '',
          'uses_cleartext':get_attr(app,'usesCleartextTraffic') if app is not None else '',
          'allow_backup':get_attr(app,'allowBackup') if app is not None else ''}
    return meta,permissions,components

RULES = [
# key, label, severity, permission regex, method ref regex, string literal regex, component regex, interpretation
('camera','Camera access / capture','high',r'\bCAMERA$',r'(CameraManager;->openCamera|Camera;->open|CameraDevice;->createCaptureSession|ImageReader;->newInstance|CameraCaptureSession;->capture)',r'(android\.hardware\.camera|Landroid/hardware/Camera;|camera2/CameraDevice)', '', 'Camera-related capability detected; recording is NOT confirmed.'),
('microphone','Microphone / audio recording','high',r'\bRECORD_AUDIO$',r'(MediaRecorder;->start|AudioRecord;->startRecording|SpeechRecognizer;->startListening)',r'(MediaRecorder|AudioRecord|RECORD_AUDIO)', '', 'Audio recording capabilities may have legitimate uses.'),
('accessibility','Accessibility-based text/screen access','high',r'BIND_ACCESSIBILITY_SERVICE$',r'(AccessibilityService;->|AccessibilityEvent;->getText|AccessibilityNodeInfo;->getText|AccessibilityNodeInfo;->getChild)',r'(TYPE_VIEW_TEXT_CHANGED|AccessibilityService|canRetrieveWindowContent)',r'android\.accessibilityservice\.AccessibilityService|BIND_ACCESSIBILITY_SERVICE','Accessibility services may inspect UI; this does not prove a keylogger.'),
('keyboard','Keyboard / input-method service','high',r'BIND_INPUT_METHOD$',r'(InputMethodService;->|InputConnection;->getExtractedText|InputConnection;->getTextBeforeCursor)',r'(InputMethodService|android\.view\.InputMethod|onKeyDown)',r'InputMethodService|BIND_INPUT_METHOD','Keyboard input handling may be normal for a legitimate keyboard app.'),
('screencapture','Screen capture / media projection','high',r'CAPTURE_VIDEO_OUTPUT$|READ_MEDIA_IMAGES$',r'(MediaProjectionManager;->createScreenCaptureIntent|MediaProjection;->createVirtualDisplay|ImageReader;->acquireLatestImage)',r'(MediaProjection|createVirtualDisplay|screencap)',r'mediaProjection','Possible screen capture capability, not proof of activation.'),
('overlay','Overlay / tapjacking potential','medium',r'SYSTEM_ALERT_WINDOW$',r'(WindowManager;->addView|Settings;->canDrawOverlays)',r'(TYPE_APPLICATION_OVERLAY|SYSTEM_ALERT_WINDOW)', '', 'Overlay capabilities may be abused to mislead users.'),
('notifications','Notification content access','medium',r'BIND_NOTIFICATION_LISTENER_SERVICE$',r'(NotificationListenerService;->onNotificationPosted|StatusBarNotification;->getNotification)',r'NotificationListenerService',r'NotificationListenerService|BIND_NOTIFICATION_LISTENER_SERVICE','Notification listener can expose message content, depending on privileges.'),
('sms','SMS / call-related access','high',r'(READ_SMS|RECEIVE_SMS|SEND_SMS|READ_CALL_LOG|READ_PHONE_STATE)$',r'(SmsManager;->sendTextMessage|TelephonyManager;->getLine1Number|SmsMessage;->createFromPdu)',r'(content://sms|content://call_log)', '', 'Messaging or call access warrants purpose review.'),
('contacts','Contacts / account collection','medium',r'(READ_CONTACTS|GET_ACCOUNTS)$',r'(ContactsContract|ContentResolver;->query)',r'(ContactsContract|content://com.android.contacts)', '', 'May access personal contacts or accounts.'),
('location','Location tracking','medium',r'(ACCESS_FINE_LOCATION|ACCESS_COARSE_LOCATION|ACCESS_BACKGROUND_LOCATION)$',r'(FusedLocationProviderClient;->|LocationManager;->requestLocationUpdates|Location;->getLatitude)',r'(ACCESS_BACKGROUND_LOCATION|requestLocationUpdates)', '', 'Location permissions/APIs detected; no actual tracking confirmed.'),
('storage','Files and storage access','medium',r'(READ_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE|MANAGE_EXTERNAL_STORAGE|READ_MEDIA_.*)$',r'(FileInputStream;->|ContentResolver;->openInputStream|Environment;->getExternalStorageDirectory)',r'(MANAGE_EXTERNAL_STORAGE|DocumentsContract|READ_MEDIA_IMAGES)', '', 'File access can support ordinary app features or collection.'),
('network','Network / remote communication','info',r'INTERNET$',r'(HttpURLConnection;->|OkHttpClient;->newCall|Socket;->connect|URLConnection;->connect|WebView;->loadUrl|Retrofit;->)',r'(https?://|wss?://)', '', 'Network access alone is not malicious.'),
('upload','File upload / outbound transfer methods','medium','',r'(MultipartBody|RequestBody;->create|OutputStream;->write|HttpURLConnection;->setDoOutput|FTPClient;->storeFile|FilePart)',r'(multipart/form-data|Content-Disposition: form-data|/upload|uploadFile|exfiltrat)', '', 'Upload/write APIs need tracing to confirm what data is sent and where.'),
('persistence','Boot, scheduling / persistent work','medium',r'RECEIVE_BOOT_COMPLETED$|FOREGROUND_SERVICE$',r'(AlarmManager;->setRepeating|JobScheduler;->schedule|WorkManager;->enqueue|Context;->startForegroundService)',r'(BOOT_COMPLETED|START_STICKY|PeriodicWorkRequest)',r'BOOT_COMPLETED|JobService','Periodic/background behavior can be benign or concerning.'),
('dynamic','Dynamic code / reflection / native libraries','medium','',r'(DexClassLoader;->|PathClassLoader;->|Class;->forName|System;->loadLibrary|Runtime;->exec)',r'(DexClassLoader|loadDex|System\.loadLibrary|Runtime\.getRuntime)', '', 'Dynamic loading or native code can limit coverage of static inspection.'),
('device_admin','Device administration / elevated control','high',r'BIND_DEVICE_ADMIN$|REQUEST_INSTALL_PACKAGES$',r'(DevicePolicyManager;->lockNow|DevicePolicyManager;->wipeData|PackageInstaller;->)',r'(DEVICE_ADMIN_ENABLED|DeviceAdminReceiver)',r'BIND_DEVICE_ADMIN|DeviceAdminReceiver','Device administration deserves inspection of the user consent flow.'),
('clipboard','Clipboard monitoring','medium','',r'(ClipboardManager;->getPrimaryClip|ClipboardManager;->addPrimaryClipChangedListener)',r'(OnPrimaryClipChangedListener|getPrimaryClip)', '', 'Clipboard APIs may reveal sensitive copied data.'),
('anti_analysis','Anti-analysis / environment checks','medium','',r'(Debug;->isDebuggerConnected|Build;->FINGERPRINT|PackageManager;->getInstalledPackages)',r'(frida|magisk|xposed|test-keys|isEmulator|isRooted|su -c)', '', 'Potential anti-analysis strings are noisy; manually validate.'),
]

PERMISSION_SEVERITY={'CAMERA':'high','RECORD_AUDIO':'high','BIND_ACCESSIBILITY_SERVICE':'high','BIND_INPUT_METHOD':'high',
 'READ_SMS':'high','READ_CALL_LOG':'high','MANAGE_EXTERNAL_STORAGE':'high','ACCESS_BACKGROUND_LOCATION':'high',
 'SYSTEM_ALERT_WINDOW':'medium','RECEIVE_BOOT_COMPLETED':'medium','READ_CONTACTS':'medium'}

URI_RE=re.compile(r'(?i)\b(?:https?|wss?)://[^\s\x00\"\'<>\\]{4,250}')
IP_RE=re.compile(r'(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])')
HOST_RE=re.compile(r'(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|xyz|top|info|dev|app|me|cloud|site|online|co|ai|biz|uk|sa|de|us|tk|pw)\b')
IGNORE_HOSTS={'schemas.android.com','www.w3.org','developer.android.com','android.com','example.com','example.org',
 'localhost','www.google.com','google.com','firebase.google.com','github.com','www.github.com','maven.google.com'}

def extract_indicators(strings,methods):
    vals=defaultdict(lambda:{'sources':set(),'kinds':set()})
    for src,s in strings:
        # Ignore high frequency noise and compiler class metadata.
        if len(s)>5000:continue
        for m in URI_RE.finditer(s):
            url=m.group(0).rstrip(').,;]')
            host=re.sub(r'^.*?://','',url).split('/')[0].split(':')[0].lower()
            if host and host not in IGNORE_HOSTS and len(host)<180:
                d=vals[host];d['sources'].add(src);d['kinds'].add('URL host')
        # Only extract DNS candidates from resource and DEX literal strings, not method signatures.
        if s.startswith('L') and ';->' in s:continue
        for host in HOST_RE.findall(s):
            host=host.lower()
            if host in IGNORE_HOSTS or host.endswith('.android.com'):continue
            if host.count('.')>6:continue
            d=vals[host];d['sources'].add(src);d['kinds'].add('Domain candidate')
        for cand in IP_RE.findall(s):
            try:
                addr=ipaddress.ip_address(cand)
                # suppress all local/reserved hosts in outbound indicator view
                if not addr.is_global:continue
                d=vals[cand];d['sources'].add(src);d['kinds'].add('Public IP candidate')
            except ValueError:pass
    result=[{'value':host,'kind':', '.join(sorted(d['kinds'])),'source':sorted(d['sources'])[:4]}
            for host,d in vals.items()]
    return sorted(result,key=lambda x:x['value'])[:150]

def analyze_apk(data,filename='uploaded.apk'):
    if len(data)>120*1024*1024:raise APKError('APK exceeds 120 MB upload limit')
    if not zipfile.is_zipfile(io.BytesIO(data)):raise APKError('Not a valid ZIP-based APK')
    sha=hashlib.sha256(data).hexdigest()
    result={'tool':'SPECTRA APK Threat Analyzer','analysis_type':'Offline static inspection only',
        'filename':filename,'sha256':sha,'size_bytes':len(data),
        'scan_utc':datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'metadata':{},'permissions':[],'components':[],'files':[],'findings':[], 'indicators':[],
        'warnings':[],'coverage':{'manifest':'not processed','dex_files':0,'dex_strings':0,'dex_method_refs':0,
                                  'native_libraries':0,'potential_obfuscation':False},
        'assessment':{'review_score':0,'priority':'Low','label':'Static triage only — not a malware verdict'}}
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        infos=z.infolist()
        if len(infos)>MAX_ENTRIES:raise APKError('APK has excessive number of ZIP entries')
        if sum(i.file_size for i in infos)>MAX_UNCOMPRESSED:raise APKError('APK expanded size exceeds safety limit')
        seen=set()
        for i in infos:
            if i.file_size>MAX_SINGLE and (i.filename=='AndroidManifest.xml' or i.filename.endswith('.dex')):
                raise APKError('Manifest or DEX entry exceeds safety limit')
            if i.filename in seen:result['warnings'].append('Duplicate ZIP entry: '+i.filename[:120])
            seen.add(i.filename)
            result['files'].append({'path':i.filename,'size_bytes':i.file_size,'compressed_bytes':i.compress_size})
        if 'AndroidManifest.xml' not in seen:
            result['warnings'].append('AndroidManifest.xml missing; likely not a standard APK')
        else:
            try:
                manifest=z.read('AndroidManifest.xml')
                meta,perms,comps=inspect_manifest(manifest)
                result['metadata']=meta;result['permissions']=perms;result['components']=comps
                result['coverage']['manifest']='parsed'
            except Exception as ex:
                result['coverage']['manifest']='failed'
                result['warnings'].append('Manifest decoding failed: '+str(ex)[:180])
        dnames=sorted((n for n in seen if re.fullmatch(r'classes(?:\d+)?\.dex',n)))
        if not dnames:result['warnings'].append('No classes.dex found; code scan incomplete')
        if len(dnames)>MAX_DEX:
            result['warnings'].append(f'{len(dnames)} DEX files present; inspected first {MAX_DEX}')
        dnames=dnames[:MAX_DEX]
        strings=[];methods=[]
        for name in dnames:
            try:
                out=parse_dex(z.read(name),name)
                result['warnings']+=out['warnings']
                strings.extend((f'{name}:string[{ix}]',s) for ix,s in enumerate(out['strings']))
                methods.extend((f'{name}:method_ref[{ix}]',s) for ix,s in enumerate(out['methods']))
                result['coverage']['dex_files']+=int(not out['warnings'])
            except Exception as ex:
                result['warnings'].append(f'{name}: cannot read DEX: {str(ex)[:120]}')
        result['coverage']['dex_strings']=len(strings)
        result['coverage']['dex_method_refs']=len(methods)
        nlibs=[n for n in seen if n.endswith('.so')]
        result['coverage']['native_libraries']=len(nlibs)
        if nlibs:result['warnings'].append('Native .so code is not disassembled by the built-in engine')
        if dnames and result['coverage']['dex_files']<len(dnames):
            result['warnings'].append('Some DEX parsing failed; negative findings are not reliable')
        if result['coverage']['dex_files']==0:
            result['warnings'].append('No valid DEX parsed; code-level detection unavailable')
        # Additional configuration/asset IOC strings: bounded, textual resources only.
        extra=[]
        for name in sorted(seen):
            if name.startswith('META-INF/') or name.endswith('.dex'):continue
            if (name.endswith(('.txt','.json','.properties','.js','.html','.xml','.cfg','.ini'))
                and name!='AndroidManifest.xml'):
                try:
                    info=z.getinfo(name)
                    if info.file_size>200*1024:continue
                    raw=z.read(name)
                    if b'\x00' in raw[:100]:continue
                    content=raw[:200*1024].decode('utf-8','replace')
                    for line in content.splitlines()[:350]:
                        if URI_RE.search(line) or HOST_RE.search(line):
                            extra.append((f'asset:{name}',line[:1000]))
                except Exception:pass
        # Avoid unbounded analysis of stored secrets/strings.
        result['indicators']=extract_indicators(strings+extra,methods)
        permission_items=[('manifest:uses-permission',p) for p in result['permissions']]
        component_items=[]
        for c in result['components']:
            comp='manifest:'+c['kind']+':'+c['name']
            component_items += [(comp,v) for v in [c['name'],c['permission']]+c['actions'] if v]
        patterns_compiled=[(key,title,severity,re.compile(p,re.I) if p else None,
           re.compile(m,re.I) if m else None,re.compile(s,re.I) if s else None,
           re.compile(c,re.I) if c else None,interpretation)
           for key,title,severity,p,m,s,c,interpretation in RULES]
        def hits(items,rx,limit=7):
            if rx is None:return []
            out=[]
            for source,value in items:
                if rx.search(value):
                    out.append({'source':source,'match':value[:200]})
                    if len(out)>=limit:break
            return out
        detections={}
        for key,title,severity,pr,mr,sr,cr,interpretation in patterns_compiled:
            ph=hits(permission_items,pr)
            mh=hits(methods,mr)
            sh=hits(strings,sr)
            ch=hits(component_items,cr)
            if not (ph or mh or sh or ch):continue
            types=[k for k,group in [('Manifest permission',ph),('DEX method reference',mh),('DEX string',sh),('Manifest component',ch)] if group]
            # Capability signals, never assert spying occurred.
            confidence='Elevated' if (mh and (ph or ch)) or (ch and ph) else ('Moderate' if mh or ch or ph else 'Low')
            result['findings'].append({'id':key,'title':title,'severity':severity,'confidence':confidence,
              'evidence_types':types,'evidence':(ph+ch+mh+sh)[:12],'assessment':interpretation,
              'status':'Potential capability / pattern, not confirmed runtime behavior'})
            detections[key]=True
        if nlibs:
            result['findings'].append({'id':'native','title':'Bundled native binaries',
               'severity':'info','confidence':'Elevated','evidence_types':['APK file listing'],
               'evidence':[{'source':'apk:file','match':n} for n in nlibs[:7]],
               'assessment':'Native libraries need dedicated reverse engineering for full coverage.',
               'status':'Static package content'})
        if result['metadata'].get('debuggable')=='true':
            result['findings'].append({'id':'debug','title':'Debuggable application','severity':'medium',
              'confidence':'Elevated','evidence_types':['Manifest attribute'],
              'evidence':[{'source':'manifest:application','match':'android:debuggable=true'}],
              'assessment':'Debuggable build increases exposure when deployed to end users.',
              'status':'Manifest configuration'})
        if result['metadata'].get('uses_cleartext')=='true':
            result['findings'].append({'id':'cleartext','title':'Cleartext traffic permitted','severity':'medium',
              'confidence':'Elevated','evidence_types':['Manifest attribute'],
              'evidence':[{'source':'manifest:application','match':'android:usesCleartextTraffic=true'}],
              'assessment':'Some network traffic may be unencrypted; not proof of use.',
              'status':'Manifest configuration'})
        # Correlations do not assert command-and-control / exfiltration occurred.
        def correlate(key,title,why,required,sev='high'):
            if not all(detections.get(k) for k in required):return
            linked=[]
            for f in result['findings']:
                if f['id'] in required: linked += f['evidence'][:2]
            result['findings'].insert(0,{'id':key,'title':title,'severity':sev,'confidence':'Moderate',
               'evidence_types':['Cross-category correlation'], 'evidence':linked[:8],
               'assessment':why,'status':'Suspicious combination; confirm data flow with code review and isolated dynamic analysis'})
        correlate('possible_keylogging','Possible input-data collection + outbound capability',
                  'Accessibility/keyboard capabilities and outbound transfer indications coexist. This is NOT confirmed keylogging.',
                  ['accessibility','upload'])
        correlate('possible_exfil','Possible sensitive-data collection + outbound capability',
                  'Sensitive data access and upload-related methods coexist. Trace call sites to establish actual exfiltration.',
                  ['storage','upload'])
        correlate('possible_c2','Possible remote coordination indicators',
                  'Remote communication and background scheduling are present. This is not verified C2 infrastructure.',
                  ['network','persistence'],'medium')
        correlate('possible_camera_exfil','Possible camera capture + outbound transfer',
                  'Camera-related APIs and upload-related references coexist. No camera capture or upload is proven.',
                  ['camera','upload'])
        score=0
        weights={'high':14,'medium':6,'info':0}
        for f in result['findings']:
            w=weights[f['severity']]
            if f['confidence']=='Low':w//=2
            score+=w
        score=min(100,score)
        result['assessment']['review_score']=score
        result['assessment']['priority']='High' if score>=55 else 'Medium' if score>=20 else 'Low'
        result['assessment']['meaning']='Heuristic review priority, NOT probability of malware or a detection verdict.'
        result['coverage']['static_only']=True
        result['coverage']['runtime_behavior_observed']=False
        result['coverage']['network_traffic_observed']=False
        result['coverage']['data_exfiltration_confirmed']=False
        return result
