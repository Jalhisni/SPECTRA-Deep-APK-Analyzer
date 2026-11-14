"""SPECTRA deep static APK scan. Untrusted packages never executed, endpoints never contacted.
Supported encrypted shard format is narrow/format-specific; scan reports limitations.
"""
from __future__ import annotations
import hashlib, io, json, re, struct, zipfile, gzip
from collections import defaultdict
from analyzer import analyze_apk, parse_dex, APKError

MAX_STAGE=120*1024*1024
MAX_FILES=5000
MAX_STAGES=3
KEYWORDS={
  'Keylogging':['KEYLOGGER_START','KEYLOGGER_STOP','KEYLOG_DUMP','KEYLOG_FETCH','KEYLOG_START','KEYLOG_CLEAR','KeylogModule','KeylogCapture'],
  'Camera surveillance':['CAMERA_START','CAMERA_STOP','CAMERA_SWITCH','TAKE_PHOTO','CAMERA_CAPTURE','CameraModule'],
  'Microphone surveillance':['MICROPHONE_START_RECORDING','MICROPHONE_STOP_RECORDING','AUDIO_RECORD_START','MicrophoneModule'],
  'Screen monitoring':['SCREEN_CAPTURE','SCREEN_CAPTURE_START','SCREEN_CAPTURE_STOP','SCREEN_STREAM','SCREENSHOT_TAKE'],
  'File operations / upload':['FILE_UPLOAD','FILE_DOWNLOAD','FILE_LIST','ACT_UPLOAD','cmdUpload','DataUploader'],
  'SMS / contacts access':['SMS_SEND','SMS_READ','SMS_FETCH','SMS_SYNC','CONTACTS_FETCH','SmsModule','ContactsModule'],
  'Credential collection':['CredentialCapture','CredentialPromptActivity','CREDENTIAL_CAPTURE','PASSWORD_CAPTURE'],
  'Remote command interface':['COMMAND_EXEC','SHELL_EXEC','CMD_EXEC','REMOTE_COMMAND','REMOTE_SHELL','COMMAND_DISPATCH'],
  'Device / persistence':['DEVICE_ADMIN','BOOT_COMPLETED','PlatformAssistDaemon','DISABLE_PLAY_PROTECT']
}
WATCH_URL_KEYS={'serverurl','reporturl','baseurl','apiurl','endpoint','socketurl','websocketurl','host','server','c2url'}
WATCH_KEYS={'showappicon','enabledeviceadmin','enablecamera','enablemicrophone','enableallfilesaccess','enablesms','enablecontacts','enablegallery','enablestorage','enableplayprotect'}


def safe_zip(blob):
    if len(blob)>MAX_STAGE: raise APKError('Nested payload exceeds safety limit')
    if not zipfile.is_zipfile(io.BytesIO(blob)):raise APKError('Not ZIP-based payload')
    z=zipfile.ZipFile(io.BytesIO(blob))
    infos=z.infolist()
    if len(infos)>MAX_FILES and 'AndroidManifest.xml' not in z.namelist():
        z.close();raise APKError('Excessive nested entries')
    if sum(x.file_size for x in infos)>350*1024*1024:
        z.close();raise APKError('Nested APK expanded size over safe limit')
    return z


def discover_nested(blob):
    """Find stored APKs and supported encrypted-shard format, without running or importing app code."""
    output=[];messages=[]
    with safe_zip(blob) as z:
        inf={i.filename:i for i in z.infolist()}
        # Plain nested APKs / gzip embedded APKs. No recursive arbitrary decompression.
        for name,i in sorted(inf.items(),key=lambda t:-t[1].file_size):
            if len(output)>=2:break
            if i.file_size<256 and not name.endswith('.apk'):continue
            if i.file_size>MAX_STAGE:continue
            if name.endswith('.apk') or (i.file_size<35*1024*1024 and name.startswith('assets/')):
                try:
                    raw=z.read(name)
                    if zipfile.is_zipfile(io.BytesIO(raw)):
                        with zipfile.ZipFile(io.BytesIO(raw)) as inner:
                            if 'AndroidManifest.xml' in inner.namelist():output.append((raw,'Embedded APK at '+name))
                    elif raw[:2]==b'\x1f\x8b' and len(raw)<25*1024*1024:
                        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as dec:
                            out=dec.read(MAX_STAGE+1)
                        if len(out)<=MAX_STAGE and zipfile.is_zipfile(io.BytesIO(out)):
                            output.append((out,'GZIP embedded APK at '+name))
                except (ValueError,OSError,EOFError,zipfile.BadZipFile):pass
        if output:return output,messages
        # Supported AES-GCM sharded loader: header (23 salt/random, 4 index, 12 nonce,
        # 4 ciphertext length), authentication tag; the native loader holds XOR-masked key.
        # Detection is structural and cryptographically authenticated, not hash-based report substitution.
        shards=[]
        for name,i in inf.items():
            if not name.startswith('assets/') or i.file_size<250*1024 or i.file_size>25*1024*1024:continue
            if name.count('/')!=1:continue
            try:
                data=z.read(name)
                if len(data)<59:continue
                index=struct.unpack_from('>I',data,23)[0]
                sz=struct.unpack_from('>I',data,39)[0]
                if index in range(1,16) and sz==len(data)-43 and 12<=sz<=25*1024*1024:
                    shards.append((index,name,data))
            except (ValueError,IndexError,struct.error):continue
        if not (2<=len(shards)<=10):
            if any(i.file_size>1_000_000 and i.filename.startswith('assets/') for i in inf.values()):
                messages.append('Large embedded assets exist; unsupported encryption or packing may hide payloads.')
            return [],messages
        shards.sort()
        if [i for i,_,_ in shards]!=list(range(1,len(shards)+1)):
            return [],['Detected possible sharded assets, but shard sequence is incomplete.']
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            return [],['Encrypted-shard loader detected; optional cryptography dependency is missing. Run INSTALL.bat.']
        # For supported loader family, native ARM64 data block holds the masked AES key.
        # Limit to a small fixed structural search window and verify via GCM authentication.
        libs=[n for n in inf if n.startswith('lib/arm64-v8a/') and n.endswith('.so') and inf[n].file_size<8*1024*1024]
        for lib in libs[:8]:
            elf=z.read(lib)
            if not elf.startswith(b'\x7fELF'):continue
            for offset in [0x540]:
                if offset+0x50>len(elf):continue
                mask=elf[offset:offset+32];markxor=elf[offset+32:offset+48];keyxor=elf[offset+48:offset+80]
                key=bytes(x^y for x,y in zip(keyxor,mask));mark=bytes(x^y for x,y in zip(markxor,mask[:16]))
                try:
                    stream=[]
                    for index,name,buf in shards:
                        nonce=buf[27:39]
                        aad=mark+struct.pack('>II',index,0)
                        plaintext=AESGCM(key).decrypt(nonce,buf[43:],aad)
                        stream.append(plaintext)
                    cat=b''.join(stream)
                    with gzip.GzipFile(fileobj=io.BytesIO(cat)) as g:
                        payload=g.read(MAX_STAGE+1)
                    if len(payload)>MAX_STAGE:raise ValueError('payload size exceeded')
                    with safe_zip(payload) as pz:
                        if 'AndroidManifest.xml' not in pz.namelist():continue
                    output.append((payload,'Authenticated AES-GCM shard extraction: '+', '.join(n for _,n,_ in shards)))
                    messages.append('Supported sharded loader decoded offline; this method will not unpack arbitrary encrypted malware.')
                    return output,messages
                except Exception:
                    # A failed cryptographic authentication simply means this loader key layout does not match.
                    continue
        messages.append('Possible encrypted-shard payload found, but no supported authenticated decoder succeeded.')
    return [],messages


def stage_evidence(blob,stage_num):
    result={'commands':[],'config':[],'code_references':[],'text_evidence':[],'iocs':[]}
    with safe_zip(blob) as z:
        names=set(z.namelist())
        refs=[];matched=defaultdict(list)
        for name in sorted(n for n in names if re.fullmatch(r'classes(?:\d+)?\.dex',n))[:12]:
            d=parse_dex(z.read(name),name)
            for ix,s in enumerate(d['strings']):
                if len(s)>280:continue
                su=s.upper()
                for category,keywords in KEYWORDS.items():
                    if any(su==k.upper() for k in keywords):
                        matched[(category,s)].append(f'{name}:string[{ix}]')
            for ix,s in enumerate(d['methods']):
                # Exact method reference is the closest built-in equivalent to a code snippet.
                if re.search(r'(Camera|Keylog|Microphone|ScreenCapture|Accessibility|PackageInstaller|DexClassLoader|upload|sendToServer|HttpURLConnection|MediaProjection|SmsModule|CredentialCapture|doInstall|shard|assemble|Cipher;->doFinal|addJavascriptInterface)',s,re.I):
                    refs.append({'stage':stage_num,'file':name,'method':s[:220],'ref_index':ix})
        result['commands']=[{'stage':stage_num,'category':k[0],'value':k[1],'source':list(dict.fromkeys(v))[:3]}
                            for k,v in sorted(matched.items())][:220]
        result['code_references']=refs[:260]
        for name in names:
            if not name.lower().endswith(('.json','.html','.properties','.txt','.cfg')):continue
            try:
                info=z.getinfo(name)
                if info.file_size>350_000 or info.file_size==0:continue
                raw=z.read(name)
                if b'\x00' in raw[:200]:continue
                content=raw.decode('utf-8','replace')
                if name.lower().endswith('.json'):
                    try:
                        obj=json.loads(content)
                        # Extract only simple relevant settings (not credentials/tokens).
                        def visit(value,path='',depth=0):
                            if depth>4:return
                            if isinstance(value,dict):
                                for k,v in list(value.items())[:150]:visit(v,k,depth+1)
                            elif isinstance(value,(bool,int,float,str)):
                                key=path.lower().replace('_','')
                                if key in WATCH_KEYS or key in WATCH_URL_KEYS:
                                    if isinstance(value,str):value=value[:180]
                                    result['config'].append({'stage':stage_num,'source':name,'key':path,'value':value})
                        visit(obj)
                    except (json.JSONDecodeError,UnicodeError):pass
                if name.endswith(('.html','.txt','.properties')):
                    for ix,line in enumerate(content.splitlines()):
                        if re.search(r'(addJavascriptInterface|doInstall|Google Play|Accessibility|PackageInstaller|install|update)',line,re.I):
                            result['text_evidence'].append({'stage':stage_num,'file':name,'line':ix+1,'snippet':line.strip()[:300]})
                            if len(result['text_evidence'])>=35:break
            except (UnicodeError,KeyError,zipfile.BadZipFile):continue
        result['config']=result['config'][:100]
        result['text_evidence']=result['text_evidence'][:45]
    return result


def deep_analyze(data,filename):
    top=analyze_apk(data,filename)
    top['engine_version']='4.0'
    top['stages']=[]
    top['command_indicators']=[]
    top['code_references']=[]
    top['text_evidence']=[]
    top['settings_evidence']=[]
    top['loader_notes']=[]
    top['assessment']['meaning']='Static heuristic triage across stages; not probability of maliciousness.'
    seen=set();payload=data
    for stage in range(1,MAX_STAGES+1):
        sha=hashlib.sha256(payload).hexdigest()
        if sha in seen:break
        seen.add(sha)
        scan=top if stage==1 else analyze_apk(payload,f'stage-{stage}.apk')
        if stage>1:
            for finding in scan['findings']:
                finding['stage']=stage
            top['findings']+=scan['findings']
            for ind in scan['indicators']:
                ind['stage']=stage
                top['indicators'].append(ind)
            top['warnings']+=['Stage '+str(stage)+': '+w for w in scan['warnings']]
        else:
            for finding in top['findings']:finding['stage']=1
            for ind in top['indicators']:ind['stage']=1
        top['stages'].append({'stage':stage,'sha256':sha,'size_bytes':len(payload),'metadata':scan['metadata'],
                              'permissions':scan['permissions'],'components':scan['components'],
                              'dex_files':scan['coverage']['dex_files'],'dex_strings':scan['coverage']['dex_strings'],
                              'method_references':scan['coverage']['dex_method_refs'],'file_count':len(scan['files']),
                              'risk_priority':scan['assessment']['priority'],'review_score':scan['assessment']['review_score']})
        e=stage_evidence(payload,stage)
        top['command_indicators']+=e['commands'];top['code_references']+=e['code_references']
        top['text_evidence']+=e['text_evidence'];top['settings_evidence']+=e['config']
        if stage>=MAX_STAGES:break
        nested,notes=discover_nested(payload)
        top['loader_notes']+=notes
        if not nested:break
        unvisited=[(x,origin) for x,origin in nested if hashlib.sha256(x).hexdigest() not in seen]
        if not unvisited:break
        payload,origin=unvisited[0]
        top['loader_notes'].append(f'Stage {stage+1} recovered: {origin}')
    if len(top['stages'])>1:
        top['assessment']['priority']='High' if top['stages'][-1]['review_score']>=55 else top['stages'][-1]['risk_priority']
        top['assessment']['review_score']=max(s['review_score'] for s in top['stages'])
    # Limit IOC noise: unverified domain candidates from normal libraries are not C2 assertions.
    config_hosts=[]
    for x in top['settings_evidence']:
        if x['key'].lower().replace('_','') in WATCH_URL_KEYS and isinstance(x['value'],str):
            config_hosts.append({'stage':x['stage'],'setting':x['key'],'value':x['value'],'source':x['source'],
                                 'interpretation':'Configured URL / host (potential endpoint; no observed connection)'})
    top['configured_endpoints']=config_hosts
    top['static_only']=True
    top['notes']=['Evidence is extracted from uploaded APK bytes, not preset case data.',
                  'Method references and command labels indicate capability, not proven execution.',
                  'Not all encrypted loaders can be unpacked; native code and reflection may limit findings.',
                  'No sample is executed and no outbound traffic is generated.']
    top['stage_count']=len(top['stages'])
    return top
