"""Verify packaged DTB metadata and the absence of the M8M remap-node name."""
import argparse,hashlib,json,struct
from pathlib import Path
from verify_m0_memory import load_decoded
from rtos_catalog import require
H=lambda b:hashlib.sha256(b).hexdigest()
HERE=Path(__file__).resolve().parent

def run(decoded,evidence):
 e=evidence['dtb'];off=int(e['decoded_offset'],16);n=e['size']
 require(0<=off<off+n<=len(decoded),'DTB bounds mismatch')
 d=decoded[off:off+n];require(H(d)==e['sha256'],'DTB hash mismatch')
 magic,total,structure,strings,reserve,version,compat,bootcpu,string_size,structure_size=struct.unpack_from('>10I',d)
 require(magic==0xd00dfeed and total==n and (version,compat)==(17,16),'DTB header mismatch')
 require(40<=reserve<structure and reserve%8==0 and structure%4==0 and structure+structure_size<=strings and strings+string_size==total,'DTB block layout mismatch')
 require(d[reserve:reserve+16]==bytes(16),'Unexpected reservation list')
 require(struct.unpack_from('>I',d,structure)[0]==1 and d[structure+4:structure+8]==bytes(4),'Root node mismatch')
 require(struct.unpack_from('>II',d,structure+structure_size-8)==(2,9),'DTB termination mismatch')
 properties=[]
 for r in e['root_properties']:
  a=int(r['decoded_offset'],16)-off;size=r['size']
  require(structure+8<=a-12<a+size<=structure+structure_size,'Property bounds mismatch')
  token,length,nameoff=struct.unpack_from('>III',d,a-12)
  require(token==3 and length==size and nameoff<string_size,'Property header mismatch')
  end=d.find(b'\0',strings+nameoff,strings+string_size)
  require(end>=0 and d[strings+nameoff:end].decode('ascii')==r['name'],'Property name mismatch')
  value=d[a:a+size]
  require(H(value)==r['sha256'] and value==('\0'.join(r['strings'])+'\0').encode(),'Property value mismatch')
  properties.append(dict(name=r['name'],strings=r['strings']))
 absent=e['absent_nul_terminated_strings']
 require(all(s.encode()+b'\0' not in d for s in absent),'Unexpected remap or trampoline node name')
 return dict(passed=True,dtb_sha256=H(d),decoded_offset=hex(off),size=n,root_properties=properties,absent_nul_terminated_strings=absent,physical_sram_alias_verified=False,vendor_source_replayed=False,scope='Exact packaged DTB checked; source member hashes and line references are recorded separately. Runtime DTB modifications and active hardware mappings were not observed.')

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('decoded',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 result=run(load_decoded(a.decoded),json.loads((HERE/'analysis/sram-remap-evidence.json').read_text()))
 a.output.write_text(json.dumps(result,indent=2)+'\n');print('Passed packaged DTB and remap-node metadata checks')
