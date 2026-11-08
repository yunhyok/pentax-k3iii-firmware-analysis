"""Local ICONBIN descriptor probe and byte-faithful neutral preview.

No device access or package generation; original decoded input is read-only. Colored channel assignment and downstream alpha blending are unknown.
"""
import argparse, hashlib, json, struct
from dataclasses import dataclass, asdict
from pathlib import Path

DECODED_SHA='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
RTOS_SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4'
ICON_SHA='9895330cd5d8c52231e96e1d39e883ae22ab35906eaf39d11476d852280b5808'
RTOS_BASE=0x52500000;RTOS_OFFSET=0x1c19c;RTOS_SIZE=25483200
ICON_OFFSET=47623500;ICON_SIZE=26219192
TABLE_ROM=0x53d08e80;TABLE_RAM=0x54521140;COUNT=0x682
sha=lambda b:hashlib.sha256(b).hexdigest()

@dataclass(frozen=True)
class Descriptor:
 icon_id:int
 address:int
 active:int
 reserved_byte:int
 width:int
 height:int
 reserved_halfword:int
 pixel_offset:int
 @property
 def byte_offset(self):return self.pixel_offset*4
 @property
 def byte_length(self):return self.width*self.height*4

def bounded(data,offset,size,label):
 if offset<0 or size<0 or offset>len(data) or size>len(data)-offset:raise ValueError(label+' outside source bounds')
 return data[offset:offset+size]

def load_verified(path):
 data=Path(path).read_bytes()
 if sha(data)!=DECODED_SHA:raise ValueError('decoded.bin SHA256 mismatch')
 rtos=bounded(data,RTOS_OFFSET,RTOS_SIZE,'RTOS');icons=bounded(data,ICON_OFFSET,ICON_SIZE,'ICONBIN')
 if sha(rtos)!=RTOS_SHA or sha(icons)!=ICON_SHA:raise ValueError('slice SHA256 mismatch')
 return rtos,icons

def parse_descriptors(rtos,payload_size,table_rom=TABLE_ROM,count=COUNT):
 if not 1<=count<=COUNT or payload_size<0 or payload_size%4:raise ValueError('unsupported count or payload size')
 table=bounded(rtos,table_rom-RTOS_BASE,count*4,'descriptor table');rows=[]
 for i in range(count):
  address=struct.unpack_from('<I',table,i*4)[0]
  if address%4:raise ValueError('unaligned descriptor pointer')
  d=Descriptor(i,address,*struct.unpack('<BBHHHI',bounded(rtos,address-RTOS_BASE,12,'descriptor')))
  if d.active not in (0,1) or d.reserved_byte or d.reserved_halfword:raise ValueError('unsupported descriptor flags/reserved fields')
  if d.active:
   if not d.width or not d.height:raise ValueError('active zero dimension')
   if d.byte_offset>payload_size or d.byte_length>payload_size-d.byte_offset:raise ValueError('pixel span outside ICONBIN')
  elif d.width or d.height or d.pixel_offset:raise ValueError('unsupported nonempty inactive descriptor')
  rows.append(d)
 return rows

def check_partition(rows,size):
 spans=sorted((d.byte_offset,d.byte_offset+d.byte_length,d.icon_id) for d in rows if d.active)
 next_offset=0
 for a,z,i in spans:
  if a!=next_offset:raise ValueError('descriptor gap or overlap')
  next_offset=z
 if next_offset!=size:raise ValueError('descriptors do not cover full payload')
 return {'active':len(spans),'inactive':sum(not d.active for d in rows),'covered_bytes':next_offset,'gaps':0,'overlaps':0}

def extract(payload,d):
 if not d.active:raise ValueError('inactive icon')
 return bounded(payload,d.byte_offset,d.byte_length,'pixel span')

def model_blit(source,width,height,destination,dest_pitch,x,y,offset_x,offset_y,requested_width,requested_height,key):
 """528c3ffc equivalent on explicitly checked valid geometry; no alpha blend."""
 if min(width,height,dest_pitch)<1 or min(x,y,offset_x,offset_y,requested_width,requested_height)<0 or not 0<=key<=255:raise ValueError('invalid blit geometry/key')
 cw=min(width,requested_width);ch=min(height,requested_height)
 if len(source)!=width*height*4 or len(destination)%4:raise ValueError('invalid word buffers')
 if offset_x+cw>width or offset_y+ch>height:raise ValueError('source rectangle overflow')
 if x+offset_x+cw>dest_pitch or (y+offset_y+ch)*dest_pitch*4>len(destination):raise ValueError('destination rectangle overflow')
 out=bytearray(destination)
 for row in range(ch):
  for col in range(cw):
   si=((row+offset_y)*width+col+offset_x)*4
   di=((row+y+offset_y)*dest_pitch+col+x+offset_x)*4
   if source[si+3]!=key:out[di:di+4]=source[si:si+4]
 return bytes(out)

def neutral_preview(raw,width,height,key=0):
 """Conservative low-byte visualization. Refuse color or partial high-byte data.

 Reads the same source geometry and skip key as the CPU blitter. Equality of the
 three low bytes makes this preview independent of their permutation. This does
 not establish LCD RGB meaning, tone response, or general alpha interpretation.
 """
 from PIL import Image
 if len(raw)!=width*height*4:raise ValueError('pixel size mismatch')
 out=bytearray()
 for b0,b1,b2,high in struct.iter_unpack('<BBBB',raw):
  if high==key:out.extend((0,0,0,0));continue
  if high!=255 or not b0==b1==b2:raise ValueError('neutral preview supports equal low bytes and high-byte 0/255 only')
  out.extend((b0,b0,b0,255))
 return Image.frombytes('RGBA',(width,height),bytes(out))

def author_badge(raw,width,height):
 """Authored seven-pixel plus badge; preserve dimensions and high byte."""
 if width<12 or height<12 or len(raw)!=width*height*4:raise ValueError('icon too small or malformed')
 out=bytearray(raw);x0=width-11;y0=height-11;changes=[]
 for dy in range(7):
  for dx in range(7):
   index=(y0+dy)*width+x0+dx;pos=index*4
   if raw[pos+3]!=255:raise ValueError('badge would change transparency boundary')
   level=255 if (dx==3 and 1<=dy<=5) or (dy==3 and 1<=dx<=5) else 0
   new=bytes((level,level,level,raw[pos+3]))
   if new!=raw[pos:pos+4]:
    changes.append({'pixel_index':index,'old_word':hex(struct.unpack_from('<I',raw,pos)[0]),'new_word':hex(struct.unpack('<I',new)[0])});out[pos:pos+4]=new
 return bytes(out),changes

def replace_icon(payload,d,new):
 if len(new)!=d.byte_length:raise ValueError('replacement must preserve descriptor byte length')
 extract(payload,d)
 return payload[:d.byte_offset]+new+payload[d.byte_offset+d.byte_length:]

def write_prototype(decoded,output_dir):
 from PIL import Image,ImageDraw
 rtos,icons=load_verified(decoded);rows=parse_descriptors(rtos,len(icons));coverage=check_partition(rows,len(icons))
 out=Path(output_dir);out.mkdir(parents=True,exist_ok=False)
 records=[]
 for d in rows:
  row=asdict(d);row.update(byte_offset=d.byte_offset,byte_length=d.byte_length)
  if d.active:row['pixel_sha256']=sha(extract(icons,d))
  records.append(row)
 (out/'descriptor-inventory.json').write_text(json.dumps(records,indent=2)+'\n',encoding='utf-8')
 d=rows[5];raw=extract(icons,d);changed,delta=author_badge(raw,d.width,d.height)
 candidate=replace_icon(icons,d,changed);restored=replace_icon(candidate,d,raw)
 assert restored==icons and candidate[:d.byte_offset]==icons[:d.byte_offset] and candidate[d.byte_offset+d.byte_length:]==icons[d.byte_offset+d.byte_length:]
 (out/'icon-0005.original.u32le.bin').write_bytes(raw);(out/'icon-0005.candidate.u32le.bin').write_bytes(changed)
 (out/'ICONBIN.candidate.bin').write_bytes(candidate)
 neutral_preview(raw,d.width,d.height).save(out/'icon-0005.original.png');neutral_preview(changed,d.width,d.height).save(out/'icon-0005.candidate.png')
 ids=[5,49,55,58,63,64,68,69,83]
 sheet=Image.new('RGB',(600,600),'#ccd1d7');draw=ImageDraw.Draw(sheet)
 for n,i in enumerate(ids):
  q=rows[i];im=neutral_preview(extract(icons,q),q.width,q.height);scale=min(3,150//q.width,150//q.height);im=im.resize((q.width*scale,q.height*scale),Image.Resampling.NEAREST)
  x=(n%3)*200;y=(n//3)*200;draw.text((x+8,y+8),f'ID {i}: {q.width} x {q.height}',fill='black');sheet.paste(im,(x+(200-im.width)//2,y+40),im)
 sheet.save(out/'neutral-contact-sheet.png')
 manifest={'schema':1,'source_decoded_sha256':DECODED_SHA,'rtos_sha256':RTOS_SHA,'iconbin_source_offset':ICON_OFFSET,'iconbin_source_size':ICON_SIZE,'iconbin_source_sha256':ICON_SHA,'descriptor_table_ram':hex(TABLE_RAM),'descriptor_table_rom':hex(TABLE_ROM),'coverage':coverage,'candidate_icon':asdict(d),'descriptor_bytes_sha256':sha(rtos[d.address-RTOS_BASE:d.address-RTOS_BASE+12]),'descriptor_modified':False,'original_icon_sha256':sha(raw),'candidate_icon_sha256':sha(changed),'candidate_payload_sha256':sha(candidate),'rollback_payload_sha256':sha(restored),'all_other_payload_bytes_unchanged':True,'high_bytes_unchanged':raw[3::4]==changed[3::4],'delta':delta,'authored_change':'7x7 neutral plus badge at width-11,height-11; preserve high byte and descriptor shape','scope':'Asset-only local candidate, not packaged/signed/bootable firmware. No source decoded.bin change. Default key0 applies to identified UI profile0/2 color tables. Preview refuses unequal low bytes and intermediate high bytes. RGB meaning/order and hardware alpha blend remain unresolved.'}
 (out/'candidate-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
 html='''<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ICONBIN local prototype</title><style>body{max-width:1050px;margin:35px auto;font:16px/1.6 system-ui;padding:20px}figure{display:inline-block;margin:16px}figure img{width:240px;height:240px;image-rendering:pixelated;background:repeating-conic-gradient(#bbb 0% 25%,#eee 0% 50%) 0 0/20px 20px}code{overflow-wrap:anywhere}.note{padding:15px;background:#fff2dc}</style><h1>ICONBIN 단일 아이콘 로컬 후보</h1><p>실제 ID 5의 40 × 40 저장 픽셀을 사용했습니다. 오른쪽의 작은 + 표식은 새로 작성한 후보입니다. descriptor와 다른 아이콘의 바이트는 보존했습니다.</p><figure><img src="icon-0005.original.png" alt="Original stored icon ID 5, neutral-byte preview"><figcaption>원본 ID 5 · low-byte 중립 미리보기</figcaption></figure><figure><img src="icon-0005.candidate.png" alt="Authored icon ID 5 candidate with a small plus badge"><figcaption>로컬 후보 · 7 × 7 표식</figcaption></figure><p class="note">원본 ARM이 확인한 것은 32-bit 픽셀 복사, 행 stride, 상위 byte 비교에 따른 복사 생략입니다. 이 미리보기는 하위 세 byte가 같고 상위 byte가 0/255인 아이콘만 허용합니다. 실제 LCD의 RGB 의미·채널 순서·알파 합성·색 관리는 검증하지 않았습니다. 회색 체크무늬는 미리보기 배경입니다.</p><p><a href="candidate-manifest.json">변경 범위·해시·복구 증거</a> · <a href="descriptor-inventory.json">1666-slot 목록</a> · <a href="https://yunhyok.github.io/pentax-k3iii-firmware-analysis/analysis/icon-resources.html">분석 보고서</a></p><h2>추출된 중립 아이콘 표본</h2><img src="neutral-contact-sheet.png" width="600" alt="9 neutral stored-byte icon previews"><p>카메라 UI 실행이나 완성된 펌웨어 패키지가 아닙니다. 원본 decoded.bin은 읽기만 했습니다.</p></html>'''
 (out/'preview.html').write_text(html,encoding='utf-8')
 return {'coverage':coverage,'candidate_id':5,'changed_pixels':len(delta),'rollback_sha256':sha(restored),'preview':str(out/'preview.html')}

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('decoded',type=Path);p.add_argument('--output-dir',type=Path,required=True);a=p.parse_args();print(json.dumps(write_prototype(a.decoded,a.output_dir),indent=2))
