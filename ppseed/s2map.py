"""Parse s2.one into an object map; provide surgical mutation utilities."""
import struct, uuid, sys, copy

class S2:
    def __init__(self, path):
        self.path = path
        self.d = bytearray(open(path,'rb').read())
        self.decls = []   # dict: node_off, blob_off, blob_cb, oid, gi, jcid, props:[(pid,type,val_off)]
        self._walk()

    def _u16(self,o): return struct.unpack_from('<H',self.d,o)[0]
    def _u32(self,o): return struct.unpack_from('<I',self.d,o)[0]
    def _u64(self,o): return struct.unpack_from('<Q',self.d,o)[0]

    def _walk(self):
        d=self.d; N=len(d)
        stp,cb=struct.unpack_from('<QI',d,0xAC)
        seen=set()
        stack=[(stp,cb)]
        while stack:
            off,cb=stack.pop()
            while off in seen and False: break
            if (off,cb) in seen: continue
            seen.add((off,cb))
            p=off
            while p < off+cb and p+16<=N:
                if self._u64(p)!=0xA4567AB1F5F7F4C4: break
                frag_end=p+cb
                q=p+16
                while q < frag_end-20 and q+4<=N:
                    v=self._u32(q)
                    fnid=v&0x3FF; size=(v>>10)&0x1FFF; bt=(v>>27)&0xF
                    if size<4 or q+size>N: break
                    if fnid==0x0FF:
                        q+=4; break
                    if bt in (1,2):
                        stpf=(v>>23)&3; cbf=(v>>25)&3
                        ssz={0:8,1:4,2:2,3:4}[stpf]; csz={0:4,1:8,2:1,3:2}[cbf]
                        rp=q+4
                        if ssz==8: r_stp=self._u64(rp)
                        elif ssz==4: r_stp=self._u32(rp)
                        elif ssz==2: r_stp=self._u16(rp)*8
                        else: r_stp=self._u32(rp)
                        if csz==8: r_cb=self._u64(rp+ssz)
                        elif csz==4: r_cb=self._u32(rp+ssz)
                        elif csz==2: r_cb=self._u16(rp+ssz)*8
                        else: r_cb=self.d[rp+ssz]*8
                        if r_stp==0xFFFFFFFFFFFFFFFF or r_stp==0 or r_cb==0:
                            q+=size; continue
                        if bt==2:
                            stack.append((r_stp,r_cb))
                        else:
                            if fnid in (0x0A4,0x0A5):
                                body=rp+ssz+csz
                                flags=self.d[body]
                                oidv=self._u32(body+1)
                                jcid=self._u32(body+5)
                                self._parse_propset(r_stp, r_cb, oidv, jcid, fnid)
                        q+=size
                        continue
                    q+=size
                nf=frag_end-20
                if nf+12<=N:
                    nstp,ncb=struct.unpack_from('<QI',self.d,nf)
                    if nstp!=0xFFFFFFFFFFFFFFFF and ncb!=0xFFFFFFFF and nstp!=0:
                        # continue to next fragment in chain
                        p=nstp; cb=ncb
                        continue
                break

    def _parse_propset(self, off, cb, oidv, jcid, decl_fnid):
        d=self.d
        p=off; end=off+cb
        from types import SimpleNamespace
        rec = SimpleNamespace(node_off=None, blob_off=off, blob_cb=cb, oid_n=oidv&0xFF, gi=(oidv>>8)&0xFFFFFF, jcid=jcid, fnid=decl_fnid, props=[], oids_count=0, oids_off=0, osids_off=0, osids_count=0, hdr_off=off, cprops_off=0, prids_off=0)
        v=self._u32(p); oids_count=v&0xFFFFFF; ext=(v>>30)&1; osid_np=(v>>31)&1
        p+=4+4*oids_count
        rec.oids_count=oids_count; rec.oids_off=off+4; rec.hdr_off=off
        if not osid_np:
            v=self._u32(p); c=v&0xFFFFFF; ext2=(v>>30)&1
            rec.osids_off=p+4; rec.osids_count=c
            p+=4+4*c
            if ext2:
                v=self._u32(p); c2=v&0xFFFFFF
                p+=4+4*c2
        cprops=self._u16(p); p+=2
        rec.cprops_off=p-2
        prids=[]
        for i in range(cprops):
            pv=self._u32(p); prids.append((pv&0x3FFFFFF,(pv>>26)&0x1F)); p+=4
        rec.prids_off = p - 4*cprops
        for pid,ty in prids:
            if p+8>end:
                break
            rec.props.append(SimpleNamespace(pid=pid,ty=ty,off=p))
            if ty==2: p+=1
            elif ty==1: pass
            elif ty==3: p+=1
            elif ty==4: p+=2
            elif ty==5: p+=4
            elif ty==6: p+=8
            elif ty==7:
                n=self._u32(p); p+=4+n
                if p>end: break
            elif ty==8: p+=4
            elif ty==9:
                n=self._u32(p); p+=4+4*n
            elif ty==0xA: p+=4
            elif ty==0xB:
                n=self._u32(p); p+=4+4*n
            elif ty==0xC: p+=4
            elif ty==0xD:
                n=self._u32(p); p+=4+4*n
            elif ty in (0x10,0x11):
                break  # stop at complex types
        self.decls.append(rec)

    def save(self, path):
        open(path,'wb').write(bytes(self.d))

    def summary(self):
        out=[]
        for r in self.decls:
            ps=", ".join("0x%08X/t%d"%(pr.pid,pr.ty) for pr in r.props)
            out.append("oid(n=%d,gi=%d) jcid=0x%08X blob@0x%X cb=0x%X: %s"%(r.oid_n,r.gi,r.jcid,r.blob_off,r.blob_cb,ps))
        return "\n".join(out)

if __name__=='__main__':
    s=S2(sys.argv[1] if len(sys.argv)>1 else 's2.one')
    print(s.summary())

def fix_crcname(path):
    """Set Header.crcName = CRC32(UTF16LE(filename)+NUL) to match the actual file name."""
    import os, zlib, struct
    d = bytearray(open(path,'rb').read())
    name = os.path.basename(path)
    crc = zlib.crc32(name.encode('utf-16-le') + b'\x00\x00') & 0xFFFFFFFF
    struct.pack_into('<I', d, 0x90, crc)
    open(path,'wb').write(bytes(d))
    return crc
