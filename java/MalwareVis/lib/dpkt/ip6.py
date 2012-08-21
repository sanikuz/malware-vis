# $Id: ip6.py 50 2008-08-17 20:08:57Z jon.oberheide $

"""Internet Protocol, version 6."""

import dpkt

class IP6(dpkt.Packet):
    __hdr__ = (
        ('v_fc_flow', 'I', 0x60000000L),
        ('plen', 'H', 0),	# payload length (not including header)
        ('nxt', 'B', 0),	# next header protocol
        ('hlim', 'B', 0),	# hop limit
        ('src', '16s', ''),
        ('dst', '16s', '')
        )
    _protosw = {}		# XXX - shared with IP
    
    def _get_v(self):
        return self.v_fc_flow >> 28
    def _set_v(self, v):
        self.v_fc_flow = (self.v_fc_flow & ~0xf0000000L) | (v << 28)
    v = property(_get_v, _set_v)

    def _get_fc(self):
        return (self.v_fc_flow >> 20) & 0xff
    def _set_fc(self, v):
        self.v_fc_flow = (self.v_fc_flow & ~0xff00000L) | (v << 20)
    fc = property(_get_fc, _set_fc)

    def _get_flow(self):
        return self.v_fc_flow & 0xfffff
    def _set_flow(self, v):
        self.v_fc_flow = (self.v_fc_flow & ~0xfffff) | (v & 0xfffff)
    flow = property(_get_flow, _set_flow)

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        buf = self.data[:self.plen]
        try:
            self.data = self._protosw[self.nxt](buf)
            setattr(self, self.data.__class__.__name__.lower(), self.data)
        except (KeyError, dpkt.UnpackError):
            self.data = buf

    def __str__(self):
        if (self.nxt == 6 or self.nxt == 17 or self.nxt == 58) and \
               not self.data.sum:
            # XXX - set TCP, UDP, and ICMPv6 checksums
            p = str(self.data)
            s = dpkt.struct.pack('>16s16sxBH', self.src, self.dst, self.nxt, len(p))
            s = dpkt.in_cksum_add(0, s)
            s = dpkt.in_cksum_add(s, p)
            try:
                self.data.sum = dpkt.in_cksum_done(s)
            except AttributeError:
                pass
        return dpkt.Packet.__str__(self)

    def set_proto(cls, p, pktclass):
        cls._protosw[p] = pktclass
    set_proto = classmethod(set_proto)

    def get_proto(cls, p):
        return cls._protosw[p]
    get_proto = classmethod(get_proto)

# XXX - auto-load IP6 dispatch table from IP dispatch table
import ip
IP6._protosw.update(ip.IP._protosw)

if __name__ == '__main__':
    import unittest

    class IP6TestCase(unittest.TestCase):
        def test_IP6(self):
            s = '`\x00\x00\x00\x00(\x06@\xfe\x80\x00\x00\x00\x00\x00\x00\x02\x11$\xff\xfe\x8c\x11\xde\xfe\x80\x00\x00\x00\x00\x00\x00\x02\xb0\xd0\xff\xfe\xe1\x80r\xcd\xca\x00\x16\x04\x84F\xd5\x00\x00\x00\x00\xa0\x02\xff\xff\xf8\t\x00\x00\x02\x04\x05\xa0\x01\x03\x03\x00\x01\x01\x08\n}\x185?\x00\x00\x00\x00'
            ip = IP6(s)
            #print `ip`
            ip.data.sum = 0
            s2 = str(ip)
            ip2 = IP6(s)
            #print `ip2`
            assert(s == s2)

    unittest.main()
