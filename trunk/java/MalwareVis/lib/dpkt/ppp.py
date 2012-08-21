# $Id: ppp.py 23 2006-11-08 15:45:33Z dugsong $

"""Point-to-Point Protocol."""

import struct
import dpkt

# XXX - finish later

# http://www.iana.org/assignments/ppp-numbers
PPP_IP	= 0x21		# Internet Protocol
PPP_IP6 = 0x57		# Internet Protocol v6

# Protocol field compression
PFC_BIT	= 0x01

class PPP(dpkt.Packet):
    __hdr__ = (
        ('p', 'B', PPP_IP),
        )
    _protosw = {}
    
    def set_p(cls, p, pktclass):
        cls._protosw[p] = pktclass
    set_p = classmethod(set_p)

    def get_p(cls, p):
        return cls._protosw[p]
    get_p = classmethod(get_p)
    
    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        if self.p & PFC_BIT == 0:
            self.p = struct.unpack('>H', buf[:2])[0]
            self.data = self.data[1:]
        try:
            self.data = self._protosw[self.p](self.data)
            setattr(self, self.data.__class__.__name__.lower(), self.data)
        except (KeyError, struct.error, dpkt.UnpackError):
            pass

    def pack_hdr(self):
        try:
            if self.p > 0xff:
                return struct.pack('>H', self.p)
            return dpkt.Packet.pack_hdr(self)
        except struct.error, e:
            raise dpkt.PackError(str(e))

def __load_protos():
    import os
    d = dict.fromkeys([ x[:-3] for x in os.listdir(os.path.dirname(__file__) or '.') if x.endswith('.py') ])
    g = globals()
    for k, v in g.iteritems():
        if k.startswith('PPP_'):
            name = k[4:]
            modname = name.lower()
            if modname in d:
                mod = __import__(modname, g)
                PPP.set_p(v, getattr(mod, name))

if not PPP._protosw:
    __load_protos()
