import org.pcap4j.packet.Packet;

import gal.uvigo.det.ro1819.nat.AddrSet;
import gal.uvigo.det.ro1819.nat.NATTable;
import gal.uvigo.det.ro1819.nat.RoNAT.Interface;

class SampleTable implements NATTable {
    private AddrSet addrSet;
    
    public SampleTable(AddrSet addrSet) {
	this.addrSet = addrSet;
    }
    
    @Override
    public synchronized Packet getOutputPacket(Packet packet, Interface iface) {
	return null;
    }

}
