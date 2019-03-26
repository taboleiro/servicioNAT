import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.util.MacAddress;

import gal.uvigo.det.ro1819.nat.RoNAT;

class Nat {
    public static void main(String[] args) {
	if (args.length != 1) {
	    System.err.println("Error de parametros: requírese a MAC do router interno do host anfitrión.");
	    System.err.println("\nRoNAT mac_router");
	    System.exit(1);
	}

	var hostRouterMacAddr = MacAddress.getByName(args[0]);

	try {
	    var roNat = RoNAT.create(hostRouterMacAddr);	
	    var table = new SampleTable(roNat.getAddresses());

	    roNat.execute(table);
	} catch (PcapNativeException | NotOpenException e) {
	    // TODO Auto-generated catch block
	    e.printStackTrace();
	}
    }
}
