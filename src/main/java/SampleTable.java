import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Random;

import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.packet.namednumber.UdpPort;

import gal.uvigo.det.ro1819.nat.AddrSet;
import gal.uvigo.det.ro1819.nat.NATTable;
import gal.uvigo.det.ro1819.nat.RoNAT;
import gal.uvigo.det.ro1819.nat.RoNAT.Interface;
import gal.uvigo.det.ro1819.nat.PacketTransmission;

/**
 * No programa principal (main, en Nat.java) créase un obxecto da clase
 * SampleTable, que compartirán os dous threads que implementan a
 * funcionalidade do noso router virtual. E é aquí onde debedes incorporar as
 * estructuras de datos que representen a táboa de asociacións inside/outside,
 * e calquera otra información/obxectos que manexedes/creedes para implementar
 * a funcionalidade do NAT.
 *
 * O método "getOutputPacket" é chamado automáticamente polo thread
 * responsable da interface pola que recén chegou un paquete. Agora mesmo só
 * imprime unha mensaxe, e o propio paquete recibido, e representa o voso
 * punto de partida para principiar o seu procesamento. O parámetro "Interface
 * iface" indicaranos si chegou pola interface inside ou pola outside. O
 * método debe rematar devolvendo null (si o paquete vai a ser filtrado), o
 * mesmo paquete recibido (si non se ve afectado polo NAT e ten que ser
 * encamiñado pola outra interfaz), o paquete modificado polo NAT, ou unha
 * petición ARP (si se implementa esta funcionalidade). Será o thread que está
 * agardando a finalización do método, quen fará a transmisión (chamada á
 * función sendPacket en RoNAT.java).
 * 
 * O paquete a transmitir ten que envolverse dentro dun obxecto PacketTransmission,
 * onde se indicará tamén a interface de saída (INSIDE ou OUTSIDE)
 * 
 * A información contida neste obxecto debe tratarse coas debidas precaucións
 * xa que falamos dun obxecto compartido entre dous procesos/threads, que
 * deberán sincronizarse para que a información que len/modifican non
 * sexa/resulte inconsistente. Os profesores explicaranvos e orientaranvos no
 * xeito de facer está sincronización.
*/
class SampleTable implements NATTable {
    private AddrSet addrSet;
    private String port = "5000"; 
    Random rand = new Random();
    PacketTransmission pTrans;
    /* 
     * NatTable 
     * key: IPin_PORTin_protocol
     * Data: arrayList: [protocol, IP_output, Port_output, IP_input, Port_input] 
     */
    private LinkedHashMap<String, ArrayList<String>> natTable= new LinkedHashMap<String, ArrayList<String>>();
    private LinkedHashMap<String, String> usedPorts = new LinkedHashMap<String, String> ();
    public SampleTable(AddrSet addrSet) {
    	this.addrSet = addrSet;
    }
   
    @Override
    public synchronized PacketTransmission getOutputPacket(Packet packet, Interface iface){
    	ArrayList<String> tableInput = new ArrayList<String>(5);
    	String key = new String();
    	String outPort = "";
    	UdpPacket udpPacket = null;
    	TcpPacket tcpPacket = null;
    	Inet4Address srcAddr, dstAddr = null; 
    	Short srcPort, dstPort = 0;
    	IpV4Packet ipv4P;
        System.err.println("Thread xestionando a interface " + 
			   ((iface == RoNAT.Interface.OUTSIDE) ? "externa" : "interna"));
        System.err.println(packet);
        
        //"inside : outside" case
        
        /*
         * IMPORTANTE: Ahora mismo no tengo en cuenta los puertos que se vienen
         * con la tabla de reenvío inicial. Considero que no existe una tabla 
         * inicial y por lo tanto el servivio NAT empieza de cero. 
         * Cualquier paquete que venga de la interface outside inicialmente, 
         * será descartado.
         */
	    EthernetPacket ethP = packet.get(EthernetPacket.class);
        if (iface == RoNAT.Interface.INSIDE) {
        	// Obtención de los datos para tabla de reenvío
	        if (ethP.getHeader().getType() == EtherType.IPV4) {
	        	ipv4P = packet.get(IpV4Packet.class);
	        	if (ipv4P.getHeader().getDstAddr().toString().split(".")[0].contains("224")) {
	        		// this packet is filtered because it contains a multicast direction
	        		return null;
	        	}
	        	//if (ipv4P.getHeader().getProtocol() == IpNumber.arp)
	        	tableInput.set(0, ipv4P.getHeader().getProtocol().toString());
	        	tableInput.set(1, ipv4P.getHeader().getSrcAddr().toString());
	        	tableInput.set(3, ipv4P.getHeader().getDstAddr().toString());
	        	key = ipv4P.getHeader().getSrcAddr().toString();
	        	if (ipv4P.getHeader().getProtocol() == IpNumber.UDP) {
	        		udpPacket = packet.get(UdpPacket.class);
	        		tableInput.set(2, udpPacket.getHeader().getSrcPort().toString());
	        		key.concat(":"+udpPacket.getHeader().getSrcPort().toString());
	        	}else if (ipv4P.getHeader().getProtocol() == IpNumber.TCP) {
	        		tcpPacket = packet.get(TcpPacket.class);
	        		tableInput.set(2, tcpPacket.getHeader().getSrcPort().toString());
	        		key.concat(":"+tcpPacket.getHeader().getSrcPort().toString());
	        	}
	        	
	        	if (!natTable.containsKey(key)) {
	        		// First use of ip_in:port_in
		        	if (usedPorts.containsKey(key.split(":")[1])) {
		        		port = key.split(":")[1];
		        		while (!usedPorts.containsKey(port)){
		        			port = Integer.toString(rand.nextInt(1500) + 5000); //generate int from 5000 to 6500
		        		}
		        		tableInput.set(4, port);
		        	} else {
		        		tableInput.set(4, tableInput.get(2));
		        	}
		        	natTable.put(key, tableInput);
	        	}else {
	        		// ip_in:port_in was used before
	    	        if (ethP.getHeader().getType() == EtherType.IPV4) {
	    	        	ipv4P = packet.get(IpV4Packet.class);
	    	        	key = ipv4P.getHeader().getSrcAddr().toString();
	    	        	// 1.- add the dstPort to the packet
	    	        	if (ipv4P.getHeader().getProtocol() == IpNumber.UDP) {
	    	        		udpPacket = packet.get(UdpPacket.class);
	    	        		tableInput.set(2, udpPacket.getHeader().getSrcPort().toString());
	    	        		key.concat(":"+udpPacket.getHeader().getSrcPort().toString());
	    	        		UdpPacket.Builder udpB = udpPacket.getBuilder();
	    	        		udpB.dstPort(UdpPort.getInstance(Short.parseShort(natTable.get(key).get(4))));
	    	        	}else if (ipv4P.getHeader().getProtocol() == IpNumber.TCP) {
	    	        		tcpPacket = packet.get(TcpPacket.class);
	    	        		tableInput.set(2, tcpPacket.getHeader().getSrcPort().toString());
	    	        		key.concat(":"+tcpPacket.getHeader().getSrcPort().toString());
	    	        		TcpPacket.Builder tcpB = tcpPacket.getBuilder();
	    	        		tcpB.dstPort(TcpPort.getInstance(Short.parseShort(natTable.get(key).get(4))));
	    	        	}
	    	        	
		        		//2.- source IP changed (IP_private -> IP_public)
		        		try {
		        			IpV4Packet.Builder ipB = ipv4P.getBuilder();
							ipB.srcAddr( (Inet4Address)Inet4Address.getByName(natTable.get(key).get(3)));
							ipB.build();
						} catch (UnknownHostException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
	    	        }
	        	}
	        }	        
	        
	        
        }else if (iface == RoNAT.Interface.OUTSIDE) {
        	ipv4P = ethP.get(IpV4Packet.class);
    		IpV4Packet.Builder ipB = ipv4P.getBuilder();
	    	if (ipv4P.getHeader().getProtocol() == IpNumber.UDP) {
	    		udpPacket = ipv4P.get(UdpPacket.class);
	    		tableInput.set(2, udpPacket.getHeader().getSrcPort().toString());
	    		outPort = udpPacket.getHeader().getSrcPort().toString();
	    	}else if (ipv4P.getHeader().getProtocol() == IpNumber.TCP) {
	    		tcpPacket = ipv4P.get(TcpPacket.class);
	    		tableInput.set(2, tcpPacket.getHeader().getSrcPort().toString());
	    		outPort = tcpPacket.getHeader().getSrcPort().toString();
	    	}    		
    		if (usedPorts.containsKey(outPort)) {
    			// Changing source and destination port 
        		srcAddr = ipv4P.getHeader().getDstAddr();
        		dstAddr = (Inet4Address)Inet4Address.getByName(usedPorts.get(outPort).split(":")[0]);
        		srcPort = Short.parseShort(natTable.get(key).get(4));
				dstPort = Short.parseShort(natTable.get(key).get(2));
    			if (ipv4P.getHeader().getProtocol() == IpNumber.UDP) {
	    			UdpPacket.Builder udpB = udpPacket.getBuilder();
	    			udpB.srcPort(UdpPort.getInstance(srcPort));
	    			udpB.dstPort(UdpPort.getInstance(dstPort));	
	    			udpB.dstAddr(srcAddr).srcAddr(dstAddr);
	    			// udpB.build();
					ipB.srcAddr(srcAddr).dstAddr(dstAddr).getPayloadBuilder(udpB);
	        	} else if (ipv4P.getHeader().getProtocol() == IpNumber.TCP) {
	    			TcpPacket.Builder tcpB = tcpPacket.getBuilder();
	    			tcpB.srcPort(TcpPort.getInstance(srcPort));
	    			tcpB.dstPort(TcpPort.getInstance(dstPort));
	    			tcpB.dstAddr(srcAddr).srcAddr(dstAddr);
	    			// tcpB.build();
					ipB.srcAddr(srcAddr).dstAddr(dstAddr).getPayloadBuilder(tcpB);
	        	}
	        	
    			// Changing source and destination IPaddress
    			try {
					ipB.srcAddr(srcAddr).dstAddr(dstAddr).getPayloadBuilder();
					ipB.dstAddr();
					ipB.build();
				} catch (UnknownHostException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
    		} else {
    			return null;
    		}
        	
        }
	    //packet construction and transmission 
    	pTrans = new PacketTransmission(packet, iface);
        return pTrans;
    }

}
