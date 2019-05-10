import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Arrays;
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
import org.pcap4j.util.MacAddress;

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
    //private static Logger log = Logger.getLogger("InfoLogging");
    /* 
     * NatTable 
     * key: IPin:PORTin
     * Data: arrayList: [protocol, IP_output, Port_output, IP_input, Port_input] 
     */
    private LinkedHashMap<String, List<String>> natTable= new LinkedHashMap<String, List<String>>();
    private LinkedHashMap<String, MacAddress> ipMac = new LinkedHashMap<String, MacAddress>();
    private LinkedHashMap<String, String> usedPorts = new LinkedHashMap<String, String> ();
    public SampleTable(AddrSet addrSet) {
    	this.addrSet = addrSet;
    }
   
    @Override
    public synchronized PacketTransmission getOutputPacket(Packet packet, Interface iface){
    	//ArrayList<String> inputLine = new ArrayList<String>();
    	String key = new String();
    	String outPort = "";
    	Inet4Address srcAddr, dstAddr = null; 
    	Short srcPort, dstPort = 0;
    	EthernetPacket ethP;
    	EthernetPacket.Builder ethB;
    	IpV4Packet ipv4P;
    	IpV4Packet.Builder ipB;
    	UdpPacket udpPacket = null;
    	UdpPacket.Builder udpB;
    	TcpPacket tcpPacket = null;
    	TcpPacket.Builder tcpB;
    	String protocolTable, dstIpTable, dstPortTable, srcIpTable, srcPortTable = ""; 
        //System.err.println("Thread xestionando a interface " + 
		//	   ((iface == RoNAT.Interface.OUTSIDE) ? "externa" : "interna"));
        //System.err.println(packet);
        
        //"inside : outside" case
        
        /*
         * IMPORTANTE: Ahora mismo no tengo en cuenta los puertos que se vienen
         * con la tabla de reenvío inicial. Considero que no existe una tabla 
         * inicial y por lo tanto el servivio NAT empieza de cero. 
         * Cualquier paquete que venga de la interface outside inicialmente, 
         * será descartado.
         */
	    ethP = packet.get(EthernetPacket.class);
	    ethB = ethP.getBuilder();
        if (ethP.getHeader().getType() == EtherType.IPV4) {
        	ipv4P = ethP.get(IpV4Packet.class);
        	ipB = ipv4P.getBuilder();	
        } else {
        	return null;
        }
		try {
	        if (iface == RoNAT.Interface.INSIDE) {
	        	// Obtención de los datos para tabla de reenvío
	        	System.out.println("El paquete viene de la interface inside");
	        	/*
	        	if (ipv4P.getHeader().getDstAddr().toString().split(".")[0].contains("224")) {
	        		System.out.println("El paquete ha sido filtrado. Multicast direction");
	        		// this packet is filtered because it contains a multicast direction
	        		return null; 
	        	}*/
	        	key = ipv4P.getHeader().getSrcAddr().toString();
	        	System.out.println("Direccion origen IP"+ipv4P.getHeader().getSrcAddr().toString());
	        	if (ipMac.containsKey(key)){
	        		if (ipMac.get(key) != ethP.getHeader().getSrcAddr()) {
	        			ipMac.put(key, ethP.getHeader().getSrcAddr());
	        		}
	        	} else {
	        		ipMac.put(key, ethP.getHeader().getSrcAddr());
	        	}
	        	if (ipv4P.getHeader().getProtocol() == IpNumber.UDP) {
		        	System.out.println("Trabajando con UDP");
	        		udpPacket = ipv4P.get(UdpPacket.class);
	        		System.out.println("'"+udpPacket.getHeader().getSrcPort().toString()+"'");
	        		srcPortTable = udpPacket.getHeader().getSrcPort().toString().split(" ")[0];
	        	}else if (ipv4P.getHeader().getProtocol() == IpNumber.TCP) {
		        	System.out.println("Trabajando con TCP");
	        		tcpPacket = ipv4P.get(TcpPacket.class);
	        		srcPortTable = tcpPacket.getHeader().getSrcPort().toString();
	        	}	        	
	        	key = key.concat(":"+srcPortTable);
	        	if (!natTable.containsKey(key)) {
	        		System.out.println("No existe entrada en la tabla. Creando entrada");
	        		System.out.println(ipv4P.getHeader().getProtocol());
	        		protocolTable = ipv4P.getHeader().getProtocol().toString().split(" ")[0];
	        		System.out.println(protocolTable);
	        		srcIpTable = ipv4P.getHeader().getSrcAddr().toString().replace("/", "");
	        		System.out.println(srcIpTable);
	        		dstIpTable = ipv4P.getHeader().getDstAddr().toString().replace("/", "");;
	        		System.out.println(key);
	        		// First use of ip_in:port_in
		        	port = key.split(":")[1];
	        		System.out.println("No existe entrada en la tabla. Creando entrada");
		        	if (usedPorts.containsKey(port)) {
		        		System.out.println("Puerto en uso");
		        		while (!usedPorts.containsKey(port)){
		        			port = Integer.toString(rand.nextInt(1500) + 5000); //generate int from 5000 to 6500
		        		}
		        		dstPortTable = port;
		        	} else {
		        		dstPortTable = srcPortTable;
		        	}
		        	System.out.println("Nueva entrada en la tabla");
		        	natTable.put(key, Arrays.asList(protocolTable, dstIpTable, dstPortTable, srcIpTable, srcPortTable));
	        	}
	        	// 1.- add the dstPort to the packet
	        	System.out.println(natTable.toString());
	        	System.out.println("Entrada de la tabla utilizada: "+natTable.get(key.toString()));
	        	System.out.println(natTable.get(key).get(4));  
	        	srcAddr = (Inet4Address)Inet4Address.getByName(natTable.get(key).get(3));
	        	System.out.println("Modificando parámetros del paquete");
	        	System.out.println(natTable.get(key).get(4));
	        	dstPort =  Short.parseShort(natTable.get(key).get(4), 6000);
	        	System.out.println(dstPort);
	        	if (ipv4P.getHeader().getProtocol() == IpNumber.UDP) {
	        		udpPacket = packet.get(UdpPacket.class);
	        		udpB = udpPacket.getBuilder();
		        	System.out.println("	puerto destino original: "+udpPacket.getHeader().getDstPort().toString());
	        		udpB.dstPort(UdpPort.getInstance(dstPort));
		        	System.out.println("	puerto destino modificado: "+dstPort);
		        	System.out.println("	IPdir origen original: "+ipv4P.getHeader().getSrcAddr().toString());
					ipB.srcAddr(srcAddr).payloadBuilder(udpB);
		        	System.out.println("	IPdir origen modificado: "+srcAddr);
	        	}else if (ipv4P.getHeader().getProtocol() == IpNumber.TCP) {
	        		tcpPacket = packet.get(TcpPacket.class);
		        	System.out.println("puerto destino "+tcpPacket.getHeader().getDstPort().toString());
	        		tcpB = tcpPacket.getBuilder();
		        	System.out.println("	puerto destino original: "+tcpPacket.getHeader().getSrcPort().toString());
	        		tcpB.dstPort(TcpPort.getInstance(dstPort));
		        	System.out.println("	puerto destino modificado: "+dstPort);
					ipB.srcAddr(srcAddr).payloadBuilder(tcpB);
	        	}
	        	ipB.build();
	        	ethB.dstAddr(addrSet.getRouterMac()).srcAddr(addrSet.getOuterMac()).payloadBuilder(ipB);
	        	ethB.build();
	        	System.out.println("Paquete modificado a enviar");
	        	//System.out.println(packet);
	        }else if (iface == RoNAT.Interface.OUTSIDE) {
	    		// checking the used port 
		    	if (ipv4P.getHeader().getProtocol() == IpNumber.UDP) {
		    		udpPacket = ipv4P.get(UdpPacket.class);
		    		//tableInput.set(2, udpPacket.getHeader().getSrcPort().toString());
		    		outPort = udpPacket.getHeader().getDstPort().toString();
		    	}else if (ipv4P.getHeader().getProtocol() == IpNumber.TCP) {
		    		tcpPacket = ipv4P.get(TcpPacket.class);
		    		//tableInput.set(2, tcpPacket.getHeader().getSrcPort().toString());
		    		outPort = tcpPacket.getHeader().getSrcPort().toString();
		    	}    		
	    		if (usedPorts.containsKey(outPort)) {
	    			// Changing source and destination port 
	        		srcAddr = ipv4P.getHeader().getDstAddr();
					dstAddr = (Inet4Address)Inet4Address.getByName(usedPorts.get(outPort).split(":")[0]);
	        		srcPort = Short.parseShort(natTable.get(key).get(4));
					dstPort = Short.parseShort(natTable.get(key).get(2));
	    			if (ipv4P.getHeader().getProtocol() == IpNumber.UDP) {
		    			udpB = udpPacket.getBuilder();
		    			udpB.srcPort(UdpPort.getInstance(srcPort));
		    			udpB.dstPort(UdpPort.getInstance(dstPort));	
		    			udpB.dstAddr(srcAddr).srcAddr(dstAddr);
		    			// udpB.build();
						ipB.srcAddr(srcAddr).dstAddr(dstAddr).payloadBuilder(udpB);
		        	} else if (ipv4P.getHeader().getProtocol() == IpNumber.TCP) {
		    			tcpB = tcpPacket.getBuilder();
		    			tcpB.srcPort(TcpPort.getInstance(srcPort));
		    			tcpB.dstPort(TcpPort.getInstance(dstPort));
		    			tcpB.dstAddr(srcAddr).srcAddr(dstAddr);
		    			// tcpB.build();
						ipB.srcAddr(srcAddr).dstAddr(dstAddr).payloadBuilder(tcpB);
		        	}
	    			// building the packet
		        	ipB.build();
		        	ethB.dstAddr(ipMac.get(usedPorts.get(outPort).split(":")[0])).srcAddr(addrSet.getInnerMac()).payloadBuilder(ipB);
		        	ethB.build();
	    		} else {
	    			return null;
	    		}        	
	        }
		} catch (UnknownHostException e) {
			System.out.println(e.getMessage());
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	    //packet construction and transmission 
    	pTrans = new PacketTransmission(packet, iface);
    	System.out.println(pTrans.toString());
        return pTrans;
    }

}
