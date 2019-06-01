import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
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
    Boolean first = true;
	long cleanTime = 0;
    //private static Logger log = Logger.getLogger("InfoLogging");
    /* 
     * NatTable 
     * key: IPin:PORTin
     * Data: arrayList: [protocol, IP_output, Port_output, IP_input, Port_input, expiration](Instante de último uso) 
     */
    private LinkedHashMap<String, RowTable> natTable= new LinkedHashMap<String, RowTable>();
    private LinkedHashMap<String, MacAddress> ipMac = new LinkedHashMap<String, MacAddress>();
    private LinkedHashMap<Short, String> usedPorts = new LinkedHashMap<Short, String> ();
    public SampleTable(AddrSet addrSet) {
    	this.addrSet = addrSet;
    }
   
    @Override
    public synchronized PacketTransmission getOutputPacket(Packet packet, Interface iface){
    	//ArrayList<String> inputLine = new ArrayList<String>();
    	RowTable rowTable = new RowTable();
    	String key = "";
    	Short outPort = 0;
    	Inet4Address srcAddr, dstAddr = null; 
    	Short srcPort, dstPort = 0;
    	EthernetPacket ethP;
    	EthernetPacket.Builder ethB;
    	IpV4Packet ipv4P;
    	IpV4Packet.Builder ipB;
    	UdpPacket udpPacket = null;
    	UdpPacket.Builder udpB = null;
    	TcpPacket tcpPacket = null;
    	TcpPacket.Builder tcpB = null;
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
    	if (first) {
    		try {
	    		File file = new File("/home/ro/eclipse-workspace/NAT2018-19/src/main/java/NAT.txt");
				BufferedReader staticNat = new BufferedReader(new FileReader(file));
	    		first = false;
	    		String st; 
	    		String[] parameters;
	    		while ((st = staticNat.readLine()) != null) {
	    			parameters = st.split(" ");
	    			switch (parameters[0]) {
		    			case "17":
		    				rowTable.setProtocol(IpNumber.TCP);
		    				break;
		    			case "6":
		    				rowTable.setProtocol(IpNumber.UDP);
		    				break;
	    			}
	    			rowTable.setOutPort(Short.parseShort(parameters[1]));
	    			rowTable.setInIP((Inet4Address)InetAddress.getByName(parameters[2]));
	    			rowTable.setSrcPort(Short.parseShort(parameters[3]));
	    			rowTable.setUltimoUso(Long.parseLong("0"));
	    			key = rowTable.getInIP().toString()+":"+rowTable.getInPort();
	    			addToTable(key, rowTable, outPort);
	    		} 
			} catch (IOException e) {
				// TODO Auto-generated catch blocks
				e.printStackTrace();
			}
    	}
	    ethP = packet.get(EthernetPacket.class);
	    ethB = ethP.getBuilder();
        if (ethP.getHeader().getType() == EtherType.IPV4) {
        	ipv4P = ethP.get(IpV4Packet.class);
        	ipB = ipv4P.getBuilder();
	        ipB.correctChecksumAtBuild(true);	
        } else {
        	return null;
        }
        // checking time of the last cleaning work
    	System.out.println("Clean time:"+cleanTime);
        if (cleanTime < System.currentTimeMillis() - 30000) {
        	natTable.clear();
        	cleanTime = System.currentTimeMillis();
        	System.out.println("Eliminando todas las entradas dinámicas de la tabla");
        } else {
        	// checking expiration of the rows of the nat table
        	for (String keys: natTable.keySet()) {
        		if (natTable.get(keys).getUltimoUso() < System.currentTimeMillis() - 60000 && natTable.get(keys).getUltimoUso() > 0) {
        			System.out.println("La entrada "+keys+" ha sido eliminada porque ha caducado");  
        			System.out.println("valor de último uso: "+natTable.get(keys).getUltimoUso());      			
        			natTable.remove(keys);
        		}
        	}
        }
        if (iface == RoNAT.Interface.INSIDE) {
        	iface = RoNAT.Interface.OUTSIDE;
        	// Obtención de los datos para tabla de reenvío
        	System.out.println("El paquete viene de la interface inside");
        	if (ipv4P.getHeader().getDstAddr().toString().contains("/224.") ||
        		ipv4P.getHeader().getDstAddr().equals(addrSet.getInnerIP())) {
        		// this packet is filtered because it contains a multicast direction
        		filtering("INSIDE", ipv4P.getHeader().getDstAddr().toString());
        		return null; 
        	}
        	//System.out.println(packet);
        	key = ipv4P.getHeader().getSrcAddr().toString();
        	System.out.println("Direccion origen IP"+ipv4P.getHeader().getSrcAddr().toString());
        	if (ipMac.containsKey(key)){
        		if (ipMac.get(key) != ethP.getHeader().getSrcAddr()) {
        			ipMac.put(key, ethP.getHeader().getSrcAddr());
        		}
        	} else {
        		ipMac.put(key, ethP.getHeader().getSrcAddr());
        	}
        	System.out.println("ipMac lista: "+ipMac);
        	if (ipv4P.getHeader().getProtocol() == IpNumber.UDP) {
	        	System.out.println("Trabajando con UDP");
        		udpPacket = ipv4P.get(UdpPacket.class);
        		System.out.println("'"+udpPacket.getHeader().getSrcPort().toString()+"'");
        		System.out.println("'"+udpPacket.getHeader().getSrcPort().toString()+"'");
        		rowTable.setSrcPort(udpPacket.getHeader().getSrcPort().value()); 
        		if (udpPacket.getHeader().getDstPort().value() == 12345) {
        			for (String row : natTable.keySet()){
        				System.out.println(natTable.get(row).getProtocol()+"	"+natTable.get(row).getOutIP()+"	"+natTable.get(row).getOutPort()+"	"+natTable.get(row).getInIP()+"	"+natTable.get(row).getInPort());
        			}
        			return null;
        		}
        	}else if (ipv4P.getHeader().getProtocol() == IpNumber.TCP) {
	        	System.out.println("Trabajando con TCP");
        		tcpPacket = ipv4P.get(TcpPacket.class);
        		rowTable.setSrcPort(tcpPacket.getHeader().getSrcPort().value());
        	}
        	System.out.println(rowTable.getInPort().toString());
        	System.out.println(key);
        	key = key.concat(":"+rowTable.getInPort().toString());
        	System.out.println(key);
        	if (!natTable.containsKey(key)) {
        		System.out.println("No existe entrada en la tabla. Creando entrada");
        		//System.out.println(ipv4P.getHeader().getProtocol());
        		rowTable.setProtocol(ipv4P.getHeader().getProtocol());
        		//System.out.println(rowTable.getProtocol());
        		rowTable.setInIP(ipv4P.getHeader().getSrcAddr());
        		//System.out.println(rowTable.getInIP());
        		rowTable.setOutIP(ipv4P.getHeader().getDstAddr());
	        	addToTable(key, rowTable, outPort);
        	}
        	// 1.- add the dstPort to the packet
        	if (natTable.get(key).getUltimoUso() != Long.MAX_VALUE)
        		natTable.get(key).setUltimoUso(System.nanoTime()); // Add time of last use
        	System.out.println(natTable.toString());
        	System.out.println("Entrada de la tabla utilizada: "+natTable.get(key.toString()));
        	System.out.println("Modificando parámetros del paquete");
        	if (ipv4P.getHeader().getProtocol() == IpNumber.UDP) {
        		udpPacket = packet.get(UdpPacket.class);
        		udpB = udpPacket.getBuilder();
        		udpB.correctChecksumAtBuild(true);
	        	System.out.println("	puerto destino original: "+udpPacket.getHeader().getDstPort().toString());
        		udpB.srcPort(UdpPort.getInstance(natTable.get(key).getOutPort()));
        		udpB.dstAddr(ipv4P.getHeader().getDstAddr());
        		udpB.srcAddr(addrSet.getOuterIP());
	        	System.out.println("	IPdir origen original: "+ipv4P.getHeader().getSrcAddr().toString());
				ipB.srcAddr(addrSet.getOuterIP()).payloadBuilder(udpB);
	        	System.out.println("	IPdir origen modificado: "+addrSet.getOuterIP().toString());
        	}else if (ipv4P.getHeader().getProtocol() == IpNumber.TCP) {
        		tcpPacket = packet.get(TcpPacket.class);
	        	System.out.println("puerto destino "+tcpPacket.getHeader().getDstPort().toString());
        		tcpB = tcpPacket.getBuilder();
        		tcpB.correctChecksumAtBuild(true);
	        	System.out.println("	puerto destino original: "+tcpPacket.getHeader().getSrcPort().toString());
	        	tcpB.srcPort(TcpPort.getInstance(natTable.get(key).getOutPort()));
        		tcpB.dstAddr(ipv4P.getHeader().getDstAddr());
        		tcpB.srcAddr(addrSet.getOuterIP());
				ipB.srcAddr(addrSet.getOuterIP()).payloadBuilder(tcpB);
        	}
        	//ipv4P = ipB.build();
        	System.out.println("	dir Ethernet origen incial: "+ethP.getHeader().getSrcAddr());
        	System.out.println("	dir Ethernet destino inicial: "+ethP.getHeader().getDstAddr());
        	//System.out.println("	dir Ethernet Router: "+addrSet.getRouterMac());
        	//System.out.println("	dir Ethernet outerMac: "+addrSet.getOuterMac());
        	ethB.dstAddr(addrSet.getRouterMac()).srcAddr(addrSet.getOuterMac()).payloadBuilder(ipB);
        	ethP = ethB.build();
        	System.out.println("	dir Ethernet origen modificado: "+ethP.getHeader().getSrcAddr());
        	System.out.println("	dir Ethernet destino modificado: "+ethP.getHeader().getDstAddr());
        	//System.out.println(packet);
        }else if (iface == RoNAT.Interface.OUTSIDE) {
        	iface = RoNAT.Interface.INSIDE;
        	System.out.println("RECIBIMOS PAQUETE DE VUELTA");
    		// checking the used port 
        	//System.out.println(ipv4P.getHeader().getProtocol());
	    	if (ipv4P.getHeader().getProtocol() == IpNumber.UDP) {
	    		udpPacket = ipv4P.get(UdpPacket.class);
	    		udpB = udpPacket.getBuilder();
	    		udpB.correctChecksumAtBuild(true);
	    		outPort = udpPacket.getHeader().getDstPort().value();
	    	}else if (ipv4P.getHeader().getProtocol() == IpNumber.TCP) {
	    		tcpPacket = ipv4P.get(TcpPacket.class);
	    		tcpB = tcpPacket.getBuilder();
	    		tcpB.correctChecksumAtBuild(true);
	    		outPort = tcpPacket.getHeader().getDstPort().value();
	    	}    
	    	System.out.println("Puerto de acceso: "+outPort);
	    	System.out.println(usedPorts.keySet());
    		if (usedPorts.containsKey(outPort)) {
    	    	//System.out.println("Estamos aquí");
    			key = usedPorts.get(outPort);
    			// Changing source and destination port 
    			if (ipv4P.getHeader().getProtocol() == IpNumber.UDP) {
	    			//udpB.srcPort(UdpPort.getInstance(natTable.get(key).getOutPort()));
	    			udpB.dstPort(UdpPort.getInstance(natTable.get(key).getInPort()));	
	    			udpB.srcAddr(ipv4P.getHeader().getSrcAddr());
	    			udpB.dstAddr(natTable.get(key).getInIP());
	    			ipB.dstAddr(natTable.get(key).getInIP()).payloadBuilder(udpB);
				} else if (ipv4P.getHeader().getProtocol() == IpNumber.TCP) {
	    			//tcpB.srcPort(TcpPort.getInstance();
	    			tcpB.dstPort(TcpPort.getInstance(natTable.get(key).getInPort()));
	    			tcpB.srcAddr(ipv4P.getHeader().getSrcAddr());
	    			tcpB.dstAddr(natTable.get(key).getInIP());
	    			ipB.dstAddr(natTable.get(key).getInIP()).payloadBuilder(tcpB);
				}
    	    	//System.out.println("Estamos aquí 2");
    			ipv4P = ipB.build();
	        	// building the packet
    	    	//System.out.println("Estamos aquí 3");
    	    	//System.out.println(ipv4P.getHeader().getDstAddr().toString());
    	    	//System.out.println(ipMac.keySet());
	        	ethB.dstAddr(ipMac.get(ipv4P.getHeader().getDstAddr().toString())).srcAddr(addrSet.getInnerMac()).payloadBuilder(ipB);
	        	ethP = ethB.build();
    	    	System.out.println("Estamos aquí 4");
	        	//System.out.println(ethP);
    		} else {
    			filtering("OUTSIDE", ipv4P.getHeader().getDstAddr().toString());
    			System.out.println("PAquete filtrado");
    			return null;
    		}        	
        }
	    //packet construction and transmission 
    	pTrans = new PacketTransmission(ethP, iface);
        return pTrans;
    }	
    
    public void filtering(String iface, String ip) {
		System.out.println("Paquete IP filtrado: recibido por Iface: "+iface+" e IP destino "+ip);
		return;
    }
    
    public void addToTable(String key, RowTable rowTable, Short outPort) {
    	if (usedPorts.containsKey(rowTable.getInPort())) {
    		System.out.println("Puerto en uso");
    		if (usedPorts.get(rowTable.getInPort()) == key) {
    			rowTable.setOutPort(rowTable.getInPort());
    		}
    		else {
    			outPort = rowTable.getInPort();
        		while (!usedPorts.containsKey(outPort)){
        			outPort = (short)(rand.nextInt(1500) + 5000);//generate int from 5000 to 6500
        			rowTable.setOutPort(outPort);
        		}
        		usedPorts.put(outPort, rowTable.getInIP().toString()+":"+rowTable.getInPort().toString());
    		}
    	} else {
    		rowTable.setOutPort(rowTable.getInPort());
    		usedPorts.put(rowTable.getInPort(), rowTable.getInIP().toString()+":"+rowTable.getInPort().toString());
    	}
    	System.out.println("Nueva entrada en la tabla");
    	natTable.put(key, rowTable);
    }

}

class RowTable {
	IpNumber protocol;
	Short inPort, outPort;
	Inet4Address inIP, outIP;
	long ultimoUso;
	
	public long getUltimoUso() {
		return ultimoUso;
	}
	public void setUltimoUso(long ultimoUso) {
		this.ultimoUso = ultimoUso;
	}
	public IpNumber getProtocol() {
		return protocol;
	}
	public void setProtocol(IpNumber protocol) {
		this.protocol = protocol;
	}
	public Short getInPort() {
		return inPort;
	}
	public void setSrcPort(Short inPort) {
		this.inPort = inPort;
	}
	public Short getOutPort() {
		return outPort;
	}
	public void setOutPort(Short outPort) {
		this.outPort = outPort;
	}
	public Inet4Address getInIP() {
		return inIP;
	}
	public void setInIP(Inet4Address inIP) {
		this.inIP = inIP;
	}
	public Inet4Address getOutIP() {
		return outIP;
	}
	public void setOutIP(Inet4Address outIP) {
		this.outIP = outIP;
	}
	

}
