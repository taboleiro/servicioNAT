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
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4CommonPacket.Builder;
import org.pcap4j.packet.IcmpV4EchoPacket;
import org.pcap4j.packet.IcmpV4EchoReplyPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IcmpV4Type;
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
    	RowTable rowTable = new RowTable();
    	String key = "";
    	Short outPort = 0;
    	Inet4Address srcAddr, dstAddr = null; 
    	Short srcPort, dstPort = 0;
    	EthernetPacket ethP;
    	EthernetPacket.Builder ethB;
    	IpV4Packet ipv4P = null;
    	IpV4Packet.Builder ipB = null;
    	UdpPacket udpPacket = null;
    	UdpPacket.Builder udpB = null;
    	TcpPacket tcpPacket = null;
    	TcpPacket.Builder tcpB = null;
    	IcmpV4CommonPacket icmpPacket = null;
    	Builder icmpB = null;
    	Boolean synFlag = true, synFin = false, prueba = true;
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
	    			rowTable.setOutIP(addrSet.getOuterIP());
	    			rowTable.setInIP((Inet4Address)InetAddress.getByName(parameters[2]));
	    			rowTable.setInPort(Short.parseShort(parameters[3]));
	    			rowTable.setUltimoUso(Long.parseLong("0"));
	    			key = rowTable.getInIP().toString()+":"+rowTable.getInPort();
	    			addToTable(key, rowTable, outPort);
	    			rowTable = new RowTable();
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
        } else if(ethP.getHeader().getType() == EtherType.ARP){
        	System.out.println("Paquete ARP: recibido por Iface: "+iface);
        	return null;
        }
    	// checking expiration of the rows of the nat table
    	if (cleanTime < System.currentTimeMillis() - 30000) {
	    	for (String keys: natTable.keySet()) {
	    		if (natTable.get(keys).getUltimoUso() < System.currentTimeMillis() - 60000 && natTable.get(keys).getUltimoUso() > 0) {
	    			if (usedPorts.containsKey(natTable.get(keys).getOutPort()))
	    				usedPorts.remove(natTable.get(keys).getOutPort());     			
	    			natTable.remove(keys);
	    		}
	    	}
	    }
        cleanTime = System.currentTimeMillis();
        if (iface == RoNAT.Interface.INSIDE) {
        	iface = RoNAT.Interface.OUTSIDE;
        	// Obtención de los datos para tabla de reenvío
        	if (ipv4P.getHeader().getDstAddr().toString().contains("/224.") ||
        		ipv4P.getHeader().getDstAddr().equals(addrSet.getInnerIP())) {
        		filtering("INSIDE", ipv4P.getHeader().getDstAddr().toString());
        		return null; 
        	}
        	key = ipv4P.getHeader().getSrcAddr().toString();
        	if (ipMac.containsKey(key)){
        		if (ipMac.get(key) != ethP.getHeader().getSrcAddr()) {
        			ipMac.put(key, ethP.getHeader().getSrcAddr());
        		}
        	} else {
        		ipMac.put(key, ethP.getHeader().getSrcAddr());
        	}
        	if (ipv4P.getHeader().getProtocol() == IpNumber.UDP) {
        		udpPacket = ipv4P.get(UdpPacket.class);
        		rowTable.setInPort(udpPacket.getHeader().getSrcPort().value()); 
        		if (udpPacket.getHeader().getDstPort().value() == 12345) {
        			for (String row : natTable.keySet()){
        				System.out.println(natTable.get(row).getProtocol()
	        						+"	"+natTable.get(row).getOutIP()
	        						+"	"+natTable.get(row).getOutPort()
	        						+"	"+natTable.get(row).getInIP()
	        						+"	"+natTable.get(row).getInPort()
	        						+"	"+natTable.get(row).getUltimoUso());
        			}
        			return null;
        		}
        	}else if (ipv4P.getHeader().getProtocol() == IpNumber.TCP) {
        		tcpPacket = ipv4P.get(TcpPacket.class);
        		rowTable.setInPort(tcpPacket.getHeader().getSrcPort().value());
        		if (!tcpPacket.getHeader().getSyn())
        			synFlag = false;
        		if (tcpPacket.getHeader().getFin()) {
        			natTable.get(key).setUltimoUso(natTable.get(key).getUltimoUso() - 40000);
        			synFin = true;
        		}
        	}
        	if (ipv4P.getHeader().getProtocol() == IpNumber.ICMPV4) {
        		icmpPacket = ethP.get(IcmpV4CommonPacket.class);
        		if (icmpPacket.getHeader().getType() == IcmpV4Type.ECHO) {
	        		IcmpV4EchoPacket icmpP = ethP.get(IcmpV4EchoPacket.class);
	        		rowTable.setInPort(icmpP.getHeader().getIdentifier());
        		}
        		else {
        			return null;
        		}
        	}
        	key = key.concat(":"+rowTable.getInPort().toString());
        	if (!natTable.containsKey(key) && synFlag) {
        		rowTable.setProtocol(ipv4P.getHeader().getProtocol());
        		rowTable.setInIP(ipv4P.getHeader().getSrcAddr());
        		rowTable.setOutIP(ipv4P.getHeader().getDstAddr());
	        	addToTable(key, rowTable, outPort);
        	}
        	if (natTable.get(key).getUltimoUso() != 0 && !synFin)
        		natTable.get(key).setUltimoUso(System.currentTimeMillis()); // Add time of last use
        	if (ipv4P.getHeader().getProtocol() == IpNumber.UDP) {
        		udpPacket = packet.get(UdpPacket.class);
        		udpB = udpPacket.getBuilder();
        		udpB.correctChecksumAtBuild(true);
        		udpB.srcPort(UdpPort.getInstance(natTable.get(key).getOutPort()));
        		udpB.dstAddr(ipv4P.getHeader().getDstAddr());
        		udpB.srcAddr(addrSet.getOuterIP());
				ipB.srcAddr(addrSet.getOuterIP()).payloadBuilder(udpB);
        	}else if (ipv4P.getHeader().getProtocol() == IpNumber.TCP) {
        		tcpPacket = packet.get(TcpPacket.class);
        		tcpB = tcpPacket.getBuilder();
        		tcpB.correctChecksumAtBuild(true);
	        	tcpB.srcPort(TcpPort.getInstance(natTable.get(key).getOutPort()));
        		tcpB.dstAddr(ipv4P.getHeader().getDstAddr());
        		tcpB.srcAddr(addrSet.getOuterIP());
				ipB.srcAddr(addrSet.getOuterIP()).payloadBuilder(tcpB);
        	} else if (ipv4P.getHeader().getProtocol() == IpNumber.ICMPV4) {
        		IcmpV4CommonPacket icmpP = packet.get(IcmpV4CommonPacket.class);
        		icmpB = icmpP.getBuilder();
        		icmpB.correctChecksumAtBuild(true);
    			IcmpV4EchoPacket.Builder icmpEchoB = icmpP.get(IcmpV4EchoPacket.class).getBuilder();
    			icmpEchoB.identifier(natTable.get(key).getOutPort());
        		icmpB.payloadBuilder(icmpEchoB);
        		ipB.srcAddr(addrSet.getOuterIP()).payloadBuilder(icmpB);
        	}
        	ethB.dstAddr(addrSet.getRouterMac()).srcAddr(addrSet.getOuterMac()).payloadBuilder(ipB);
        	ethP = ethB.build();
        }else if (iface == RoNAT.Interface.OUTSIDE) {
        	iface = RoNAT.Interface.INSIDE;
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
	    	}else if (ipv4P.getHeader().getProtocol() == IpNumber.ICMPV4) {
	    		icmpPacket = ipv4P.get(IcmpV4CommonPacket.class);
	    		icmpB = icmpPacket.getBuilder();
	    		icmpB.correctChecksumAtBuild(true);
	    		if (icmpPacket.getHeader().getType() == IcmpV4Type.ECHO_REPLY) {
	    			outPort = icmpPacket.get(IcmpV4EchoReplyPacket.class).getHeader().getIdentifier();
	    		} else {
	    			return null;
	    		}
	    	}
    		if (usedPorts.containsKey(outPort)) {
    			key = usedPorts.get(outPort);
    			// Changing source and destination port 
    			if (ipv4P.getHeader().getProtocol() == IpNumber.UDP) {
	    			udpB.dstPort(UdpPort.getInstance(natTable.get(key).getInPort()));	
	    			udpB.srcAddr(ipv4P.getHeader().getSrcAddr());
	    			udpB.dstAddr(natTable.get(key).getInIP());
	    			ipB.dstAddr(natTable.get(key).getInIP()).payloadBuilder(udpB);
				} else if (ipv4P.getHeader().getProtocol() == IpNumber.TCP) {
	    			tcpB.dstPort(TcpPort.getInstance(natTable.get(key).getInPort()));
	    			tcpB.srcAddr(ipv4P.getHeader().getSrcAddr());
	    			tcpB.dstAddr(natTable.get(key).getInIP());
	    			ipB.dstAddr(natTable.get(key).getInIP()).payloadBuilder(tcpB);
				} else if (ipv4P.getHeader().getProtocol() == IpNumber.ICMPV4) {
					IcmpV4EchoReplyPacket.Builder icmpReplyB = icmpPacket.get(IcmpV4EchoReplyPacket.class).getBuilder();
					icmpReplyB.identifier(natTable.get(key).getInPort());
					icmpB.payloadBuilder(icmpReplyB).correctChecksumAtBuild(true);
	    			ipB.dstAddr(natTable.get(key).getInIP()).payloadBuilder(icmpB);
				}
    			ipv4P = ipB.build();
	        	ethB.dstAddr(ipMac.get(ipv4P.getHeader().getDstAddr().toString())).srcAddr(addrSet.getInnerMac()).payloadBuilder(ipB);
	        	ethP = ethB.build();
    		} else {
    			filtering("OUTSIDE", ipv4P.getHeader().getDstAddr().toString());
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
    	natTable.put(key, rowTable);
    }

}

class RowTable {
	IpNumber protocol;
	Short inPort, outPort;
	Inet4Address inIP, outIP;
	long ultimoUso = Long.parseLong("1");
	/*
	public RowTable(IpNumber protocol, Short inPort, Inet4Address inIP, Short outPort, Inet4Address outIP, Long ultimoUso) {
		this.protocol = protocol;
		this.inPort = inPort;
		this.inIP = inIP;
		this.outPort = outPort;
		this.outIP = outIP;
		this.ultimoUso = ultimoUso;
	}*/
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
	public void setInPort(Short inPort) {
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
