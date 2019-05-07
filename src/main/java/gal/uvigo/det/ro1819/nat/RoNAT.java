/*
 * Copyright (C) 2019 Miguel Rodríguez Pérez <miguel@det.uvigo.gal> and 
 *                    Raúl Rodríguez Rubio <rrubio@det.uvigo.es>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package gal.uvigo.det.ro1819.nat;

import java.net.Inet4Address;

import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.MacAddress;

public class RoNAT {
    public enum Interface {
		INSIDE,
		OUTSIDE
    };

    private static final String DEFAULTNETWORK = "10.99.100.0/24"; //MÁSCARA DE RED POR DEFECTO DE LOS EQUIPOS
    private static final String DEFAULTIIFACE = "tap0"; //INPUT INTERFACE
    private static final String DEFAULTOIFACE = "br0"; //OUTPUT INTERFACE
    private static final int SNAPSHOTLENGTH = 65536; // bytes   
    private static final int READTIMEOUT = 50; // mseg                   
    
    private static RoNAT self = null;
    
    private String localNetwork;
    private PcapNetworkInterface iiDev;
    private PcapNetworkInterface oiDev;
    private AddrSet addresses;
    
    /**
     * This function create a default RoNAT router
     * @param hostRouterMacAddr
     * @return
     * @throws PcapNativeException
     */
    public static RoNAT create(MacAddress hostRouterMacAddr) throws PcapNativeException {
    	return create(hostRouterMacAddr, DEFAULTNETWORK, DEFAULTIIFACE, DEFAULTOIFACE);
    }
    
    /**
     * Create a RoNAT router with different values than the default ones
     * @param hostRouterMacAddr
     * @param localNetwork
     * @param iiface
     * @param oiface
     * @return
     * @throws PcapNativeException
     */
    public static RoNAT create(MacAddress hostRouterMacAddr, String localNetwork, String iiface, String oiface)
	throws PcapNativeException {
		if (self == null) 	   
		    self = new RoNAT(hostRouterMacAddr, localNetwork, iiface, oiface);
	
		return self;	
    }

    /**
     * @param hostRouterMacAddr 
     * @param localNetwork 
     * @param iiface input Network device name
     * @param oiface output Network device name
     * @return O paquete modificado ou null se se quere filtrar o paquete.
     */
    private RoNAT(MacAddress hostRouterMacAddr, String localNetwork, String iiface, String oiface)
	throws PcapNativeException {
		this.localNetwork = localNetwork;
	
		iiDev = getNetworkDevice(iiface);		
		if (iiDev == null) {
		    System.err.println("Error abrindo interface " + iiface);
		    System.exit(1);
		}
		
		oiDev = getNetworkDevice(oiface);
		if (oiDev == null) {
		    System.err.println("Error abrindo interface " + oiface);
		    System.exit(1);
		}
	
		var laddr1 = iiDev.getAddresses();
		var laddr2 = oiDev.getAddresses();
		var lmac1 = iiDev.getLinkLayerAddresses();
		var lmac2 = oiDev.getLinkLayerAddresses();
		addresses = new AddrSet((Inet4Address) laddr1.get(0).getAddress(),
						 (Inet4Address) laddr2.get(1).getAddress(),
						 (MacAddress) lmac1.get(0),
						 (MacAddress) lmac2.get(0),
						 (MacAddress) hostRouterMacAddr);
	    }
	
	    
    private PcapNetworkInterface getNetworkDevice(String devname) throws PcapNativeException {
		var device = Pcaps.findAllDevs().stream().filter(dev -> devname.equals(dev.getName())).findAny();
	
		if (device.isPresent()) {
		    return device.get();		
		}
	
		return null;       
	    }
	
	    public AddrSet getAddresses() {
		return addresses;
    }
    
    public void execute(NATTable table) throws PcapNativeException, NotOpenException  {	
		final PcapHandle handleIn, sendHandleIn, handleOut, sendHandleOut;
		
		// Apertura dos dispositivos, obtención dos "handlers" e configuración dos filtros
		handleIn = iiDev.openLive(SNAPSHOTLENGTH, PromiscuousMode.PROMISCUOUS, READTIMEOUT);
		
		handleOut = oiDev.openLive(SNAPSHOTLENGTH, PromiscuousMode.PROMISCUOUS, READTIMEOUT);
		sendHandleIn = iiDev.openLive(SNAPSHOTLENGTH, PromiscuousMode.PROMISCUOUS, READTIMEOUT);
		sendHandleOut = oiDev.openLive(SNAPSHOTLENGTH, PromiscuousMode.PROMISCUOUS, READTIMEOUT);
	
	
		String filterIn = "((arp[6:2] = 2) and (ether dst " + Pcaps.toBpfString(addresses.getInnerMac())
		    + ")) or ip src net " + localNetwork; 
		handleIn.setFilter(filterIn, BpfCompileMode.OPTIMIZE);
		
		String dstHost = addresses.getOuterIP().getHostAddress();
		String filterOut = "((arp[6:2] = 2) and (ether dst " + Pcaps.toBpfString(addresses.getOuterMac())
		    + ")) or ip dst host " + dstHost; 
		handleOut.setFilter(filterOut, BpfCompileMode.OPTIMIZE);		
		
		var tIn = new PacketHandler(handleIn, sendHandleIn, sendHandleOut, Interface.INSIDE, table);
		tIn.start();
		
		var tOut = new PacketHandler(handleOut, sendHandleIn, sendHandleOut, Interface.OUTSIDE, table);
		tOut.start();
    } 
        
    private static class PacketHandler extends Thread {	
		private PcapHandle handleRX;
		private PcapHandle handleTxIn;
		private PcapHandle handleTxOut;
		private PacketListener listener;
		private NATTable table;
		private Interface iface;
		
		public PacketHandler(PcapHandle rx, PcapHandle txin, PcapHandle txout, Interface iface, NATTable NAT) {
		    handleTxIn = txin;
		    handleTxOut = txout;
		    handleRX = rx;
		    table = NAT;
		    this.iface = iface;
		}
		
		@Override
		public void run() {
		    listener = packet -> {	
		 		PacketTransmission pktTX = table.getOutputPacket(packet, iface);
				Packet newP = pktTX.getPacket();
			        Interface txIface = pktTX.getTxInterface();
		
				try {
				    if (newP != null) {			
					var handle = (txIface == RoNAT.Interface.INSIDE) ? handleTxIn : handleTxOut;
				    
					handle.sendPacket(newP);
				    }
				} catch (PcapNativeException | NotOpenException e) {
				    // TODO Auto-generated catch block
				    e.printStackTrace();
				    return;		  
				}
		    };
	
		    try {
		    	handleRX.loop(-1, this.listener);
		    } catch (PcapNativeException | InterruptedException | NotOpenException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		    } finally {		
				handleRX.close();
				handleTxIn.close();
				handleTxOut.close();
		    }
		}
    }        
} 
