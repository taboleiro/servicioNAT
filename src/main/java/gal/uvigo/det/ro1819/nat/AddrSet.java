/*
 * Copyright (C) 2019 Miguel Rodriguez Perez <miguel@det.uvigo.gal> and 
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

import org.pcap4j.util.MacAddress;

public class AddrSet {
    Inet4Address innerIP;
    // A tarxeta principal ten que estar configurada cunha ip secundaria (a externa do NAT!)
    Inet4Address outerIP;
    MacAddress innerMac;
    MacAddress outerMac;
    // A MAC destino dos paquetes tx pola interfaz externa ten ser a do router interno do host anfitrión
    MacAddress routerMac;

    AddrSet(Inet4Address innerIP, Inet4Address outerIP, MacAddress innerMac,
	    MacAddress outerMac, MacAddress routerMac) {
	this.innerIP = innerIP;
	this.outerIP = outerIP;
	this.innerMac = innerMac;
	this.outerMac = outerMac;
	this.routerMac = routerMac;
    }
    
    /**
     * @return the innerIP
     */
    public Inet4Address getInnerIP() {
	return innerIP;
    }

    /**
     * @return the outerIP
     */
    public Inet4Address getOuterIP() {
	return outerIP;
    }
    /**
     * @return the innerMac
     */
    public MacAddress getInnerMac() {
	return innerMac;
    }

    /**
     * @return the outerMac
     */
    public MacAddress getOuterMac() {
	return outerMac;
    }
    /**
     * @return the routerMac
     */
    public MacAddress getRouterMac() {
	return routerMac;
    }
        
}
