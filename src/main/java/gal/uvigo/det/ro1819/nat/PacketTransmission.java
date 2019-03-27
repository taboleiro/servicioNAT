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

import org.pcap4j.packet.Packet;

import gal.uvigo.det.ro1819.nat.RoNAT.Interface;

public class PacketTransmission {
    private Packet packet;
    private Interface transmissionIface;   

    PacketTransmission(Packet p, Interface iface) {
	this.packet=p;
	this.transmissionIface = iface;
    }
    
    /**
     * @return the packet
     */
    public Packet getPacket() {
	return packet;
    }

    /**
     * @return output Interface
     */
    public Interface getTxInterface() {
	return transmissionIface;
    } 
}
