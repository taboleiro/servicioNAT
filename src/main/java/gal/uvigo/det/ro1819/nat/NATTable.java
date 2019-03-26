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

import com.sun.tools.jdi.Packet;

import gal.uvigo.det.ro1819.nat.RoNAT.Interface;

/*
 * A clase NAT_Table é onde almacenaredes as asociacións inside/outside
 * necesarias para implementar a funcionalidade do NAT. E hai que tomar as
 * precaucións necesarias (synchonized!) porque será un obxecto compartido entre
 * os dous threads que atenden, respectivamente, as dúas interfaces do noso
 * router virtual.
*/

public interface NATTable {
    /* Aquí debedes incorporar o voso código, consultando e modificando a
     * tabla NAT (NATTable table) e modificandço, se ha lugar, os paquetes que
     * atravesan o noso router virtual. Todo paquete que abandone o router
     * virtual por algunha das súas interfaces debe set devolto por este
     * método.
    */		

    public Packet getOutputPacket(Packet packet, Interface iface);    
}
