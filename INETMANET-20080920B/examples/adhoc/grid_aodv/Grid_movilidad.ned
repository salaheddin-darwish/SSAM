//
// Copyright (C) 2005 Andras Varga
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
//


package inet.examples.adhoc.grid_aodv;

import inet.networklayer.autorouting.FlatNetworkConfigurator;
import inet.nodes.adhoc.MobileHost;
import inet.nodes.adhoc.FixManetRoutingHost;
import inet.nodes.adhoc.MobileManetRoutingHost;

import inet.world.ChannelControl;

network Grid_movilidad
{
    parameters:
        int numHosts;
        double playgroundSizeX;
        double playgroundSizeY;
    submodules:
        host[numHosts]: MobileManetRoutingHost {
            parameters:
                //	nodeId = index;
               // @display("i=device/pocketpc_s;r=,,#707070");
                
                //        host[numHosts]: MobileManetRoutingHost {
         //   parameters:
                @display("i=device/pocketpc_s;r=100,,grey71,1;is=n");
        //}
        }
        channelcontrol: ChannelControl {
            parameters:
                playgroundSizeX = playgroundSizeX;
                playgroundSizeY = playgroundSizeY;
                @display("p=33,28;i=misc/sun");
        }
        configurator: FlatNetworkConfigurator {
            parameters:
                networkAddress = "145.236.0.0";
                netmask = "255.255.0.0";
                @display("p=140,50;i=block/cogwheel_s");
        }
    connections allowunconnected:
}

