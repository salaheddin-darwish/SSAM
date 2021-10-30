//
// Copyright (C) 2005 Andras Varga
// Copyright (C) 2011-2015 Salaheddin Darwish; Department of Computer Science, Brunel University London, UK 
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

package inet.examples.adhoc.manet_aam;

import inet.world.ChannelControl;
import inet.networklayer.autorouting.FlatNetworkConfigurator;
//import inet.networklayer.autorouting.NetworkConfigurator;
import inet.nodes.adhoc.MobileHost;
import inet.nodes.adhoc.MobileManetRoutingHost_AAM;



network Net_Manet_AAM_
{
    parameters:
        int numHosts;
        double playgroundSizeX;
        double playgroundSizeY;
      
    submodules:

        channelcontrol: ChannelControl {
            parameters:
                coreDebug = true;
                playgroundSizeX = playgroundSizeX;
                playgroundSizeY = playgroundSizeY;
                @display("p=54,135;i=misc/sun");
        }
        configurator: FlatNetworkConfigurator {
            parameters:
                networkAddress = "145.236.0.0";
                netmask = "255.255.0.0";
                @display("p=54,60;i=block/cogwheel_s");
        }

//      configurator: NetworkConfigurator {
//            parameters:
////                networkAddress = "145.236.0.0";
////                netmask = "255.255.0.0";
//                @display("p=54,60;i=block/cogwheel_s");
//        }

           host[numHosts]: MobileManetRoutingHost_AAM {
            parameters:
                @display("i=device/pocketpc_s;r=50,,grey71,1;is=s");
        }


    connections allowunconnected:
}


