//
// Copyright (C) 2006 Andras Varga
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


package inet.nodes.adhoc;

import inet.appAAM.TrafMan.TraffGenHostMan;
import inet.applications.pingapp.PingApp;
//import inet.applications.tcpapp.TCPApp;
import inet.applications.udpapp.UDPApp;
import inet.base.NotificationBoard;
import inet.mobility.BasicMobility;
import inet.linklayer.ieee80211.Ieee80211NicAdhoc;
import inet.linklayer.ieee80211.Ieee80211aNicAdhoc;
import inet.linklayer.ieee80211.Ieee80211gNicAdhoc;
import inet.networklayer.common.InterfaceTable;
import inet.networklayer.ipv4.RoutingTable;
import inet.nodes.inet.NetworkLayerGlobalArp;
//import inet.transport.tcp.TCP;
import inet.transport.udp.UDP;
import inet.networklayer.manetrouting.ManetRouting;
//import inet.battery.InetSimpleBattery;
import inet.appAAM.MainUnit.mainUnit;
//import inet.battery.BasicBattery;

//
// Models a mobile host with a wireless (802.11b) card in ad-hoc mode.
// This model contains the new IEEE 802.11 implementation, Ieee80211Nic,
// and IP, TCP and UDP protocols. The mobility model can be
// dynamically specified with the mobilityType parameter.
//
// @see MFMobileHost, WirelessHost
//
module MobileManetRoutingHost_AAM_F
{
    parameters:
        @node;
        //     string trafGenType;
        //int numTcpApps = default(0);
        int numUdpApps = default(0);
        //int numTrafGen = default(0);
        // string tcpAppType = default("");
        string udpAppType = default("");
        string routingFile = default("");
        string mobilityType = default("NullMobility");
        @display("i=device/pocketpc;bgb=395,372;is=l");
    gates:
        input radioIn @directIn;
    submodules:
       // battery: BatteryModule {
         //   parameters:
         //       @display("p=60,325;i=block/plug");

        //} -!>

        notificationBoard: NotificationBoard {
            parameters:
                @display("p=60,70");
        }
//        battery: InetSimpleBattery {
//            parameters:
//                @display("p=51,310;i=block/plug");
//        }

        interfaceTable: InterfaceTable {
            parameters:
                @display("p=60,154");
        }
        routingTable: RoutingTable {
            parameters:
                IPForward = true;
                routerId = "";
                routingFile = routingFile;
                @display("p=60,230");
        }
        //        tcpApp[numTcpApps]: <tcpAppType> like TCPApp {
        //            parameters:
        //                @display("p=170,47");
        //        }
        //        tcp: TCP {
        //            parameters:
        //                @display("p=179,161");
        //        }
        udpApp[numUdpApps]: <udpAppType> like UDPApp {
            parameters:
                @display("p=279,51");
        }
        udp: UDP {
            parameters:
                @display("p=279,143");
        }
        //                pingApp: PingApp {
        //                    parameters:
        //                        @display("p=370,219");
        //                }
        networkLayer: NetworkLayerGlobalArp {
            parameters:
                proxyARP = false;
                globalARP = true;
                @display("p=256,230;q=queue");
            gates:
                ifIn[1];
                ifOut[1];
        }
        manetrouting: ManetRouting {
            @display("p=153,230;i=block/network2");
        }
        wlan: Ieee80211gNicAdhoc {
            parameters:
                @display("p=256,310;q=queue");
        }
        mobility: <mobilityType> like BasicMobility {
            parameters:
                @display("p=153,301;i=block/cogwheel");
        }
        MainUnit: mainUnit {
            parameters:

                @display("p=357,301");
        }


        // battery module
        //   battery: BasicBattery {




        TraffGenHostMan: TraffGenHostMan {
            @display("p=175,137;i=block/source");
        }
    //        battery: InetSimpleBattery {
    //            parameters:
    //                @display("p=73,365;i=block/plug");
    //
    //        }
    connections allowunconnected:


        networkLayer.TCPOut --> TraffGenHostMan.lowergateIn;
        networkLayer.tcpIn <-- TraffGenHostMan.lowergateOut;

        for i=0..numUdpApps-1 {
            udpApp[i].udpOut --> udp.appIn++;
            udpApp[i].udpIn <-- udp.appOut++;
        }


        udp.ipOut --> networkLayer.udpIn;
        udp.ipIn <-- networkLayer.udpOut;

//        networkLayer.pingOut --> pingApp.pingIn;
//        networkLayer.pingIn <-- pingApp.pingOut;

//        networkLayer.pingOut --> trafGen.ipIn;
//        networkLayer.pingIn <-- trafGen.ipOut;


        networkLayer.MANETOut --> manetrouting.from_ip;
        networkLayer.MANETIn <-- manetrouting.to_ip;

        // connections to network outside
        radioIn --> wlan.radioIn;
        wlan.uppergateOut --> networkLayer.ifIn[0];
        wlan.uppergateIn <-- networkLayer.ifOut[0];

}

