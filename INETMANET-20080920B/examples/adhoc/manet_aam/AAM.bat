//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

package inet.examples.adhoc.manet_aam;

import inet.examples.adhoc.manet_aam.ServiceAndSecurityCoordinator.ServiceSecurityCoordinator;

import inet.appAAM.AuthenticationUnit.AuthNManager;


import inet.appAAM.AuthorisationManager.authorisationManager;

import inet.appAAM.TrustManager.trustManager;

import inet.appAAM.ResourceManager.resourceManager;

//
// TODO auto-generated module
//
module AAM

{
    @display("bgb=624,207");

    gates:

        input tolowerlayer;


    submodules:

        SSCoordinator: ServiceSecurityCoordinator {
            @display("p=476,89");
        }

        AuthenticationManager: authenticationManager {
            @display("p=360,149");
        }

        AuthorisationManager: authorisationManager {
            @display("p=551,149");
        }

        TrustManager: trustManager {
            @display("p=360,33");
        }

        ResourceManager: resourceManager {
            @display("p=551,33");
        }


    connections allowunconnected:

        SSCoordinator.fromtoAuthenticationManager <--> { @display("ls=,,s"); } <--> AuthenticationManager.toAuthenticationfromSSC;
        SSCoordinator.fromtoAuthorisationManager <--> AuthorisationManager.touthorisationfromSSC;
        SSCoordinator.fromtoTrustManager <--> TrustManager.toTrustManagerfromSSC;
        SSCoordinator.fromtoResourceManger <--> ResourceManager.toResourceManagerfromSSC;

        AuthenticationManager.toAuthenticationfromTrustManager <--> TrustManager.toTrustManagerfromAuthenMan;

}
