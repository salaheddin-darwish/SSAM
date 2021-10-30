// Copyright (C) 2015 Salaheddin Darwish; Department of Computer Science, Brunel University London, UK
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

package inet.appAAM.TrafMan;

//
// TODO auto-generated module
//
simple TraffGenHostMan
{
        @class("TraffGenHostMan");
        
        bool SingOrMultiSrv = default (true) ; // true : calling only one Source , false calling Multi-Sources
        int MultiNumNum = default (2); // Multi-Serv Number if SingOrMultiSrv is true
        
        bool WaitingEnable  = default (false); // enable a Expiry Timer for calling Source Server
        double WaitTime = default (60s) @unit("s"); // 
        int MaxReqNum = default (1);        
        
        volatile int ReqPacketSize @unit("B")= default(1024B);
        volatile double TrigTime = default(3s) @unit("s");    // second     
        
        int Protocol = default(6); // 6:TCP, 17: UDP 
        
        double WaitingTrafficWindow = default (400) ; 
        
    //    xml trafConfig;
    gates:
        input lowergateIn;
        output lowergateOut;
}
