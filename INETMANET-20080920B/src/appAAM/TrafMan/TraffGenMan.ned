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
simple TraffGenMan
{
        @class("TraffGenMan");
        bool isSink = default(true); // if true the node doesn't send traffic
        volatile int packetSize @unit("B")= default(10B);
	    volatile double interDepartureTime @unit("s") = default(exponential(1s));
	    volatile double firstPacketTime @unit("s")= default(5s);
	    string   trafDest =  default("");
	    bool      onIdenticalTrafDest = default (false);
	    volatile double onLength @unit("s")= default(0s);
	    volatile double offLength @unit("s")= default(0s);
	    volatile double offInterDepartureTime @unit("s")= default(0s);	    
	    int Protocol = default (6); // 6:TCP, 17: UDP 
	    bool selfActivation = default (true) ; 
    //    xml trafConfig;
    gates:
        input lowergateIn;
        output lowergateOut;
}
