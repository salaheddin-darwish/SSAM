// Copyright (C) 2011-2015 Salaheddin Darwish; Department of Computer Science, Brunel University London, UK
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
simple TraffGenSrMan
{
    
    volatile double interDepartureTime @unit("s") = default(exponential(0.5s));  
    volatile double firstPacketTime @unit("s") = default(1s);
    
    volatile double onLength @unit("s") = default(0s);
    volatile double offLength @unit("s") = default(0s);
    
    int Protocol = default(6); // 6:TCP, 17: UDP 
    double prsumSessionlength 	= default(normal(3s,1s)) @unit("s");   // Session Length for all request     
    int packetSize @unit("B")	= default(800B);
    int HandledSrvNum 			= default (1) ; //  Number of Servers handled at Once 
    bool SendDelayedFlag 		= default (false) ;
    double SendDelayedVal  		= default(0.001s) @unit("s"); 
    int TrafPatType 			= default (0); // 0: Session Based Patterns , 1 : Number of Flows
    int MaxFlowNum 				= default (5) ; // if TrafPatType  =  , take MaxFlowNum as number of msg should be sent;
    
    gates:
        input lowergateIn;
        output lowergateOut;
}
