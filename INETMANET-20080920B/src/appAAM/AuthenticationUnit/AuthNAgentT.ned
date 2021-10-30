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

package inet.appAAM.AuthenticationUnit;

//
// TODO auto-generated module
import inet.applications.tcpapp.TCPApp;
//



simple AuthNAgentT like TCPApp
{
	parameters:
	    
	    int AuthnManPort;
        int localAuthnAgentPort; // if -1, app doesn't bind in UDP
        int messageLength @unit("B"); // length of messages to generate, in bytes
        string AuthNMANAddr = default(""); // list of \IP addresses, separated by spaces

        double AWaitInterval @unit("s");
        volatile double time_begin @unit("s");// begin transmission time  should usually be a random value, e.g. exponential(1)
        int GeneratorSeed; // for random generator 

        volatile int numRequestsPerSession = default(1);  // number of requests sent per session
        volatile int requestLength @unit(B) = default(200B); // length of a request
        volatile int replyLength @unit("B") = default(1MB); // length of a reply
        volatile double thinkTime @unit("s"); // time gap between requests
        volatile double idleInterval @unit(s); // time gap between sessions
        volatile double reconnectInterval @unit("s") = default(30s);  // if connection breaks, waits this much before trying to reconnect
      
        @display("i=block/user");
    gates:
        input tcpIn;
        output tcpOut;
}
