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

package inet.mobility;

//
// Steady State Random Waypoint mobility model.
//
// The node moves in line segments. For each line segment, a random destination
// position (distributed uniformly over the playground) and a random speed
// is chosen. You can define a speed as a variate from which a new value
// will be drawn for each line segment; it is customary to specify it as
// uniform(minSpeed, maxSpeed). When the node reaches the target position,
// it waits for the time waitTime which can also be defined as a variate.
// After this time the the algorithm calculates a new random position, etc.
//
// This model was written by Georg Lutz (GeorgLutz AT gmx DOT de) for his
// diploma thesis "Effizientes Modell fuer Funkverbindungen in 4G-Netzen fuer
// OMNeT++" (Efficient model for radio links in 4G networks for OMNeT++)
// at Institut fuer Telematik, Universitaet Karlsruhe (Institute for
// Telematics, University Karlsruhe, Germany), 2005-06-21. Slightly modified
// by Andras Varga 2005.06.22.
//
// @author Salaheddin Darwish

simple SteadyStateRandomWPMobility like BasicMobility
{
        parameters:
        bool debug = default(false); // debug switch
        double x = default(-1); // start x coordinate (-1 = display string position, or random if it's missing)
        double y = default(-1); // start y coordinate (-1 = display string position, or random if it's missing)
        double updateInterval @unit("s") = default(0.1s);
        
        volatile double speedMean @unit("mps")	= default(0mps); // the mean of node speead 
        volatile double speedDelta @unit("mps")	= default(0.5mps);// Speed Standard Deviation 
		volatile double pauseMean  @unit("s") 	= default(40s); // mean of wait (called pause) time between reaching a target and choosing a new one
		volatile double pauseDelta @unit("s") 	= default(10s);
       
        bool logTrace = default (true) ; // save x , y cordinations in vectors
        @display("i=block/cogwheel_s");
}
