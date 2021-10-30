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

#ifndef __INET_HIP_STEADYSTATERANDOMWPMOBILITY_H_
#define __INET_HIP_STEADYSTATERANDOMWPMOBILITY_H_

#include <omnetpp.h>
#include "BasicMobility.h"
/**
 * TODO - Generated class
 */
class SteadyStateRandomWPMobility : public BasicMobility
{
  protected:
    bool nextMoveIsWait;
    cOutVector * mTraceX;
    cOutVector * mTraceY;
    double pauseTime, speed;
    double speedLow, pauseLow, speedRange, pauseRange;
    cDisplayString* display_string ;
    // config
    double updateInterval; ///< time interval to update the host's position

    // state
    simtime_t targetTime;  ///< end time of current linear movement
    Coord targetPos;       ///< end position of current linear movement
    Coord step;            ///< step size (added to pos every updateInterval)
    bool stationary;       ///< if set to true, host won't move
    bool StPauseFlg;

  protected:
    /** @brief Initializes mobility model parameters.*/
    virtual void initialize(int);

    /** @brief Overridden from LineSegmentsMobilityBase.*/
    virtual void setTargetPosition();

    /** @brief Overridden from LineSegmentsMobilityBase.*/
    virtual void fixIfHostGetsOutside();

    /** @brief Begin new line segment after previous one finished */
    virtual void beginNextMove(cMessage *msg);

    /** @brief Called upon arrival of a self messages*/
    virtual void handleSelfMsg(cMessage *msg);

    virtual void finish();

};

#endif
