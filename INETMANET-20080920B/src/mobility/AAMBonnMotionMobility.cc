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

#include "AAMBonnMotionMobility.h"
#include "BonnMotionFileCache.h"
#include "FWMath.h"

#define CurrentRunNumber ev.getConfigEx()->getActiveRunNumber()

Define_Module(AAMBonnMotionMobility);


void AAMBonnMotionMobility::initialize(int stage)
{
    LineSegmentsMobilityBase::initialize(stage);

    EV << "Initialising AAMBonnMotionMobility stage " << stage << endl;

    if (stage == 2)
    {

    	std::stringstream xfName;
    	display_string = &getParentModule()->getDisplayString();

    	StartPoint = simTime();
    	int nodeId = par("nodeId");
        if (nodeId == -1)
        {
        	if (!nodeIndx)
        	nodeId = RunId= getParentModule()->getIndex();
            else
            {
            nodeId = RunId =  BasicMobility::nodeIndx;
            }
        }


        xfName<<par("traceFile").stdstringValue()<<CurrentRunNumber<<".movements";

        const char *fname = xfName.str().c_str();

        const BonnMotionFile *bmFile = BonnMotionFileCache::getInstance()->getFile(fname);

        vecp = bmFile->getLine(nodeId);

        if (!vecp)
            error("invalid nodeId %d -- no such line in file '%s'", nodeId, fname);
        vecpos = 0;

        // obtain initial position
        const BonnMotionFile::Line& vec = *vecp;
        if (vec.size()>=3)
        {
            pos.x = vec[1];
            pos.y = vec[2];
            targetPos = pos;
            vecpos +=3;


            Coord targetPosTemp ; // next position
            targetPosTemp.x = vec[4];
            targetPosTemp.y = vec[5];

            if (targetPosTemp==pos)
              	display_string->setTagArg("i2", 0, "old/ball2_vs");
            else
            	display_string->setTagArg("i2", 0, "old/ball_vs");

        }
        updatePosition();
       // WATCH ((CurrentRunNumber);
        WATCH(StartPoint);
        WATCH(targetTime);
    }
}

AAMBonnMotionMobility::~AAMBonnMotionMobility()
{
  //  BonnMotionFileCache::deleteInstance();
}

void AAMBonnMotionMobility::setTargetPosition()
{
    const BonnMotionFile::Line& vec = *vecp;

    std::stringstream mNam;

    if (vecpos+2 >= (int)vec.size())
    {
        stationary = true;
        return;
    }

    targetTime = vec[vecpos]+StartPoint;
    targetPos.x = vec[vecpos+1];
    targetPos.y = vec[vecpos+2];
    vecpos += 3;

    if (targetPos==pos)
      	display_string->setTagArg("i2", 0, "old/ball2_vs");
    else
    	display_string->setTagArg("i2", 0, "old/ball_vs");

    EV << "TARGET: t=" << targetTime << " (" << targetPos.x << "," << targetPos.y << ")\n";
}

void AAMBonnMotionMobility::fixIfHostGetsOutside()
{
   // raiseErrorIfOutside();

   double angle = 0;

   handleIfOutside(REFLECT, targetPos, step, angle);
}

