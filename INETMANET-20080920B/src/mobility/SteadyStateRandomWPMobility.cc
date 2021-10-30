// **************************************************************************
// Copyright (C) 2011-2015 Salaheddin Darwish; Department of Computer Science, Brunel University London, UK 
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

#include <algorithm>   // min,max
#include "SteadyStateRandomWPMobility.h"
#include "FWMath.h"

Define_Module(SteadyStateRandomWPMobility);

void SteadyStateRandomWPMobility::initialize(int stage)
{
	display_string = &getParentModule()->getDisplayString();

	BasicMobility::initialize(stage);

    if (stage == 1)
    {
    	EV << "initializing Steady State Random WayPoint Mobility stage " << stage << endl;

        stationary = (double)par("speedMean") == 0;
        updateInterval = par("updateInterval");
        targetTime = simTime();

        //nextMoveIsWait = false;


    	double u1,r;
    	double x1,y1,x2,y2;
    	cMessage * Timer;
    	std::stringstream msgName;

    	//steady-state initial positions
      do
      {
    	x1 = uniform( 0.0, getPlaygroundSizeX() );
    	y1 = uniform( 0.0, getPlaygroundSizeY() );
        x2 = uniform( 0.0, getPlaygroundSizeX() );
      	y2 = uniform( 0.0, getPlaygroundSizeY());

        r = sqrt(pow(x1-x2,2)+pow(y1-y2,2))/sqrt(pow(getPlaygroundSizeX(),2)+pow(getPlaygroundSizeY(),2));
        u1 = uniform( 0.0, 1.0 );
      }
      while ( u1 >= r );

      double u2 = uniform( 0.0, 1.0 );

      pos.x = u2*x1 + (1-u2)*x2;
      pos.y = u2*y1 + (1-u2)*y2;

      targetPos.x = x2;
      targetPos.y = y2;

      StPauseFlg = false;

      updatePosition();

      speedLow = par("speedMean").doubleValue() - par("speedDelta").doubleValue();
      pauseLow = par("pauseMean").doubleValue() - par("pauseDelta").doubleValue();
      speedRange = 2*par("speedDelta").doubleValue();
      pauseRange = 2*par("pauseDelta").doubleValue();

      //calculate the steady-state probability that a node is initially paused
      double expectedPauseTime=par("pauseMean").doubleValue();

      double a =getPlaygroundSizeX();
      double b =getPlaygroundSizeY();

      double v0	= speedLow;
      double v1	= par("speedMean").doubleValue() + par("speedDelta").doubleValue();

      double log1=b*b/a*log(sqrt((a*a)/(b*b) + 1) + a/b);
      double log2=a*a/b*log(sqrt((b*b)/(a*a) + 1) + b/a);
      double expectedTravelTime=1.0/6.0*(log1 + log2);
      expectedTravelTime+=1.0/15.0*((a*a*a)/(b*b) + (b*b*b)/(a*a)) -
                          1.0/15.0*sqrt(a*a + b*b)*((a*a)/(b*b) + (b*b)/(a*a) - 3);

      if(par("speedDelta").doubleValue()==0.0)
        expectedTravelTime/=par("speedMean").doubleValue();
      else
        expectedTravelTime*=log(v1/v0)/(v1 - v0);

        double probabilityPaused = expectedPauseTime/(expectedPauseTime + expectedTravelTime);

      //printf(stderr,"Speed Range: (%f, %f)\nPause Time Range: (%f, %f)\nNetwork Dimensions: (%f, %f)\nexpectedTravelTime: %f\nexpectedPauseTime: %f\n\nInitial Values:\nSpeed: X-Location: Y-Location: Pause Time:\n",speedLow,speedLow+speedRange,pauseLow,pauseLow+pauseRange,maxX,maxY,expectedTravelTime,expectedPauseTime);
      //these are used for steady-state initial pause times

        double t1=pauseLow;
        double t2=pauseLow + pauseRange;


        double u = uniform(0.0, 1.0);
        //steady-state initial speeds

        if(u<probabilityPaused) //node initially paused
        {
        	 u = uniform(0.0, 1.0);

        	 //calculate initial node pause time
        	if(par("pauseDelta").doubleValue()!=0.0)
        	{
        		if(u < (2*t1/(t1+t2)))
        		{
        			pauseTime=u*(t1+t2)/2;
        			//fprintf(stdout, "# Case 1 u: %f ", u);
        		}
        		else
        		{
        			// there is an error in equation 20 in the Tech. Report MCS-03-04
        			// this error is corrected in the TMC 2004 paper and below
        			pauseTime=t2-sqrt((1-u)*(t2*t2 - t1*t1));
        			//fprintf(stdout, "# Case 2 u: %f ", u);
        		}
        	}
        	else
        	pauseTime=u*par("pauseMean").doubleValue();

        	//fprintf(stdout,"# Initial Pause Time: %f\n",pauseTime);
        	nextMoveIsWait=false;

        	speed=0.0;
        	step.x =step.y = 0 ;
        	StPauseFlg = true ;
        	targetTime += pauseTime;

        	msgName<<getParentModule()->getFullName()<<" starts Waiting-Until" <<targetTime.dbl();
        	Timer = new cMessage((msgName.str()).c_str());
        	scheduleAt(simTime()+updateInterval, Timer);

        	display_string->setTagArg("i2", 0, "old/ball2_vs");
        }
        else //node initially moving
        {
          pauseTime=0.0;
          //calculate initial node speed
          v0=speedLow;
          v1=speedLow + speedRange;
          u = uniform(0.0, 1.0);
          speed=pow(v1,u)/pow(v0,u - 1);
          nextMoveIsWait = true;
          //fprintf(stdout, "# MOVING\n");

          double firstDstDistance = pos.distance(targetPos);    		 // sqrt((x2 - x)*(x2 - x)+(y2 - y)*(y2 - y));
          targetTime +=  firstDstDistance / speed;

          double initNumIntervals = SIMTIME_DBL(targetTime-simTime()) / updateInterval;

          step = (targetPos - pos) / initNumIntervals;

          msgName<<getParentModule()->getFullName()<<" starts Moving-Until" <<targetTime.dbl();
          Timer = new cMessage((msgName.str()).c_str());
          scheduleAt(simTime() +  updateInterval, Timer);

          display_string->setTagArg("i2", 0, "old/ball_vs");

        }



      recordScalar("StartPositionX",targetPos.x);
      recordScalar("StartPositionY",targetPos.y);

      mTraceX = new cOutVector("Mobility Trace x");
      mTraceY = new cOutVector("Mobility Trace y");

      if (!par("logTrace").boolValue())
      {
    	  mTraceX->disable();
    	  mTraceY->disable();
      }
      else
      {
    	    mTraceX->record(pos.x);
    	    mTraceY->record(pos.y);
      }
      WATCH (pos.x);
      WATCH (pos.y);
      WATCH (targetPos.x);
      WATCH (targetPos.y);
      WATCH (targetTime);
      WATCH (speed);
      WATCH (pauseTime);
      WATCH (nextMoveIsWait);
      WATCH (stationary );

    }
}

void SteadyStateRandomWPMobility::setTargetPosition()
{
	std::stringstream msgname;
	if (nextMoveIsWait)
    {
    	pauseTime = uniform(0.0,1.0)*pauseRange + pauseLow;
        targetTime += pauseTime;
        msgname<<"Begin to Pause-Until- "<<targetTime.dbl() ;
        getParentModule()->bubble((const char *)(msgname.str().c_str()));

     }
    else
    {

    	if(!StPauseFlg) targetPos = getRandomPosition();
    	else StPauseFlg = false ; //

    	speed = speedRange * uniform(0.0,1.0) + speedLow;
        double distance = pos.distance(targetPos);
        simtime_t travelTime = distance / speed;
        targetTime += travelTime;

        msgname<<"Begin to Move -Until-"<<targetTime.dbl() ;
        getParentModule()->bubble( (const char *)((msgname.str()).c_str()));
    }

    nextMoveIsWait = !nextMoveIsWait;

    // record newly set target position and time

    mTraceX->record(pos.x);
    mTraceY->record(pos.y);
}

void SteadyStateRandomWPMobility ::fixIfHostGetsOutside()
{
   // raiseErrorIfOutside();
	   double angle = 0;
	   handleIfOutside(REFLECT, targetPos, step, angle);
}

void SteadyStateRandomWPMobility::beginNextMove(cMessage *msg)
{
    // go to exact position where previous statement was supposed to finish
	if (!StPauseFlg) pos = targetPos;

    simtime_t now = targetTime;
    std::stringstream mNam;

    // choose new targetTime and targetPos
    setTargetPosition();

    if (targetTime<now)
        error("SteadyStateRandomWPMobility: targetTime<now was set in %s's beginNextMove()", getClassName());

    if (stationary)
    {
        // end of movement
        step.x = step.y = 0;
        delete msg;
    }
    else if (targetPos==pos)
    {
        // no movement, just wait
//    	pauseTime = pauseRange * uniform(0.0,1.0)+ pauseLow;
//    	targetTime += pauseTime;
    	display_string->setTagArg("i2", 0, "old/ball2_vs");
    	mNam<<getParentModule()->getFullName()<<" Pause-Until" <<targetTime.dbl();
    	msg->setName((mNam.str()).c_str());
        step.x = step.y = 0;
        scheduleAt(std::max(targetTime,simTime()), msg);
    }
    else
    {
        // keep moving
        double numIntervals = SIMTIME_DBL(targetTime-now) / updateInterval;
        // int numSteps = floor(numIntervals); -- currently unused,
        // although we could use step counting instead of comparing
        // simTime() to targetTime each step.

        // Note: step = speed*updateInterval = distance/time*updateInterval =
        //        = (targetPos-pos) / (targetTime-now) * updateInterval =
        //        = (targetPos-pos) / numIntervals

        display_string->setTagArg("i2", 0, "old/ball_vs");
        mNam<<getParentModule()->getFullName()<<" Move-Until" <<targetTime.dbl();
    	msg->setName((mNam.str()).c_str());

        step = (targetPos - pos) / numIntervals;
        scheduleAt(simTime() + updateInterval, msg);
    }
}

void SteadyStateRandomWPMobility::handleSelfMsg(cMessage *msg)
{
    if (stationary)
    {
        delete msg;
        return;
    }
    else if (simTime()+updateInterval >= targetTime)
    {
        beginNextMove(msg);
    }
    else
    {
        scheduleAt(simTime() + updateInterval, msg);
    }

    // update position
    pos += step;

    // do something if we reach the wall
    fixIfHostGetsOutside();

    EV << " xpos=" << pos.x << " ypos=" << pos.y << endl;

    updatePosition();
}

void SteadyStateRandomWPMobility::finish()
{
	delete mTraceX;
	delete mTraceY;
}
