//
// This file is part of an OMNeT++/OMNEST simulation example.
//
// Copyright (C) 1992-2008 Andras Varga
//
// This file is distributed WITHOUT ANY WARRANTY. See the file
// `license' for details on this and other legal matters.
//


#include <omnetpp.h>
#include "QueueBase1.h"


QueueBase1::QueueBase1()
{
    msgServiced = endServiceMsg = NULL;
}

QueueBase1::~QueueBase1()
{
    delete msgServiced;
    cancelAndDelete(endServiceMsg);
}

void QueueBase1::initialize()
{
    endServiceMsg = new cMessage("end-service");
    queue.setName("queue");
}

void QueueBase1::handleMessage(cMessage *msg)
{
    if (msg==endServiceMsg)
    {
        endService( msgServiced );
        if (queue.empty())
        {
            msgServiced = NULL;
        }
        else
        {
            msgServiced = (cMessage *) queue.pop();
            simtime_t serviceTime = startService( msgServiced );
            scheduleAt( simTime()+serviceTime, endServiceMsg );
        }
    }
    else if (!msgServiced)
    {
        arrival( msg );
        msgServiced = msg;
        simtime_t serviceTime = startService( msgServiced );
        scheduleAt( simTime()+serviceTime, endServiceMsg );

    }
    else
    {
        arrival( msg );
        queue.insert( msg );
    }
}

