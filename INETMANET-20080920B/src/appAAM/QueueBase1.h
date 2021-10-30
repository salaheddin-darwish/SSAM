//
// This file is part of an OMNeT++/OMNEST simulation example.
//
// Copyright (C) 1992-2008 Andras Varga
//
// This file is distributed WITHOUT ANY WARRANTY. See the file
// `license' for details on this and other legal matters.
//


#ifndef __QUEUEBASE1_H
#define __QUEUEBASE1_H

#include <omnetpp.h>

/**
 * Abstract base class for single-server queues.
 */
class QueueBase1 : public cSimpleModule
{
  private:
    cMessage *msgServiced;
    cMessage *endServiceMsg;
    cQueue queue;

  public:
    QueueBase1();
    virtual ~QueueBase1();

  protected:
    virtual void initialize();
    virtual void handleMessage(cMessage *msg);

    // hook functions to (re)define behaviour
    virtual void arrival(cMessage *msg) {}
    virtual simtime_t startService(cMessage *msg) = 0;
    virtual void endService(cMessage *msg) = 0;
};

#endif

