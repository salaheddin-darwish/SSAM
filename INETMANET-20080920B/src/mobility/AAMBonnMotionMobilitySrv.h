// **************************************************************************
// Copyright (C) 2011-2015 Salaheddin Darwish; Department of Computer Science, Brunel University London, UK 
// Modified for the SSAM model 
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

#ifndef __AAMBONNMOTIONMOBILITYSRV_H__
#define __AAMBONNMOTIONMOBILITYSRV_H__

#include <omnetpp.h>
#include "LineSegmentsMobilityBase.h"
#include "BonnMotionFileCache.h"
/**
 * TODO - Generated class
 */
class AAMBonnMotionMobilitySrv : public LineSegmentsMobilityBase



/**
 * @brief Uses the BonnMotion native file format. See NED file for more info.
 *
 * @ingroup mobility
 * @author Andras Varga
 * @Salaheddin Darwish 2012
 */

{
  protected:
    // state
    const BonnMotionFile::Line *vecp;
    int vecpos;
    simtime_t StartPoint ;
    int RunId ;
    cDisplayString* display_string ;

    double delx ;
    double dely;

  protected:
    virtual ~AAMBonnMotionMobilitySrv();

    /** @brief Initializes mobility model parameters.*/
    virtual void initialize(int);

    /** @brief Overridden from LineSegmentsMobilityBase.*/
    virtual void setTargetPosition();

    /** @brief Overridden from LineSegmentsMobilityBase.*/
    virtual void fixIfHostGetsOutside();
};

#endif
