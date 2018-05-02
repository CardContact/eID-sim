/**
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|
 * |#       #|  Copyright (c) 1999-2018 CardContact Software & System Consulting
 * |'##> <##'|  Andreas Schwier, 32429 Minden, Germany (www.cardcontact.de)
 *  --------- 
 *
 *  This file is part of OpenSCDP.
 *
 *  OpenSCDP is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  OpenSCDP is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with OpenSCDP; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * @fileoverview Implementation of a ISO 7816-4 file system simulation
 */



/**
 * Construct a file system node
 *
 * @class Abstract class for file system nodes
 * @constructor
 */
function FSNode(fcp) {
	this.parent = null;
	this.fcp = fcp;
}

exports.FSNode = FSNode;
DF  = require('cardsim/DF').DF;



/**
 * Sets the parent for this node
 *
 * @param {DF} the parent node
 */
FSNode.prototype.setParent = function(parent) {
	if ((typeof(parent) != "object") && !(parent instanceof(DF))) {
		throw new GPError("FSNode", GPError.INVALID_TYPE, 0, "Argument parent must be of type DF");
	}
	this.parent = parent;
}



/**
 * Gets the parent node for this node
 *
 * @type DF
 * @returns the parent node
 */
FSNode.prototype.getParent = function() {
	return this.parent;
}



/**
 * Gets the file control parameter for this node
 *
 * @type FCP
 * @returns the FCP
 */
FSNode.prototype.getFCP = function() {
	return this.fcp;
}



/**
 * Returns true if this is a DF
 *
 * @type boolean
 * @return true if this is a DF
 */
FSNode.prototype.isDF = function() {
	return (this instanceof DF);
}



/**
 * Returns a human readible string
 *
 * @type String
 * @return a string
 */
FSNode.prototype.toString = function() {
	if (!this.fcp || !this.fcp.getFID()) {
		return "FSNode";
	}
	return this.fcp.getFID().toString(HEX);
}

