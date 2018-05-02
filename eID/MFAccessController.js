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


AccessController = require('cardsim/AccessController').AccessController;



/**
 * Create an access controller for the Master File
 * @Class Class implementing an access controller for the Master File
 * @constructor
 */
function MFAccessController() {
	AccessController.call(this);
	this.name = "MFAccessController";
}
MFAccessController.prototype = new AccessController();
MFAccessController.constructor = MFAccessController;

exports.MFAccessController = MFAccessController;



/**
 * Check if read access to file system node is allowed
 *
 * @param {eIDCommandInterpreter} ci the command interpreter
 * @param {APDU} apdu the APDU used to access the object
 * @param {FSNode} node the file system object
 * @type boolean
 * @return true if access is allowed
 */
MFAccessController.prototype.checkFileReadAccess = function(ci, apdu, node) {
	var fid = node.getFCP().fid.toUnsigned();
	if ((fid == 0x011C) || (fid == 0x2F01)) {
		return true;
	}

	if (!apdu.isSecureMessaging()) {
		GPSystem.trace("Read access not allowed without secure messaging");
		return false;
	}

	if (!ci.isAuthenticatedTerminal()) {
		GPSystem.trace("Must have passed terminal authentication");
		return false;
	}

	if (fid == 0x011b) {				// EF.ChipSecurity only readable if priviledged terminal right is granted
		return this.checkRight(ci, apdu, 3);
	}
	return true;
}



/**
 * Check if access to special function is allowed
 *
 * @param {eIDCommandInterpreter} ci the command interpreter
 * @param {APDU} apdu the APDU used to access the object
 * @type boolean
 * @return true if access is allowed
 */
MFAccessController.prototype.checkRight = function(ci, apdu, bit) {
	if (!apdu.isSecureMessaging()) {
		GPSystem.trace("Special functions can only be performed with secure messaging");
		return false;
	}

	if (!ci.isAuthenticatedTerminal()) {
		GPSystem.trace("Must have passed terminal authentication");
		return false;
	}

	// Other roles than id-AT have no access
	if (!ci.getTerminalRole().equals(new ByteString("id-AT", OID))) {
		GPSystem.trace("No access to roles other than id-AT");
		return false;
	}

	// The integer value must not excced 2^32, so we only take the first 4 byte of the CHAT
	var mask = ByteString.valueOf(1 << bit, 5);
	print("EffRights:" + ci.effectiveRights);
	print("ReqRights:" + mask);
	print(mask.and(ci.effectiveRights));
	return ci.effectiveRights.and(mask).right(4).toUnsigned() > 0;
}
