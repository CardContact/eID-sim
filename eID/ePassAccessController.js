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
 * Create an access controller for the ePass application
 * @Class Class implementing an access controller for the ePass application
 * @constructor
 */
function ePassAccessController() {
	AccessController.call(this);
	this.name = "ePassAccessController";
}
ePassAccessController.prototype = new AccessController();
ePassAccessController.constructor = ePassAccessController;

exports.ePassAccessController = ePassAccessController;



/**
 * Check if read access to file system node is allowed
 *
 * @param {eIDCommandInterpreter} ci the command interpreter
 * @param {APDU} apdu the APDU used to access the object
 * @param {FSNode} node the file system object
 * @type boolean
 * @return true if access is allowed
 */
ePassAccessController.prototype.checkFileReadAccess = function(ci, apdu, node) {
	if (!apdu.isSecureMessaging()) {
		GPSystem.trace("Read access not allowed without secure messaging");
		return false;
	}

	// A secure channel with id-AT or id-ST does not qualify to read DF.ePass
	if (ci.isAuthenticatedTerminal()) {
		if (!ci.getTerminalRole().equals(new ByteString("id-IS", OID))) {
			GPSystem.trace("No access to roles other than id-IS");
			return false;
		}
	}

	var fid = node.getFCP().fid.toUnsigned();
	if ((fid != 0x0103) && (fid != 0x0104)) {
		return true;
	}

	if (!ci.isAuthenticatedTerminal()) {
		GPSystem.trace("Must have passed terminal authentication");
		return false;
	}

	var mask = ByteString.valueOf(0x01 << ((fid & 0xFF) - 3), 1);
	print("EffRights:" + ci.effectiveRights);
	print("ReqRights:" + mask);
	print(mask.and(ci.effectiveRights));
	return ci.effectiveRights.and(mask).toUnsigned() > 0;
}



/**
 * Check if access to special function is allowed
 *
 * @param {eIDCommandInterpreter} ci the command interpreter
 * @param {APDU} apdu the APDU used to access the object
 * @type boolean
 * @return true if access is allowed
 */
ePassAccessController.prototype.checkRight = function(ci, apdu, bit) {
	return false;
}



/**
 * Check if command is allowed
 *
 * @param {APDU} apdu the APDU to check
 * @type boolean
 * @return true if access is allowed
 */
ePassAccessController.prototype.checkCommandAccess = function(ci, apdu) {
	if ((apdu.getINS() == 0xA4) && (apdu.getP1() != 0x04)) {
		return apdu.isSecureMessaging();
	}
	return true;
}
