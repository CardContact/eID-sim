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
 * @fileoverview Access controller for eID card
 */

AccessController = require('cardsim/AccessController').AccessController;



/**
 * Create an access controller for the eID application
 * @Class Class implementing an access controller for the eID application
 * @constructor
 */
function eIDAccessController() {
	AccessController.call(this);
	this.name = "eIDAccessController";
}
eIDAccessController.prototype = new AccessController();
eIDAccessController.constructor = eIDAccessController;

exports.eIDAccessController = eIDAccessController;



/**
 * Check basic access conditions for eID application
 *
 * @param {eIDCommandInterpreter} ci the command interpreter
 * @param {APDU} apdu the APDU used to access the object
 * @type boolean
 * @return true if access is allowed based on basic checks
 */
eIDAccessController.prototype.checkBasicAccess = function(ci, apdu) {
	if (!apdu.isSecureMessaging()) {
		GPSystem.trace("Read access not allowed without secure messaging");
		return false;
	}

	if (!ci.isAuthenticatedTerminal()) {
		GPSystem.trace("No access to unauthenticated terminal");
		false;
	}

	// Access to eID functions only allowed with eID PIN or if CAN allowed is granted and PACE(CAN) was performed
	if (ci.paceao.id == 3) {
		return true;
	}

	if (!ci.getTerminalRole().equals(new ByteString("id-AT", OID))) {
		return true;
	}

	// CAN allowed checking only if id-AT terminal
	if (!this.checkBit(ci, apdu, 4)) {
		print("CAN allowed right not granted");
		return false;
	}

	if (ci.paceao.id != 2) {
		print("CAN allowed only effective for PACE with CAN");
		return false;
	}
	return true;
}


/**
 * Check if read access to file system node is allowed
 *
 * @param {eIDCommandInterpreter} ci the command interpreter
 * @param {APDU} apdu the APDU used to access the object
 * @param {FSNode} node the file system object
 * @type boolean
 * @return true if access is allowed
 */
eIDAccessController.prototype.checkFileReadAccess = function(ci, apdu, node) {
	if (!this.checkBasicAccess(ci, apdu)) {
		return false;
	}

	// Check valid range 0x0101 - 0x0115
	var fid = node.getFCP().fid;
	if ((fid.byteAt(0) != 0x01) || (fid.byteAt(1) < 0x01) || (fid.byteAt(1) > 0x15)) {
		GPSystem.trace("FID " + fid + " out of defined range");
		return false;
	}

	// IS have generell access if GAP with CHAT was used
	if ((ci.getTerminalRole().equals(new ByteString("id-IS", OID)) && ci.chat)) {
		return true;
	}
	
	// Other roles than id-AT have no access
	if (!ci.getTerminalRole().equals(new ByteString("id-AT", OID))) {
		GPSystem.trace("No access to roles other than id-AT");
		return false;
	}

	var mask = ByteString.valueOf(0x0100 << (fid.byteAt(1) - 1), 5);
	print("EffRights:" + ci.effectiveRights);
	print("ReqRights:" + mask);
	print(mask.and(ci.effectiveRights));
	return ci.effectiveRights.and(mask).toUnsigned() > 0;
}



/**
 * Check if write access to file system node is allowed
 *
 * @param {eIDCommandInterpreter} ci the command interpreter
 * @param {APDU} apdu the APDU used to access the object
 * @param {FSNode} node the file system object
 * @type boolean
 * @return true if access is allowed
 */
eIDAccessController.prototype.checkFileWriteAccess = function(ci, apdu, node) {
	if (!this.checkBasicAccess(ci, apdu)) {
		return false;
	}

	// Check valid range 0x0101 - 0x0115
	var fid = node.getFCP().fid;
	if ((fid.byteAt(0) != 0x01) || (fid.byteAt(1) < 0x11) || (fid.byteAt(1) > 0x15)) {
		GPSystem.trace("FID out of defined range");
		return false;
	}

	// Other roles than id-AT have no access
	if (!ci.getTerminalRole().equals(new ByteString("id-AT", OID))) {
		GPSystem.trace("No access to roles other than id-AT");
		return false;
	}

	// The integer value must not excced 2^32, so we only take the first 4 byte of the CHAT
	var mask = ByteString.valueOf(0x20000000 >> (fid.byteAt(1) - 17), 4);
	mask = mask.concat(new ByteString.valueOf(0, 1));
	print("EffRights:" + ci.effectiveRights);
	print("ReqRights:" + mask);
	print(mask.and(ci.effectiveRights));
	return ci.effectiveRights.and(mask).left(4).toUnsigned() > 0;
}



/**
 * Check if access to special function is allowed
 *
 * @param {eIDCommandInterpreter} ci the command interpreter
 * @param {APDU} apdu the APDU used to access the object
 * @type boolean
 * @return true if access is allowed
 */
eIDAccessController.prototype.checkBit = function(ci, apdu, bit) {
	// The integer value must not excced 2^32, so we only take the first 4 byte of the CHAT
	var mask = ByteString.valueOf(1 << bit, 5);
	print("EffRights:" + ci.effectiveRights);
	print("ReqRights:" + mask);
	print(mask.and(ci.effectiveRights));
	return ci.effectiveRights.and(mask).right(4).toUnsigned() > 0;
}



/**
 * Check if access to special function is allowed
 *
 * @param {eIDCommandInterpreter} ci the command interpreter
 * @param {APDU} apdu the APDU used to access the object
 * @type boolean
 * @return true if access is allowed
 */
eIDAccessController.prototype.checkRight = function(ci, apdu, bit) {
	if (!this.checkBasicAccess(ci, apdu)) {
		return false;
	}
	
	// Other roles than id-AT have no access
	if (!ci.getTerminalRole().equals(new ByteString("id-AT", OID))) {
		GPSystem.trace("No access to roles other than id-AT");
		return false;
	}

	return this.checkBit(ci, apdu, bit);
}
