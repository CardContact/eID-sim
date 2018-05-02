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
 * Create an access controller for the eSign application
 * @Class Class implementing an access controller for the eSign application
 * @constructor
 */
function eSignAccessController() {
	AccessController.call(this);
	this.name = "eSignAccessController";
}
eSignAccessController.prototype = new AccessController();
eSignAccessController.constructor = eSignAccessController;

exports.eSignAccessController = eSignAccessController;



/**
 * Check if read access to file system node is allowed
 *
 * @param {eIDCommandInterpreter} ci the command interpreter
 * @param {APDU} apdu the APDU used to access the object
 * @param {FSNode} node the file system object
 * @type boolean
 * @return true if access is allowed
 */
eSignAccessController.prototype.checkFileReadAccess = function(ci, apdu, node) {
	if (!apdu.isSecureMessaging()) {
		GPSystem.trace("Read access not allowed without secure messaging");
		return false;
	}

	if (!ci.isAuthenticatedTerminal()) {
		GPSystem.trace("No access to unauthenticated terminal");
		return false;
	}

	// ST have generell access
	if (ci.getTerminalRole().equals(new ByteString("id-ST", OID))) {
		return true;
	}

	// AT have access may have right to install certificate
	if (ci.getTerminalRole().equals(new ByteString("id-AT", OID))) {
		if (ci.effectiveRights.right(1).toUnsigned() & 0xC0) {
			return true;
		}
		GPSystem.trace("AT terminal has no right to install certificate");
	}

	return false;
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
eSignAccessController.prototype.checkFileWriteAccess = function(ci, apdu, node) {
	if (!apdu.isSecureMessaging()) {
		GPSystem.trace("Write access not allowed without secure messaging");
		return false;
	}

	if (!ci.isAuthenticatedTerminal()) {
		GPSystem.trace("No access to unauthenticated terminal");
		false;
	}

	// AT have access may have right to install certificate
	if (ci.getTerminalRole().equals(new ByteString("id-AT", OID))) {
		if (ci.effectiveRights.right(1).toUnsigned() & 0xC0) {
			return true;
		}
		GPSystem.trace("AT terminal has no right to install certificate");
	}

	return false;
}



/**
 * Check if access to special function is allowed
 *
 * @param {eIDCommandInterpreter} ci the command interpreter
 * @param {APDU} apdu the APDU used to access the object
 * @type boolean
 * @return true if access is allowed
 */
eSignAccessController.prototype.checkRight = function(ci, apdu, bit) {
	if (!apdu.isSecureMessaging()) {
		GPSystem.trace("Special functions can only be performed with secure messaging");
		return false;
	}

	if (!ci.isAuthenticatedTerminal()) {
		GPSystem.trace("No access to unauthenticated terminal");
		false;
	}
	
	return true;
}
