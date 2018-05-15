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



eIDAccessController = require('eID/eIDAccessController').eIDAccessController;



PCAAccessController.RANDOMIZED_PP_RETRIEVAL = 1;
PCAAccessController.RANDOMIZED_PI_RETRIEVAL = 2;
PCAAccessController.RANDOMIZED_PIP_RETRIEVAL = 3;



/**
 * Create an access controller for the ePass application
 * @Class Class implementing an access controller for the ePass application
 * @constructor
 */
function PCAAccessController() {
	eIDAccessController.call(this);
	this.name = "PCAAccessController";
}
PCAAccessController.prototype = new eIDAccessController();
PCAAccessController.constructor = PCAAccessController;

exports.PCAAccessController = PCAAccessController;



PCAAccessController.prototype.checkAuthorizationExtension = function(ci, apdu, bit) {
	GPSystem.trace("checkAuthorizationExtension");

	if (!ci.certExt) {
		GPSystem.trace("No Certificate Extension set during PACE");
		return false;
	}

	for (var i = 0; i < ci.certExt.elements; i++) {
		// Search Certificate Extension with PCA OID
		// which was set during PACE
		var discDataTemp = ci.certExt.get(i);
		var oid = discDataTemp.get(0);

		if (oid.value.equals(new ByteString("id-PCA-AT", OID))) {

			// Get Authorization Bit Mask from the Certificate Extension
			var extObj = discDataTemp.get(1);
			assert(extObj.tag == 0x53, "Expected Discretionary Data tag 53 for Authorization Extension");
			var paceAuthorizationBM = extObj.value.toUnsigned();

			// Get Authorization Bit Mask for PCA from trusted terminal certificate
			var authExt = ci.trustedTerminal.getExtension(oid.value);
			GPSystem.trace("Authorization Extension: " + authExt);
			var authorizationBM = authExt.get(1).value.toUnsigned();

			// The Authorization Bit Mask from the trusted terminal certificate
			// must match the Authorization Bit Mask which was set during PACE
			if (paceAuthorizationBM != authorizationBM) {
				GPSystem.trace("Authorization extension doesn\'t match");
				return false
			}

			// Check if the terminal is authorized to perform the PCA retrieval
			GPSystem.trace("Authorized Terminal: " + authorizationBM && bit == bit);
			return authorizationBM && bit == bit;
		}
	}

	// No Authorization Extension...
	return false;
}



/**
 * Check if access to special function is allowed
 *
 * @param {eIDCommandInterpreter} ci the command interpreter
 * @param {APDU} apdu the APDU used to access the object
 * @param {Number} bit representing eID function
 * @param {Number} retrievalType representing PCA function
 * @type boolean
 * @return true if access is allowed
 */
PCAAccessController.prototype.checkRight = function(ci, apdu, bit, retrievalType) {
	if (!this.checkBasicAccess(ci, apdu)) {
		return false;
	}
	
	// Other roles than id-AT have no access
	if (!ci.getTerminalRole().equals(new ByteString("id-AT", OID))) {
		GPSystem.trace("No access to roles other than id-AT");
		return false;
	}

	// Check PCA function
	if (retrievalType) {
		return this.checkAuthorizationExtension(ci, apdu, retrievalType);
	}

	// Check eID function
	return this.checkBit(ci, apdu, bit);
}
