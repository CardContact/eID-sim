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
 * @fileoverview Implementation of a PPCA specific command interpreter
 */



load("tools/eccutils.js");

eIDCommandInterpreter		= require('eID/eIDCommandInterpreter').eIDCommandInterpreter;
PolymorphicObject			= require('pca/PolymorphicObject').PolymorphicObject;
APDU						= require('cardsim/APDU').APDU;



/**
 * Create a command interpreter
 *
 * @class Class implementing a command interpreter that handles ISO 7816-4 command APDUs
 * @constructor
 * @param {FileSelector} fileSelector the file selector object
 */
function PCACommandInterpreter(fileSelector) {
	eIDCommandInterpreter.call(this, fileSelector);
}


// Inherit from eIDCommandInterpreter
PCACommandInterpreter.prototype = new eIDCommandInterpreter();
PCACommandInterpreter.constructor = PCACommandInterpreter;

exports.PCACommandInterpreter = PCACommandInterpreter;



PCACommandInterpreter.prototype.performPolymorphicAuthentication = function(apdu, oid, retrievalType) {
	GPSystem.trace("performPolymorphicAuthentication with oid " + oid.toString(OID) + " and retrieval type " + retrievalType);
	var ac = this.fileSelector.getMeta("accessController");
	if (!ac.checkRight(this, apdu, null, retrievalType)) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_SECSTATNOTSAT, "PCA retrieval not authorized");
	}

	var polymorphicObject = this.fileSelector.getObject(PolymorphicObject.TYPE, 0x81);
	var response = polymorphicObject.getData(oid);
	apdu.setRData(response);
	apdu.setSW(APDU.SW_OK);
	var paceao = this.fileSelector.getObject(AuthenticationObject.TYPE_PACE, 3);
	this.fileSelector.removeAuthenticationState(true, paceao);
}



/**
 * Process a MANAGE SECURITY ENVIRONMENT APDU
 *
 * @param {APDU} apdu the command and response APDU
 */
PCACommandInterpreter.prototype.manageSecurityEnvironment = function(apdu) {
	GPSystem.trace("PCACommandInterpreter.manageSecurityEnvironment()... apdu: " + apdu);
	
	if (apdu.getP1() == 0x41 && apdu.getP2() == 0xA4) {
		var list = new TLVList(apdu.getCData(), TLV.EMV);
		var cmr = list.find(0x80);
		if (cmr) {
			var oid = cmr.getValue();
			var retrievalType = PolymorphicObject.getRetrievalType(oid);
			var isCompressed = PolymorphicObject.isCompressed(oid);
			var isReduced = PolymorphicObject.isReduced(oid);
			
			var polymorphicInfo = this.fileSelector.getMeta("polymorphicInfo");
			if (retrievalType == PolymorphicObject.RANDOMIZED_PI_RETRIEVAL && !polymorphicInfo.randomizedPI ||
				retrievalType == PolymorphicObject.RANDOMIZED_PP_RETRIEVAL && !polymorphicInfo.randomizedPP ||
				retrievalType == PolymorphicObject.RANDOMIZED_PIP_RETRIEVAL && !polymorphicInfo.randomizedPIP ||
				isCompressed && !polymorphicInfo.compressedEncoding ||
				!isCompressed && !polymorphicInfo.uncompressedEncoding ||
				isReduced && !polymorphicInfo.reducedEncoding ||
				!isReduced && !polymorphicInfo.regularEncoding
			) {
				throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INVDATA, "Algorithm not supported");
			}
		}
	}
	
	eIDCommandInterpreter.prototype.manageSecurityEnvironment.call(this, apdu);
}



/**
 * Process GENERAL AUTHENTICATE command
 *
 * @param {APDU} the apdu
 */
PCACommandInterpreter.prototype.generalAuthenticate = function(apdu) {
	GPSystem.trace("PCACommandInterpreter.generalAuthenticate()...");
	var a = new ASN1(apdu.getCData());

	if (a.tag != 0x7C)
		throw new GPError("EACSIM", GPError.INVALID_DATA, 0, "Body must contain data element 0x7C");

	if (a.elements > 0) {
		var ddtag = a.get(0).tag;
		if (ddtag == 0x80) {
			this.performChipAuthenticationV2(apdu);
			return;
		}
		if ((ddtag == 0xA0) || (ddtag == 0xA2)) {
			this.performRestrictedIdentification(apdu);
			return;
		}
	}

	var at = this.fileSelector.getSecurityEnvironment().CDIK.t.AT;

	if (at) {
		var crt = at.find(0xA4);
		var cmr = at.find(0x80);
		if (cmr) {
			var oid = cmr.value;
			var retrievalType = PolymorphicObject.getRetrievalType(oid);
			if (retrievalType > 0) {
				this.performPolymorphicAuthentication(apdu, oid, retrievalType);
				return;
			}
		}
	}

	this.performPACE(apdu);
}
