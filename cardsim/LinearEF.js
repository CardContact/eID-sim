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


APDU                = require('cardsim/APDU').APDU;
FCP                 = require('cardsim/FCP').FCP;
FSNode              = require('cardsim/FSNode').FSNode;



/**
 * Creates a LinearEF
 *
 * @class Class implementing linear EFs
 * @constructor
 * @param {FCP} the file control parameter
 * @param {ByteString[]} records the array of records
 */
function LinearEF(fcp, records) {
	if (!(fcp instanceof FCP)) {
		throw new GPError("LinearEF", GPError.INVALID_TYPE, APDU.SW_GENERALERROR, "Argument 1 must be of type FCP");
	}
	print(typeof(records));
	if ((typeof(records) != "undefined") && (records != null) && (typeof(records) != "object")) {
		throw new GPError("LinearEF", GPError.INVALID_TYPE, APDU.SW_GENERALERROR, "Argument 2 must be of type ByteString[]");
	}

	FSNode.call(this, fcp);
	this.records = records;
}

LinearEF.prototype = new FSNode();
LinearEF.prototype.constructor = LinearEF;

exports.LinearEF = LinearEF;



/**
 * Reads a record from a linear EF
 *
 * @param {APDU} apdu the APDU used for reading
 * @param {Number} recno the record number
 * @param {Number} qualifier the qualifier as encoded in bit b3 - b1 of P1
 * @param {Number} length the length in bytes or 0 for all in short APDU or 65536 for all in extended APDUs
 * @type ByteString
 * @return the data read
 */
LinearEF.prototype.readRecord = function(apdu, recno, qualifier, length) {
	if (typeof(recno) != "number") {
		throw new GPError("LinearEF", GPError.INVALID_TYPE, APDU.SW_GENERALERROR, "Record number must be type Number");
	}
	if (typeof(qualifier) != "number") {
		throw new GPError("LinearEF", GPError.INVALID_TYPE, APDU.SW_GENERALERROR, "Qualifier must be type Number");
	}

	if (recno == 0) {
		throw new GPError("LinearEF", GPError.INVALID_DATA, APDU.SW_INCP1P2, "Current record referencing with P1=00 not support");
	}
	recno--;

	if (recno >= this.records.length) {
		throw new GPError("LinearEF", GPError.INVALID_DATA, APDU.SW_RECORDNOTFOUND, "Record number exeeds number of defined records");
	}

	if (qualifier != 4) {
		throw new GPError("LinearEF", GPError.INVALID_DATA, APDU.SW_INCP1P2, "Only absolute record references supported");
	}

	var record = this.records[recno];

	var rlen = length;
	if ((length == 0) || (length == 65536)) {
		rlen = record.length;
		if ((length == 0) && (rlen > 256)) {
			rlen = 256;
		}
	}

	if (rlen > record.length) {
		apdu.setSW(APDU.SW_EOF);
		rlen = record.length;
	} else {
		apdu.setSW(APDU.SW_OK);
	}

	return record.left(rlen);
}
