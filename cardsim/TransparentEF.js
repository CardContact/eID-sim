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
 * Create a file system node that represents a transparent EF
 *
 * @class Class implementing a transparent EF
 * @constructor
 * @param {FCP} fcp the FCP for this EF
 * @param {ByteString} contents the contents for this EF
 */
function TransparentEF(fcp, contents) {
	if (!(fcp instanceof FCP)) {
		throw new GPError("TransparentEF", GPError.INVALID_TYPE, APDU.SW_GENERALERROR, "Argument 1 must be of type FCP");
	}

	if ((typeof(contents) != "undefined") && (contents != null) && !(contents instanceof ByteString)) {
		throw new GPError("TransparentEF", GPError.INVALID_TYPE, APDU.SW_GENERALERROR, "Argument 2 must be of type ByteString");
	}

	FSNode.call(this, fcp);
	this.content = contents;
}

TransparentEF.prototype = new FSNode();
TransparentEF.prototype.constructor = TransparentEF;

exports.TransparentEF = TransparentEF;



/**
 * Reads data from a transparent EF
 *
 * @param {APDU} apdu the APDU used for reading
 * @param {Number} offset the offset to read from
 * @param {Number} length the length in bytes or 0 for all in short APDU or 65536 for all in extended APDUs
 * @type ByteString
 * @return the data read
 */
TransparentEF.prototype.readBinary = function(apdu, offset, length) {
	if (typeof(offset) != "number") {
		throw new GPError("TransparentEF", GPError.INVALID_TYPE, APDU.SW_GENERALERROR, "Offset must be type Number");
	}
	if (typeof(length) != "number") {
		throw new GPError("TransparentEF", GPError.INVALID_TYPE, APDU.SW_GENERALERROR, "Length must be type Number");
	}

	if (offset >= this.content.length) {
		throw new GPError("TransparentEF", GPError.INVALID_DATA, APDU.SW_INCP1P2, "Offset out of range");
	}
	
	var rlen = length;
	if ((length == 0) || (length == 65536)) {
		rlen = this.content.length - offset;
		if ((length == 0) && (rlen > 256)) {
			rlen = 256;
		}
	}

	if (offset + rlen > this.content.length) {
		apdu.setSW(APDU.SW_EOF);
		rlen = this.content.length - offset;
	} else {
		apdu.setSW(APDU.SW_OK);
	}

	return this.content.bytes(offset, rlen);
}



/**
 * Update data in transparent EF
 *
 * @param {APDU} apdu the APDU used for updating
 * @param {Number} offset the offset to update
 * @param {ByteString} data the data to write into the EF
 */
TransparentEF.prototype.updateBinary = function(apdu, offset, data) {
	if (typeof(offset) != "number") {
		throw new GPError("TransparentEF", GPError.INVALID_TYPE, APDU.SW_GENERALERROR, "Offset must be type Number");
	}
	if ((typeof(data) != "object") || !(data instanceof ByteString)) {
		throw new GPError("TransparentEF", GPError.INVALID_TYPE, APDU.SW_GENERALERROR, "Data must be a ByteString");
	}

	if (offset + data.length > this.fcp.size) {
		throw new GPError("TransparentEF", GPError.INVALID_DATA, APDU.SW_WRONGLENGTH, "Writing beyond file limit");
	}

	if (this.content) {
		if (offset > this.content.length) {
			throw new GPError("TransparentEF", GPError.INVALID_DATA, APDU.SW_INCP1P2, "Offset out of range");
		}
		var newcontent = this.content.bytes(0, offset).concat(data);
		if (this.content.length > newcontent.length) {
			newcontent = newcontent.concat(this.content.bytes(newcontent.length));
		}
	} else {
		if (offset > 0) {
			throw new GPError("TransparentEF", GPError.INVALID_DATA, APDU.SW_INCP1P2, "Offset out of range");
		}
		var newcontent = data;
	}

	this.content = newcontent;
	apdu.setSW(APDU.SW_OK);
}
