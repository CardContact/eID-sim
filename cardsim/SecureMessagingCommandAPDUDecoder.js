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
 * @fileoverview Implementation of a secure messaging channel as defined in ISO 7814-4 and eSign-K
 */



/**
 * Creates a decoder for a single secure messaging command APDU
 *
 * @class Decoder for a secure messaging APDU
 * @constructor
 * @param {SecureChannel} channel the secure channel object
 * @param {APDU} apdu the secure messaging APDU
 */
function SecureMessagingCommandAPDUDecoder(channel, apdu) {
	this.channel = channel;
	this.apdu = apdu;
	this.tlvlist = apdu.getCDataAsTLVList();
}

exports.SecureMessagingCommandAPDUDecoder = SecureMessagingCommandAPDUDecoder;

APDU            = require('cardsim/APDU').APDU;
SecureChannel   = require('cardsim/SecureChannel').SecureChannel;



/**
 * Verify the message authentication code (MAC)
 *
 * @type boolean
 * @return true if the MAC is valid
 */
SecureMessagingCommandAPDUDecoder.prototype.verifyMAC = function() {
	var macinp = this.buildMACInput();
	
	var mac = this.tlvlist.find(0x8E);

	if (mac == null) {
		throw new GPError("SecureMessagingCommandAPDUDecoder", GPError.INVALID_DATA, APDU.SW_SMOBJMISSING, "MAC data object (8E) not found");
	}

	return this.channel.crypto.verify(this.channel.macKey, this.channel.macMechanism, macinp, mac.getValue());
}



/**
 * Build the MAC input block
 *
 * @type ByteString
 * @return the MAC calculation input block
 */
SecureMessagingCommandAPDUDecoder.prototype.buildMACInput = function() {
	var macinp = new ByteBuffer();
	
	if (typeof(this.channel.macSendSequenceCounter) != "undefined") {
		var ssc = this.channel.macSendSequenceCounter.add(1);
		this.channel.macSendSequenceCounter = ssc;
		macinp.append(ssc);
	}
	
	if (this.apdu.isAuthenticatedHeader()) {
		macinp.append(this.apdu.getCLA());
		macinp.append(this.apdu.getINS());
		macinp.append(this.apdu.getP1());
		macinp.append(this.apdu.getP2());
		SecureChannel.pad(macinp, this.channel.macBlockSize);
	}

	var someadded = false;
	for (var i = 0; i < this.tlvlist.length; i++) {
		var tlv = this.tlvlist.index(i);
		
		if (tlv.getTag() & 0x01) {
			macinp.append(tlv.getTLV());
			someadded = true;
		}
	}
	if (someadded) {
		SecureChannel.pad(macinp, this.channel.macBlockSize);
	}
	return macinp.toByteString();
}



/**
 * Decrypt the body of a secure messaging APDU
 *
 * @param {Key} key the encryption key
 * @type ByteString
 * @return the plain body
 */
SecureMessagingCommandAPDUDecoder.prototype.decryptBody = function(key) {
	var body = this.tlvlist.find(0x87);
	var ofs = 1;
	if (body == null) {
		var body = this.tlvlist.find(0x85);
		if (body == null) {
			return null;
		}
		var ofs = 0;
	} else {
		var paddingIndicator = body.getValue().byteAt(0);
		if (paddingIndicator != 0x01) {
			throw new GPError("SecureMessagingCommandAPDUDecoder", GPError.INVALID_DATA, APDU.SW_INCSMDATAOBJECT, "Padding indicator " + paddingIndicator + " not supported");
		}
	}
	
	var cryptogram = body.getValue().bytes(ofs);
	
	var iv = this.channel.getIV();
	var plain = this.channel.crypto.decrypt(this.channel.encKey, this.channel.encMechanism, cryptogram, iv);
	
	plain = SecureChannel.removePadding(plain);
	
	return plain;
}



/**
 * Return value of optional Le element with tag '97'
 *
 * @type Number
 * @return the value of the Le element
 */
SecureMessagingCommandAPDUDecoder.prototype.getLe = function() {
	var le = this.tlvlist.find(0x97);
	if (le == null) {
		return -1;
	}
	return le.getValue().toUnsigned();
}
