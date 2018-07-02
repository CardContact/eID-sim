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
 * @fileoverview Generator for Polymorphic Points
 */


function PolymorphicPointGenerator() {
	this.crypto = new Crypto();

	var curve = new Key();
	this.curve = curve.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP320r1", OID));
	this.coefficientA = curve.getComponent(Key.ECC_A).asSigned();
	this.coefficientB = curve.getComponent(Key.ECC_B).asSigned();
	this.generatorX = curve.getComponent(Key.ECC_GX);
	this.generatorY = curve.getComponent(Key.ECC_GY);
	this.orderOfG= curve.getComponent(Key.ECC_N);
	this.primeP= curve.getComponent(Key.ECC_P).asSigned();

	var curveSpec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("brainpoolP320r1");
	this.curve = curveSpec.getCurve();
}


PolymorphicPointGenerator.VERSION = 1;
PolymorphicPointGenerator.TYPE_BSN = new ByteString("B", ASCII);



/**
 * Generate a new PIP for the given identifier
 * and safe it as XML Key Profiles in the workspace directory
 * 
 * @param {ByteString} identifier the input for the PIP
 */
PolymorphicPointGenerator.prototype.generatePIP= function(identifier) {
	var hmacKey = this.generateHmacKey();
	var piKeyPair = this.generateKeyPair();
	var ppKeyPair = this.generateKeyPair();

	var id = this.mapIdentifierToECPoint(identifier);
	var pseudonym = this.mapPseudonymToECPoint(identifier, hmacKey);

	var rnd = this.crypto.generateRandom(this.orderOfG.length + 1);
	rnd = new java.math.BigInteger(1, rnd.asSigned());

	var blinding = new Key();
	blinding.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP320r1", OID));
	blinding.setComponent(Key.ECC_QX, this.generatorX);
	blinding.setComponent(Key.ECC_QY, this.generatorY);
	var bp = blinding.getECPoint();
	bp = bp.multiply(rnd);

	var piPubKey = piKeyPair.pub.getECPoint();
	var pi = (piPubKey.multiply(rnd)).add(id);

	var ppPubKey = ppKeyPair.pub.getECPoint();
	var pp = (ppPubKey.multiply(rnd)).add(pseudonym);

	var pip = {
		blinding: this.pointToKey(bp),
		pi: this.pointToKey(pi),
		pp: this.pointToKey(pp),
		pubKeyPI: this.pointToKey(piPubKey),
		pubKeyPP: this.pointToKey(ppPubKey)
	}

	this.checkPIP(pip, piKeyPair.pri, ppKeyPair.pri, this.pointToKey(id), this.pointToKey(pseudonym));
	this.saveAsXML("kp_prk_pip_pi", piKeyPair.pri);
	this.saveAsXML("kp_prk_pip_pp", ppKeyPair.pri);

	this.saveAsXML("kp_pip_blinding", pip.blinding);
	this.saveAsXML("kp_pip_pi", pip.pi);
	this.saveAsXML("kp_pip_pp", pip.pp);

	this.saveAsXML("kp_pub_pip_pi", pip.pubKeyPI);
	this.saveAsXML("kp_pub_pip_pp", pip.pubKeyPP);

	return pip;
}



/**
 * Check the generated PIP
 * 
 * @param{Object} pip the PIP
 * @param{Key} priPI the private key of the PI
 * @param{Key} priPP the private key of the PP
 * @param{ByteString} id the plain identifier as reference value for testing
 * @param{ByteString} pseudonym the plain pseudonym as reference value for testing
 */
PolymorphicPointGenerator.prototype.checkPIP= function(pip, priPI, priPP, id, pseudonym) {
	var plainPI = this.elGamalDecrypt(pip.blinding, pip.pi, priPI);
	var plainPP = this.elGamalDecrypt(pip.blinding, pip.pp, priPP);

	var asnPI = new ASN1(plainPI);
	var enc = asnPI.get(0).find(0x86).value;
	var x = enc.bytes(1,40);
	var y = enc.bytes(41);

	if (!x.asUnsigned().equals(id.getComponent(Key.ECC_QX).asUnsigned())) {
		print("x.length=" + x.length + " x=" + x.toString(HEX));
		print(id.getComponent(Key.ECC_QX));
		throw new GPError("PolymorphicPointGenerator", GPError.CRYPTO_FAILED, 0, "Verifcation of the x coordinate for PIP.PI failed"); 
	}
	if (!y.asUnsigned().equals(id.getComponent(Key.ECC_QY).asUnsigned())) {
		print("y.length=" + y.length + " y=" + y.toString(HEX));
		print(id.getComponent(Key.ECC_QY));
		throw new GPError("PolymorphicPointGenerator", GPError.CRYPTO_FAILED, 0, "Verifcation of the y coordinate for PIP.PI failed"); 
	}

	var asnPP = new ASN1(plainPP);
	var enc = asnPP.get(0).find(0x86).value;
	var x = enc.bytes(1, 40);
	var y = enc.bytes(41);

	if (!x.asUnsigned().equals(pseudonym.getComponent(Key.ECC_QX).asUnsigned())) {
		print("x.length=" + x.length + " x=" + x.toString(HEX));
		print(pseudonym.getComponent(Key.ECC_QX));
		throw new GPError("PolymorphicPointGenerator", GPError.CRYPTO_FAILED, 0, "Verifcation of the x coordinate for PIP.PP failed"); 
	}
	if (!y.asUnsigned().equals(pseudonym.getComponent(Key.ECC_QY).asUnsigned())) {
		print("y.length=" + y.length + " y=" + y.toString(HEX));
		print(pseudonym.getComponent(Key.ECC_QY));
		throw new GPError("PolymorphicPointGenerator", GPError.CRYPTO_FAILED, 0, "Verifcation of the y coordinate for PIP.PP failed"); 
	}
}



/**
 * Decrypt an ElGamal ciphertext pair
 * 
 * @param{Key} blinding the blinding component of the ciphertext pair
 * @param{Key} cipher the cipher component of the ciphertext pair
 * @param{Key} priKey the private key for decryption
 * @type ByteString
 * @return the ASN1 encoded EC Point containing the plaintext
 */
PolymorphicPointGenerator.prototype.elGamalDecrypt= function(blinding, cipher, priKey) {
	var encBlinding = new ByteString("04", HEX);
	encBlinding = encBlinding.concat(blinding.getComponent(Key.ECC_QX));
	encBlinding = encBlinding.concat(blinding.getComponent(Key.ECC_QY));

	encCipher = new ByteString("04", HEX);
	encCipher = encCipher.concat(cipher.getComponent(Key.ECC_QX));
	encCipher = encCipher.concat(cipher.getComponent(Key.ECC_QY));

	var seq = new ASN1(ASN1.SEQUENCE);

	var pubSeq = new ASN1(0x7F49);
	pubSeq.add(new ASN1(0x06, new ByteString("brainpoolP320r1", OID)));
	pubSeq.add(new ASN1(0x86, encBlinding)); 
	seq.add(pubSeq);

	var pubSeq = new ASN1(0x7F49);
	pubSeq.add(new ASN1(0x06, new ByteString("brainpoolP320r1", OID)));
	pubSeq.add(new ASN1(0x86, encCipher)); 
	seq.add(pubSeq);

	var c = new Crypto();
	var resp = c.decrypt(priKey, Crypto.ECELGAMAL, seq.getBytes());

	return resp;
}



/**
 * Transform a ECPoint to a key
 * 
 * @param{org.bouncycastle.math.ec.ECPoint} point the ec point
 * @type Key
 * @return the Key object representing the ec point
 */
PolymorphicPointGenerator.prototype.pointToKey= function(point) {
	var x = point.getX().toBigInteger().toByteArray();
	var y = point.getY().toBigInteger().toByteArray();

	var key = new Key();
	key.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP320r1", OID));
	key.setComponent(Key.ECC_QX, x.asUnsigned(40));
	key.setComponent(Key.ECC_QY, y.asUnsigned(40));

	return key;
}



/**
 * Generate a new ec key pair
 * @type object with properties pub and pri containing the corresponding public and private keys
 * @return object containing the key pair
 */
PolymorphicPointGenerator.prototype.generateKeyPair = function() {
	var pub = new Key();
	pub.setType(Key.PUBLIC);
	pub.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP320r1", OID));

	var pri = new Key();
	pri.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP320r1", OID));
	pri.setType(Key.PRIVATE);

	this.crypto.generateKeyPair(Crypto.EC, pub, pri);
	return { pub: pub, pri: pri};
}



/**
 * Generate a new HMAC key
 * @type Key
 */
PolymorphicPointGenerator.prototype.generateHmacKey = function() {
	var hmacKey = new Key();
	hmacKey.setComponent(Key.GENERIC, this.crypto.generateRandom(this.orderOfG.length));
	return hmacKey;
}



/**
 * Map the given identifier to a point on the ec curve
 * 
 * @param{ByteString} identifier the pseudonym input
 * @type org.bouncycastle.math.ec.ECPoint
 * @return the ec point
 */
PolymorphicPointGenerator.prototype.mapIdentifierToECPoint = function(identifier) {
	identifier = this.createPIMessage(PolymorphicPointGenerator.VERSION, PolymorphicPointGenerator.TYPE_BSN, identifier);

	if (this.orderOfG.length != (identifier.length + 2 + (2*10))) {
		throw new GPError("PolymorphicPointGenerator", GPError.INVALID_DATA, 0, "Identifier doesn't fit into ec point");
	}

	// Use OAEP to find an encoding that can be mapped on a ec curve
	for (var i = 0; i < 256; i++) {
		var enc = this.encodeWithOAEP(identifier, 10);

		// Check encoding
		var tmp = this.decodeWithOAEP(enc, 10);
		if (!identifier.equals(tmp)) {
			throw new GPError("PolymorphicPointGenerator", GPError.CRYPTO_FAILED, 0, "Failed OAEP");
		}

		// Create ec point
		try {
			var point = this.createECPoint(enc.asSigned());

			var px = point.getX().toBigInteger().toByteArray().toString(16);
			var bx = new ByteString(px, HEX).asSigned();
			if (bx.length < 40) {
				bx = new ByteString("00", HEX).concat(bx);
			}
			tmp = this.decodeWithOAEP(bx, 10);

			if (!identifier.equals(tmp)) {
				throw new GPError("PolymorphicPointGenerator", GPError.CRYPTO_FAILED, 0, "Error decoding point");
			}
			return point;
		} catch (e) {
			// Try again with a different oaep encoded identifier
			GPSystem.log(GPSystem.DEBUG, "PolymorphicPointGenerator.mapIdentifierToECPoint", "Run " + i + " : " + e);
		}
	}

	
	throw new GPError("PolymorphicPointGenerator", GPError.CRYPTO_FAILED, 0, "Mapping of identifier to ec point failed");
}



/**
 * Create a pseudonym and map it to a point on the ec curve
 * 
 * @param{ByteString} identifier the pseudonym input
 * @param{Key} hmacKey the HMAC key for pseudonymisation
 * @type org.bouncycastle.math.ec.ECPoint
 * @return the ec point
 */
PolymorphicPointGenerator.prototype.mapPseudonymToECPoint = function(identifier, hmacKey) {
	var wp = this.createPseudonym(PolymorphicPointGenerator.VERSION, PolymorphicPointGenerator.TYPE_BSN, identifier, hmacKey);
	wp = wp.mod(this.orderOfG);

	// Find a pseudonym that can be mapped on a ec curve
	for (var i = 0; i < 256; i++) {
		try {
			var point = this.createECPoint(wp);

			// Check point 
			var px = point.getX().toBigInteger().toByteArray().toString(16);
			var bx = new ByteString(px, HEX).asSigned();
			if (!wp.equals(bx)) {
				print("Creation of pseudonym failed");
				print("wp=" + wp.toString(HEX));
				print("bx=" + bx.toString(HEX));
				throw new GPError("PolymorphicPointGenerator", GPError.CRYPTO_FAILED, 0, "Creation of pseudonym failed");
			}
			return point;
		} catch (e) {
			// try again
			wp = wp.biAdd(ByteString.valueOf(1));
			wp = wp.mod(this.orderOfG);
			print(i);
			GPSystem.log(GPSystem.DEBUG, "PolymorphicPointGenerator.mapPseudonymToECPoint", "Run " + i + " : " + e);
		}
	}

	
	throw new GPError("PolymorphicPointGenerator", GPError.CRYPTO_FAILED, 0, "Mapping of pseudonym to ec point failed");
}



/**
 * Wraps version, type and identifier into the message format for a PI ec point
 * 
 * @param{Number} version the version of the polymorphic message format
 * @param{ByteString} type the identifier type, e.g. PolymorphicPointGenerator.TYPE_BSN
 * @param{ByteString} identifier the identifier
 * @type ByteString
 * @return the PI message
 */
PolymorphicPointGenerator.prototype.createPIMessage= function(version, type, identifier) {
	if (type.length + identifier.length + 2 > 18) {
		throw new GPError("PolymorphicPointGenerator", GPError.INVALID_DATA, 2, "Message too long");
	}

	var bb = new ByteBuffer();
	bb.append(version);
	bb.append(type);
	bb.append(identifier.length);
	bb.append(identifier);

	if(bb.length < 18) {
		bb.append(ByteString.valueOf(0, 18 - bb.length));
	}

	return bb.toByteString();
}



/**
 * Create a pseudonym for a given identifier
 * 
 * @param{Number} version the version of the polymorphic message format
 * @param{ByteString} type the identifier type, e.g. PolymorphicPointGenerator.TYPE_BSN
 * @param{ByteString} identifier the pseudonym input
 * @param{Key} hmacKey the HMAC key to create the pseudonym
 * @type ByteString
 * @return the pseudonym
 */
PolymorphicPointGenerator.prototype.createPseudonym= function(version, type, identifier, hmacKey) {
	var bb = new ByteBuffer();
	bb.append(version);
	bb.append(type);
	bb.append(identifier.length);
	bb.append(identifier);
	print(bb);

	var b = bb.toByteString();
	var hmac = this.crypto.sign(hmacKey, Crypto.HMAC_SHA384, b);
	var hmac = hmac;
	var hmac = hmac.mod(this.orderOfG);
	print("pp length: " + hmac.length)
	print("pp : " + hmac)

	return hmac.asSigned();
}



/**
 * Perform an OAEP encoding that is adjusted 
 * to fit into a 320 bit ec point
 * 
 * @param{ByteString} message the PI message to be encoded
 * @type ByteString
 * @return the encoded message
 */
PolymorphicPointGenerator.prototype.encodeWithOAEP = function(message, len) {
	var emptyHash = this.crypto.digest(Crypto.SHA_384, new ByteString("", HEX));

	var bb = new ByteBuffer();
	bb.append(emptyHash.bytes(0,len));
	bb.append(0x01);
	bb.append(message);
	var db = bb.toByteString();

	var seed = this.crypto.generateRandom(len);
	var mask = this.crypto.digest(Crypto.SHA_384, seed.concat(new ByteString("00 00 00 00", HEX)));
	var mask = mask.bytes(0, len + message.length + 1);
	var maskedDB = db.xor(mask);

	mask = this.crypto.digest(Crypto.SHA_384, maskedDB.concat(new ByteString("00 00 00 00", HEX)));
	mask = mask.bytes(0, len);
	var maskedSeed = seed.xor(mask);
	
	var result = new ByteBuffer();
	result.append(0x00);
	result.append(maskedSeed);
	result.append(maskedDB);

	return result.toByteString();
}


/**
 * Perform an OAEP decoding that is adjusted 
 * to fit into a 320 bit ec point
 * 
 * @param{ByteString} enc the OAEP encoded message
 * @type ByteString
 * @return the PI message
 */
PolymorphicPointGenerator.prototype.decodeWithOAEP = function(enc, len) {
	var bb = new ByteBuffer();
	
	if (enc.byteAt(0) != 0) {
		throw new GPError("PolymorphicPointGenerator", GPError.CRYPTO_FAILED, 1, "Decoding of OAEP encoded message failed");
	}
	
	var y = enc.byteAt(0);
	var maskedSeed = enc.bytes(1, len);
	var maskedDB = enc.bytes(len + 1);

	var mask = this.crypto.digest(Crypto.SHA_384, maskedDB.concat(new ByteString("00 00 00 00", HEX)));
	var seed = maskedSeed.xor(mask.bytes(0, len));

	mask = this.crypto.digest(Crypto.SHA_384, seed.concat(new ByteString("00 00 00 00", HEX)));
	var db = maskedDB.xor(mask.bytes(0, maskedDB.length));

	if (db.byteAt(len) != 0x01) {
		throw new GPError("PolymorphicPointGenerator", GPError.CRYPTO_FAILED, 1, "Decoding of OAEP encoded message failed");
	}

	var emptyHash = this.crypto.digest(Crypto.SHA_384, new ByteString("", HEX));
	if (!emptyHash.bytes(0, len).equals(db.bytes(0,len))) {
		throw new GPError("PolymorphicPointGenerator", GPError.CRYPTO_FAILED, 1, "Decoding of OAEP encoded message failed");
	}

	var message = db.bytes(len + 1);
	return message;
}



/**
 * Create a 320 bit ec point for the given x coordinate
 * 
 * @param{ByteString} x the x coordinate
 * @type org.bouncycastle.math.ec.ECPoint
 * @return the ec point
 */
PolymorphicPointGenerator.prototype.createECPoint = function(x) {
	var xCube = x.modPow(ByteString.valueOf(3), this.primeP);
	var ax = x.multiply(this.coefficientA);

	var ySquare = xCube.biAdd(ax);
	ySquare = ySquare.biAdd(this.coefficientB);
	ySquare = ySquare.mod(this.primeP);

	// Calculate square root
	// square root(n) = n^((p+1)/4)
	var tmp = this.primeP.biAdd(ByteString.valueOf(1));
	var tmpHalf = tmp.divide(ByteString.valueOf(2));
	var tmpQuarter = tmpHalf.divide(ByteString.valueOf(2));
	var y = ySquare.modPow(tmpQuarter, this.primeP);
	if (new java.math.BigInteger(y).compareTo(java.math.BigInteger(tmpHalf)) == 1) {
		y = this.primeP.sub(y);
	}

	// Check square root
	var tmp = y.modPow(ByteString.valueOf(2), this.primeP);
	if (!tmp.equals(ySquare)) {
		throw new GPError("PolymorphicPointGenerator", GPError.CRYPTO_FAILED, 1, "Computation of y coord failed");
	}

	var point = new Key();
	point.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP320r1", OID));
	point.setComponent(Key.ECC_QX, x);
	point.setComponent(Key.ECC_QY, y);
	return point.getECPoint();
}



/**
 * Save key as GP key profile
 * 
 * @param name the name of the key
 * @param key the key
 */
PolymorphicPointGenerator.prototype.saveAsXML = function(name, key) {
	var curve = new ByteString("brainpoolP256r1", OID);
	var keysize = 256;

	var pubKey = new Key();
	pubKey.setType(Key.PUBLIC);
	pubKey.setComponent(Key.ECC_CURVE_OID, curve);

	var priKey = new Key();
	priKey.setType(Key.PRIVATE);
	priKey.setComponent(Key.ECC_CURVE_OID, curve);

	var crypto = new Crypto();
	crypto.generateKeyPair(Crypto.EC, pubKey, priKey);

	var gp = new Namespace("http://namespaces.globalplatform.org/systems-profiles/1.1.0");

	if (key.getType() == Key.PRIVATE) {
		var keyXML = 
			<gp:KeyProfile xmlns:gp={gp} UniqueID="2B0601040181C31F100006" ProfileVersion="1.1.0" ErrataVersion="0">
				<gp:Description>{"PrK_" + name + " ElGamal Private Key"}</gp:Description>
				<gp:Revisions arrayElement="Revision" arrayIndex="#">
					<gp:Revision Version="1.0.0" Date="2011-11-11" Time="00:00:00" By="www.smartcard-hsm.org" Digest="00000000"/>
				</gp:Revisions>
				<gp:KeyInfo Name="ECPrivate" Type="PRIVATE" SubType="EC" Size={keysize} Mode="TEST"/>
				<gp:Attribute Sensitive="false" Importable="true" Exportable="true"/>
				<gp:Usage Encrypt="true" Decrypt="true" DecryptEncrypt="true" Sign="true" Verify="true" Wrap="true" Unwrap="true" UnwrapWrap="true" Derive="true"/>
				<gp:Value Format="ECPRIVATE" arrayElement="Component" arrayIndex="#">
					<gp:Component Name="ECC_CURVE_OID" Encoding="HEX" Value={key.getComponent(Key.ECC_CURVE_OID).toString(HEX)}></gp:Component>
					<gp:Component Name="ECC_D" Encoding="HEX" Value={key.getComponent(Key.ECC_D).toString(HEX)}></gp:Component>
				</gp:Value>
			</gp:KeyProfile>
	} else {
		var keyXML =
			<gp:KeyProfile xmlns:gp={gp} UniqueID="2B0601040181C31F100008" ProfileVersion="1.1.0" ErrataVersion="0">
				<gp:Description>{"PuK_" + name + " ElGamal Public Key"}</gp:Description>
				<gp:Revisions arrayElement="Revision" arrayIndex="#">
					<gp:Revision Version="1.0.0" Date="2011-11-11" Time="00:00:00" By="www.smartcard-hsm.org" Digest="00000000"/>
				</gp:Revisions>
				<gp:KeyInfo Name="ECPublic" Type="PUBLIC" SubType="EC" Size={keysize} Mode="TEST"/>
				<gp:Attribute Sensitive="false" Importable="true" Exportable="true"/>
				<gp:Usage Encrypt="true" Decrypt="true" DecryptEncrypt="true" Sign="true" Verify="true" Wrap="true" Unwrap="true" UnwrapWrap="true" Derive="true"/>
				<gp:Value Format="ECPUBLIC" arrayElement="Component" arrayIndex="#">
					<gp:Component Name="ECC_CURVE_OID" Encoding="HEX" Value={key.getComponent(Key.ECC_CURVE_OID).toString(HEX)}></gp:Component>
					<gp:Component Name="ECC_QX" Encoding="HEX" Value={key.getComponent(Key.ECC_QX).toString(HEX)}></gp:Component>
					<gp:Component Name="ECC_QY" Encoding="HEX" Value={key.getComponent(Key.ECC_QY).toString(HEX)}></gp:Component>
				</gp:Value>
			</gp:KeyProfile>
	}

 	var fname = GPSystem.mapFilename(name + ".xml", GPSystem.CWD);
	print(keyXML);
	print("Filename " + fname);

	print("Writing " + fname + "...");
	var fw = new java.io.FileWriter(fname);
	fw.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
	fw.write(keyXML.toXMLString());
	fw.close();
}



PolymorphicPointGenerator.test = function() {
	var g = new PolymorphicPointGenerator();

	var bsn = new ByteString("123456789", ASCII);
	var pip = g.generatePIP(bsn);

	return pip;
}
