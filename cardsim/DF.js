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
FSNode              = require('cardsim/FSNode').FSNode;
FileSystemIdObject  = require('cardsim/FileSystemIdObject').FileSystemIdObject;



/**
 * Creates a Dedicated File (DF)
 *
 * <p>The constructor supports as argument a list of child elements</p>
 *
 * @class Class implementing dedicated files
 * @constructor
 * @param {FCP} the file control parameter
 */
function DF(fcp) {
	this.childs = new Array();
	this.fidmap = new Array();
	this.sfimap = new Array();
	this.aidmap = new Array();
	this.meta = new Array();
	
	FSNode.call(this, fcp);
	
	if (arguments.length > 1) {
		for (var i = 1; i < arguments.length; i++) {
			var arg = arguments[i];
			this.add(arg);
		}
	}
}

DF.prototype = new FSNode();
DF.prototype.constructor = DF;

exports.DF = DF;


/**
 * Adds a new child node to the DF
 *
 * @param {FSNode} node the node to add
 */
DF.prototype.add = function(node) {
	this.childs.push(node);
	node.setParent(this);

	var f = node.getFCP();
	
	var fid = f.getFID();
	if (fid) {
		if (this.fidmap[fid]) {
			throw new GPError("DF", GPError.INVALID_DATA, APDU.SW_FILEEXISTS, "Duplicate file identifier " + fid);
		}
		this.fidmap[fid] = node;
	}

	if (node.isDF()) {
		var aid = f.getAID();
		if (aid) {
			if (this.aidmap[aid]) {
				throw new GPError("DF", GPError.INVALID_DATA, APDU.SW_FILEEXISTS, "Duplicate application identifier " + aid);
			}
			this.aidmap[aid] = node;
		}
	} else {
		var sfi = f.getSFI();
//		print("Found SFI " + sfi);
		if (typeof(sfi) != "undefined") {
			if (this.sfimap[sfi]) {
				throw new GPError("DF", GPError.INVALID_DATA, APDU.SW_FILEEXISTS, "Duplicate short file identifier " + sfi);
			}
			this.sfimap[sfi] = node;
		}
	}

}



/**
 * Add meta information to DF
 *
 * @param {String} name name of meta information
 * @param {Object} value value of meta information
 */
DF.prototype.addMeta = function(name, value) {
	this.meta[name] = value;
}



/**
 * Add object to DF
 *
 * @param {Object} o object to be added. Must have property type and id.
 */
DF.prototype.addObject = function(o) {
	assert((typeof(o) == "object") && (o instanceof FileSystemIdObject), "Argument must be instance of FileSystemIdObject");
	if (typeof(this.meta[o.getType()]) == "undefined") {
		this.meta[o.getType()] = [];
	}
	this.meta[o.getType()][o.getId()] = o;
}



/**
 * Select a file contained in the DF using the file identifier
 *
 * @param {ByteString} the file identifier
 * @type FSNode
 * @return the found node or undefined
 */
DF.prototype.selectByFID = function(fid) {
	return this.fidmap[fid];
}



/**
 * Select a file contained in the DF using the short file identifier
 *
 * @param {Number} the short file identifier
 * @type FSNode
 * @return the found node or undefined
 */
DF.prototype.selectBySFI = function(sfi) {
	return this.sfimap[sfi];
}



/**
 * Select a DF contained in the DF using the application identifier
 *
 * @param {ByteString} the application identifier
 * @type FSNode
 * @return the found node or undefined
 */
DF.prototype.selectByAID = function(aid) {
	return this.aidmap[aid];
}



/**
 * Dump the file system system recursively starting this this node
 *
 * @param {String} indent the string to prefix the output with
 * @type String
 * @return the dump 
 */
DF.prototype.dump = function(indent) {
	if (typeof(indent) == "undefined") {
		indent = "";
	}
	var str = indent + this.toString() + "\n";
	
	if (this instanceof DF) {
		for (var i in this.meta) {
			str += indent + "  Meta:" + i + "\n";
			if (typeof(this.meta[i]) == "object") {
				for each (e in this.meta[i]) {
					if (e instanceof FileSystemIdObject) {
						str += indent + "    " + e.toString() + "\n";
					}
				}
			}
		}
	}
	
	for (var i = 0; i < this.childs.length; i++) {
		var c = this.childs[i];
		
		if (c instanceof DF) {
			str += c.dump("  " + indent);
		} else {
			str += "  " + indent + c.toString() + "\n";
		}
	}
	return str;
}
