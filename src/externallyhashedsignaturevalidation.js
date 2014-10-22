/**
 * @requires config
 * @requires crypto
 * @requires encoding/armor
 * @requires enums
 * @requires packet
 * @module PreHashedMessage
 */

'use strict';

var packet = require('./packet'),
    enums = require('./enums.js'),
    armor = require('./encoding/armor.js'),
    config = require('./config'),
    crypto = require('./crypto'),
    keyModule = require('./key.js'),
    util = require('./util.js');

function ExternallyHashedSignatureValidation(packetlist) {
    if (!(this instanceof ExternallyHashedSignatureValidation)) {
        return new ExternallyHashedSignatureValidation(packetlist);
    }
    this.packets = packetlist || new packet.List();
}

/**
 * Returns the key IDs of the keys that signed the ExternallyHashedSignatureValidation
 * @return {Array<module:type/keyid>} array of keyid objects
 */
ExternallyHashedSignatureValidation.prototype.getSigningKeyIds = function () {
    var keyIds = [];

    // search for one pass signatures
    var onePassSigList = this.packets.filterByTag(enums.packet.onePassSignature);
    onePassSigList.forEach(function (packet) {
        keyIds.push(packet.signingKeyId);
    });
    // if nothing found look for signature packets
    if (!keyIds.length) {
        var signatureList = this.packets.filterByTag(enums.packet.signature);
        signatureList.forEach(function (packet) {
            keyIds.push(packet.issuerKeyId);
        });
    }
    return keyIds;
};

/**
 * Get hash algorithm from signature
 * @return {(String)} trailer data for external hashing as binary string
 */
ExternallyHashedSignatureValidation.prototype.getHashAlgorithm = function () {
    var signatureList = this.packets.filterByTag(enums.packet.signature);
    if (signatureList.length != 1) {
        throw new Error("Invalid number of signatures");
    }
    var signature = signatureList[0];

    return util.get_hashAlgorithmString(signature.hashAlgorithm);
}

/**
 * Get trailer data for external hashing
 * @return {(String)} trailer data for external hashing as binary string
 */
ExternallyHashedSignatureValidation.prototype.getHashTrailerData = function () {

    var signatureList = this.packets.filterByTag(enums.packet.signature);
    if (signatureList.length != 1) {
        throw new Error("Invalid number of signatures");
    }
    var signature = signatureList[0];

    return signature.signatureData + signature.calculateTrailer();

};


/**
 * Verify ExternallyHashedSignatureValidation signatures
 * @param {Array<module:key~Key>} keys array of keys to verify signatures
 * @param {String} hash to verify as binary string
 * @return {Array<({keyid: module:type/keyid, valid: Boolean})>} list of signer's keyid and validity of signature
 */
ExternallyHashedSignatureValidation.prototype.verifyHash = function (keys, hash) {
    var result = [];

    var signatureList = this.packets.filterByTag(enums.packet.signature);

    if (signatureList.length != 1) {
        throw new Error("Invalid number of signatures");
    }
    var signature = signatureList[0];

    var keyPacket = null;
    for (var j = 0; j < keys.length; j++) {
        keyPacket = keys[j].getKeyPacket([signature.issuerKeyId]);
        if (keyPacket) {
            break;
        }
    }

    var verifiedSig = {};
    if (keyPacket) {
        verifiedSig.keyid = signature.issuerKeyId;
        verifiedSig.valid = signature.verifyHash(keyPacket, hash);
    } else {
        verifiedSig.keyid = signature.issuerKeyId;
        verifiedSig.valid = null;
    }

    return verifiedSig;
};


/**
 * reads an OpenPGP armored signature and returns a ExternallyHashedSignatureValidation object
 * @param {String} armoredText text to be parsed
 * @return {module:ExternallyHashedSignatureValidation~ExternallyHashedSignatureValidation} new ExternallyHashedSignatureValidation object
 * @static
 */
function readArmoredSignature(armoredText) {
    var input = armor.decode(armoredText).data;
    var packetlist = new packet.List();
    packetlist.read(input);
    if (packetlist[0].tag !== enums.packet.signature) {
        throw new Error("Not a signature");
    }
    var newPreHashedMessage = new ExternallyHashedSignatureValidation(packetlist);
    return newPreHashedMessage;
}

exports.ExternallyHashedSignatureValidation = ExternallyHashedSignatureValidation;
exports.readArmoredSignature = readArmoredSignature;
