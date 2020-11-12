/*
 This file is part of web3.js.

 web3.js is free software: you can redistribute it and/or modify
 it under the terms of the GNU Lesser General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 web3.js is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Lesser General Public License for more details.

 You should have received a copy of the GNU Lesser General Public License
 along with web3.js.  If not, see <http://www.gnu.org/licenses/>.
 */
/**
 * @file accounts.js
 * @author Fabian Vogelsteller <fabian@ethereum.org>
 * @date 2017
 */

'use strict';

var _ = require('underscore');
var core = require('web3-core');
var Method = require('web3-core-method');
var Promise = require('any-promise');
var Account = require('eth-lib/lib/account');
var Hash = require('eth-lib/lib/hash');
var RLP = require('eth-lib/lib/rlp');// jshint ignore:line
var rlp = require('rlp');
var Bytes = require('eth-lib/lib/bytes');// jshint ignore:line
var cryp = (typeof global === 'undefined') ? require('crypto-browserify') : require('crypto');
var scrypt = require('@web3-js/scrypt-shim');
var uuid = require('uuid');
var utils = require('web3-utils');
var helpers = require('web3-core-helpers');
var Transaction = require('ethereumjs-tx').Transaction;
var ethUtil = require("ethereumjs-util");
var Common = require('ethereumjs-common').default;
var sm2 = require('@fksyuan/sm-crypto').sm2;
var sm3 = require('@fksyuan/sm-crypto').sm3;
var elliptic = require("elliptic");
var secp256k1 = new elliptic.ec("secp256k1");
var BN = require('bn.js');
var Nat = require("eth-lib/lib/nat");
var sm2Util = require('@fksyuan/sm-crypto/src/sm2/utils');


var isNot = function(value) {
    return (_.isUndefined(value) || _.isNull(value));
};

var Accounts = function Accounts() {
    var _this = this;

    // sets _requestmanager
    core.packageInit(this, arguments);

    // remove unecessary core functions
    delete this.BatchRequest;
    delete this.extend;

    var _ethereumCall = [
        new Method({
            name: 'getNetworkId',
            call: 'net_version',
            params: 0,
            outputFormatter: parseInt
        }),
        new Method({
            name: 'getChainId',
            call: 'platon_chainId',
            params: 0,
            outputFormatter: utils.hexToNumber
        }),
        new Method({
            name: 'getGasPrice',
            call: 'platon_gasPrice',
            params: 0
        }),
        new Method({
            name: 'getTransactionCount',
            call: 'platon_getTransactionCount',
            params: 2,
            inputFormatter: [function(address) {
                if (utils.isBech32Address(address)) {
                    return address;
                } else {
                    throw new Error('Address ' + address + ' is not a valid address to get the "transactionCount".');
                }
            }, function() {
                return 'latest';
            }]
        })
    ];
    // attach methods to this._ethereumCall
    this._ethereumCall = {};
    _.each(_ethereumCall, function(method) {
        method.attachToObject(_this._ethereumCall);
        method.setRequestManager(_this._requestManager);
    });

    this.signType = 'secp256k1';
    this.hashType = 'sha3';

    this.wallet = new Wallet(this);
};

Accounts.prototype.setSignType = function(signType) {
    this.signType = signType;
    return;
};

Accounts.prototype.setHashType = function(hashType) {
    this.hashType = hashType;
    return;
};

Accounts.prototype._addAccountFunctions = function(account) {
    var _this = this;
    var address = utils.toBech32Address("lax", account.address);
    account.address = address;
    // add sign functions
    account.signTransaction = function signTransaction(tx, callback) {
        return _this.signTransaction(tx, account.privateKey, callback);
    };
    account.sign = function sign(data) {
        return _this.sign(data, account.privateKey);
    };

    account.encrypt = function encrypt(password, options) {
        return _this.encrypt(account.privateKey, password, options);
    };

    return account;
};

Accounts.prototype.fromPrivate = function fromPrivate(privateKey) {
    var publicKey = "";
    var publicHash = "";
    var address = "";
    if (this.signType === 'sm2') {
        privateKey = privateKey.startsWith('0x') ? privateKey.slice(2) : privateKey;
        publicKey = "0x" + sm2.getPublicKeyFromPrivateKey(privateKey).slice(2);
        if (this.hashType === 'sm3') {
            publicHash = sm3(String.fromCharCode.apply(null, utils.hexToBytes(publicKey)));
        } else {
            publicHash = Hash.keccak256(publicKey);
        }
        address = "0x" + publicHash.slice(-40);
        return {
            address: address,
            privateKey: privateKey
        };
    } else {
        var buffer = new Buffer(privateKey.slice(2), "hex");
        var ecKey = secp256k1.keyFromPrivate(buffer);
        publicKey = "0x" + ecKey.getPublic(false, 'hex').slice(2);
        if (this.hashType === 'sm3') {
            publicHash = sm3(String.fromCharCode.apply(null, utils.hexToBytes(publicKey)));
        } else {
            publicHash = Hash.keccak256(publicKey);
        }
        address = "0x" + publicHash.slice(-40);
        return {
            address: address,
            privateKey: privateKey
        };
    }
};

Accounts.prototype.create = function create(entropy) {
    entropy = entropy || utils.randomHex(32);
    var innerHex = "";
    if (this.hashType === 'sm3') {
        innerHex = sm3(String.fromCharCode.apply(null, utils.hexToBytes(Bytes.concat(Bytes.random(32), entropy || Bytes.random(32)))));
    } else {
        innerHex = Hash.keccak256(Bytes.concat(Bytes.random(32), entropy || Bytes.random(32)));
    }
    var middleHex = Bytes.concat(Bytes.concat(Bytes.random(32), innerHex), Bytes.random(32));
    var outerHex = "";
    if (this.hashType === 'sm3') {
        outerHex = sm3(String.fromCharCode.apply(null, utils.hexToBytes(middleHex)));
    } else {
        outerHex = Hash.keccak256(middleHex);
    }
    var account = this.fromPrivate(outerHex);
    return this._addAccountFunctions(account);
};

Accounts.prototype.privateKeyToAccount = function privateKeyToAccount(privateKey) {
    return this._addAccountFunctions(this.fromPrivate(privateKey));
};

Accounts.prototype.signTransaction = function signTransaction(tx, privateKey, callback) {
    var _this = this,
        error = false,
        transactionOptions = {},
        hasTxSigningOptions = !!(tx && ((tx.chain && tx.hardfork) || tx.common));

    callback = callback || function() {
    };

    if (!tx) {
        error = new Error('No transaction object given!');

        callback(error);
        return Promise.reject(error);
    }

    function signed (tx, options) {
        if (tx.common && (tx.chain && tx.hardfork)) {
            error = new Error(
                'Please provide the ethereumjs-common object or the chain and hardfork property but not all together.'
            );
        }

        if ((tx.chain && !tx.hardfork) || (tx.hardfork && !tx.chain)) {
            error = new Error(
                'When specifying chain and hardfork, both values must be defined. ' +
                'Received "chain": ' + tx.chain + ', "hardfork": ' + tx.hardfork
            );
        }

        if (!tx.gas && !tx.gasLimit) {
            error = new Error('"gas" is missing');
        }

        if (tx.nonce < 0 ||
            tx.gas < 0 ||
            tx.gasPrice < 0 ||
            tx.chainId < 0) {
            error = new Error('Gas, gasPrice, nonce or chainId is lower than 0');
        }

        if (error) {
            callback(error);
            return Promise.reject(error);
        }

        try {
            var transaction = helpers.formatters.inputCallFormatter(_.clone(tx));
        //    transaction.to = transaction.to || '0x';
            transaction.data = transaction.data || '0x';
            transaction.value = transaction.value || '0x';
            transaction.chainId = utils.numberToHex(transaction.chainId);

            if(transaction.to && utils.isBech32Address(transaction.to)) {
                let hrp = "lax";
                transaction.to = utils.decodeBech32Address(hrp, transaction.to);
            }

            // Because tx has no ethereumjs-tx signing options we use fetched vals.
            if (!hasTxSigningOptions) {
                transactionOptions.common = Common.forCustomChain(
                    'mainnet',
                    {
                        name: 'custom-network',
                        networkId: transaction.networkId,
                        chainId: transaction.chainId
                    },
                    'petersburg'
                );

                delete transaction.networkId;
            } else {
                if (transaction.common) {
                    transactionOptions.common = Common.forCustomChain(
                        transaction.common.baseChain || 'mainnet',
                        {
                            name: transaction.common.customChain.name || 'custom-network',
                            networkId: transaction.common.customChain.networkId,
                            chainId: transaction.common.customChain.chainId
                        },
                        transaction.common.hardfork || 'petersburg'
                    );

                    delete transaction.common;
                }

                if (transaction.chain) {
                    transactionOptions.chain = transaction.chain;
                    delete transaction.chain;
                }

                if (transaction.hardfork) {
                    transactionOptions.hardfork = transaction.hardfork;
                    delete transaction.hardfork;
                }
            }

            if (privateKey.startsWith('0x')) {
                privateKey = privateKey.substring(2);
            }

            var ethTx = new Transaction(transaction, transactionOptions);

            var result = {};
            var rlpEncoded = '';
            var rawTransaction = '';
            var transactionHash = '';
            if (options.signType === 'sm2') {
                var item = ethTx.raw.slice(0, 6).concat([
                    ethUtil.toBuffer(tx.chainId),
                    ethUtil.stripZeros(ethUtil.toBuffer(0)),
                    ethUtil.stripZeros(ethUtil.toBuffer(0)),
                ]);
                var txRlp = rlp.encode(item);
                var msgHash = "";
                if (options.hashType === 'sm3') {
                    msgHash = sm3(String.fromCharCode.apply(null, utils.hexToBytes('0x' + txRlp.toString('hex'))));
                } else {
                    msgHash = utils.keccak256(txRlp);
                }
                var signature = sm2.doSignature(sm2Util.hexToArray(msgHash), privateKey);
                const decodeSignature = hex => [Bytes.slice(0, 32, hex), Bytes.slice(32, 64, hex), Bytes.slice(64, Bytes.length(hex), hex)];
                const encodeSignature = ([v, r, s]) => Bytes.flatten([r, s, v]);
                var vrs = decodeSignature('0x' + signature);
                var sig = {
                    messageHash: msgHash,
                    v: utils.numberToHex(utils.hexToNumber(vrs[2]) + 27),
                    r: vrs[0],
                    s: vrs[1],
                    signature: encodeSignature([Nat.fromString(Bytes.fromNumber(utils.hexToNumber(vrs[2]) + 27)), Bytes.pad(32, Bytes.fromNat(vrs[0])), Bytes.pad(32, Bytes.fromNat(vrs[1]))])
                }
                // var sig = _this.sign(msgHash, privateKey);
                sig.v = utils.numberToHex(utils.hexToNumber(sig.v) + tx.chainId*2 + 8);
                vrs = {
                    v: sig.v,
                    r: sig.r,
                    s: sig.s
                };
                Object.assign(ethTx, vrs);
                // check gas is enough
                if (ethTx.getBaseFee().cmp(new BN(ethTx.gasLimit)) > 0) {
                    throw new Error(`gas limit is too low. Need at least ${ethTx.getBaseFee()}`);
                }
                rlpEncoded = ethTx.serialize().toString('hex');
                rawTransaction = '0x' + rlpEncoded;
                transactionHash = "";
                if (options.hashType === 'sm3') {
                    transactionHash = sm3(String.fromCharCode.apply(null, utils.hexToBytes(rawTransaction)));
                } else {
                    transactionHash = utils.keccak256(rawTransaction);
                }
                result = {
                    messageHash: "0x" + msgHash,
                    v: '0x' + Buffer.from(ethTx.v).toString('hex'),
                    r: '0x' + Buffer.from(ethTx.r).toString('hex'),
                    s: '0x' + Buffer.from(ethTx.s).toString('hex'),
                    rawTransaction: rawTransaction,
                    transactionHash: '0x' + transactionHash
                };
            } else {
                ethTx.sign(Buffer.from(privateKey, 'hex'));

                var validationResult = ethTx.validate(true);

                if (validationResult !== '') {
                    throw new Error('Signer Error: ' + validationResult);
                }

                rlpEncoded = ethTx.serialize().toString('hex');
                rawTransaction = '0x' + rlpEncoded;
                transactionHash = utils.keccak256(rawTransaction);

                result = {
                    messageHash: '0x' + Buffer.from(ethTx.hash(false)).toString('hex'),
                    v: '0x' + Buffer.from(ethTx.v).toString('hex'),
                    r: '0x' + Buffer.from(ethTx.r).toString('hex'),
                    s: '0x' + Buffer.from(ethTx.s).toString('hex'),
                    rawTransaction: rawTransaction,
                    transactionHash: transactionHash
                };
            }

            callback(null, result);
            return result;

        } catch (e) {
            callback(e);
            return Promise.reject(e);
        }
    }


    // Resolve immediately if nonce, chainId, price and signing options are provided
    if (tx.nonce !== undefined && tx.chainId !== undefined && tx.gasPrice !== undefined && hasTxSigningOptions) {
        return Promise.resolve(signed(tx, {'signType': _this.signType, 'hashType': _this.hashType}));
    }

    // Otherwise, get the missing info from the Ethereum Node
    var netType = "mainnet";
    var bech32Address = _this.privateKeyToAccount(privateKey).address;
    return Promise.all([
        isNot(tx.chainId) ? _this._ethereumCall.getChainId() : tx.chainId,
        isNot(tx.gasPrice) ? _this._ethereumCall.getGasPrice() : tx.gasPrice,
        //isNot(tx.nonce) ? _this._ethereumCall.getTransactionCount(_this.privateKeyToAccount(privateKey).address) : tx.nonce,
        isNot(tx.nonce) ? _this._ethereumCall.getTransactionCount(bech32Address) : tx.nonce,
        isNot(hasTxSigningOptions) ? _this._ethereumCall.getNetworkId() : 1
    ]).then(function(args) {
        if (isNot(args[0]) || isNot(args[1]) || isNot(args[2]) || isNot(args[3])) {
            throw new Error('One of the values "chainId", "networkId", "gasPrice", or "nonce" couldn\'t be fetched: ' + JSON.stringify(args));
        }
        return signed(_.extend(tx, {chainId: args[0], gasPrice: args[1], nonce: args[2], networkId: args[3]}), {'signType': _this.signType, 'hashType': _this.hashType});
    });
};

/* jshint ignore:start */
Accounts.prototype.recoverTransaction = function recoverTransaction(rawTx) {
    var values = RLP.decode(rawTx);
    var signature = Account.encodeSignature(values.slice(6, 9));
    var recovery = Bytes.toNumber(values[6]);
    var extraData = recovery < 35 ? [] : [Bytes.fromNumber((recovery - 35) >> 1), '0x', '0x'];
    var signingData = values.slice(0, 6).concat(extraData);
    var signingDataHex = RLP.encode(signingData);
    return Account.recover(Hash.keccak256(signingDataHex), signature);
};
/* jshint ignore:end */

Accounts.prototype.hashMessage = function hashMessage(data) {
    var message = utils.isHexStrict(data) ? utils.hexToBytes(data) : data;
    var messageBuffer = Buffer.from(message);
    var preamble = '\x19Ethereum Signed Message:\n' + message.length;
    var preambleBuffer = Buffer.from(preamble);
    var ethMessage = Buffer.concat([preambleBuffer, messageBuffer]);
    if (this.hashType === 'sm3') {
        return sm3(ethMessage.toString());
    } else {
        return Hash.keccak256s(ethMessage);
    }
};

Accounts.prototype.sign = function sign(data, privateKey) {
    var hash = this.hashMessage(data);
    var signature = "";
    var vrs = null;
    if (this.signType === 'sm2') {
        signature = sm2.doSignature(hash, privateKey);
        const decodeSignature = hex => [Bytes.slice(0, 32, hex), Bytes.slice(32, 64, hex), Bytes.slice(64, Bytes.length(hex), hex)];
        const encodeSignature = ([v, r, s]) => Bytes.flatten([r, s, v]);
        vrs = decodeSignature('0x' + signature);
        return {
            message: data,
            messageHash: hash,
            v: utils.numberToHex(utils.hexToNumber(vrs[2]) + 27),
            r: vrs[0],
            s: vrs[1],
            signature: encodeSignature([Nat.fromString(Bytes.fromNumber(utils.hexToNumber(vrs[2]) + 27)), Bytes.pad(32, Bytes.fromNat(vrs[0])), Bytes.pad(32, Bytes.fromNat(vrs[1]))])
        };
    } else {
        signature = Account.sign(hash, privateKey);
        vrs = Account.decodeSignature(signature);
        return {
            message: data,
            messageHash: hash,
            v: vrs[0],
            r: vrs[1],
            s: vrs[2],

            signature: signature
        };
    }
};

Accounts.prototype.recover = function recover(message, signature, preFixed) {
    var args = [].slice.apply(arguments);


    if (_.isObject(message)) {
        return this.recover(message.messageHash, Account.encodeSignature([message.v, message.r, message.s]), true);
    }

    if (!preFixed) {
        message = this.hashMessage(message);
    }

    if (args.length >= 4) {
        preFixed = args.slice(-1)[0];
        preFixed = _.isBoolean(preFixed) ? !!preFixed : false;

        return this.recover(message, Account.encodeSignature(args.slice(1, 4)), preFixed); // v, r, s
    }
    return Account.recover(message, signature);
};

// Taken from https://github.com/ethereumjs/ethereumjs-wallet
Accounts.prototype.decrypt = function(v3Keystore, password, nonStrict) {
    /* jshint maxcomplexity: 10 */

    if (!_.isString(password)) {
        throw new Error('No password given.');
    }

    var json = (_.isObject(v3Keystore)) ? v3Keystore : JSON.parse(nonStrict ? v3Keystore.toLowerCase() : v3Keystore);

    if (json.version !== 3) {
        throw new Error('Not a valid V3 wallet');
    }

    var derivedKey;
    var kdfparams;
    if (json.crypto.kdf === 'scrypt') {
        kdfparams = json.crypto.kdfparams;

        // FIXME: support progress reporting callback
        derivedKey = scrypt(Buffer.from(password), Buffer.from(kdfparams.salt, 'hex'), kdfparams.n, kdfparams.r, kdfparams.p, kdfparams.dklen);
    } else if (json.crypto.kdf === 'pbkdf2') {
        kdfparams = json.crypto.kdfparams;

        if (kdfparams.prf !== 'hmac-sha256') {
            throw new Error('Unsupported parameters to PBKDF2');
        }

        derivedKey = cryp.pbkdf2Sync(Buffer.from(password), Buffer.from(kdfparams.salt, 'hex'), kdfparams.c, kdfparams.dklen, 'sha256');
    } else {
        throw new Error('Unsupported key derivation scheme');
    }

    var ciphertext = Buffer.from(json.crypto.ciphertext, 'hex');

    var mac = "";
    if (this.hashType === 'sm3') {
        mac = sm3(String.fromCharCode.apply(null, utils.hexToBytes("0x" + Buffer.concat([derivedKey.slice(16, 32), ciphertext]).toString('hex'))));
    } else {
        mac = utils.sha3(Buffer.concat([derivedKey.slice(16, 32), ciphertext])).replace('0x', '');
    }
    if (mac !== json.crypto.mac) {
        throw new Error('Key derivation failed - possibly wrong password');
    }

    var decipher = cryp.createDecipheriv(json.crypto.cipher, derivedKey.slice(0, 16), Buffer.from(json.crypto.cipherparams.iv, 'hex'));
    var seed = '0x' + Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('hex');

    return this.privateKeyToAccount(seed);
};

Accounts.prototype.encrypt = function(privateKey, password, options) {
    /* jshint maxcomplexity: 20 */
    var account = this.privateKeyToAccount(privateKey);

    options = options || {};
    var salt = options.salt || cryp.randomBytes(32);
    var iv = options.iv || cryp.randomBytes(16);

    var derivedKey;
    var kdf = options.kdf || 'scrypt';
    var kdfparams = {
        dklen: options.dklen || 32,
        salt: salt.toString('hex')
    };

    if (kdf === 'pbkdf2') {
        kdfparams.c = options.c || 262144;
        kdfparams.prf = 'hmac-sha256';
        derivedKey = cryp.pbkdf2Sync(Buffer.from(password), Buffer.from(kdfparams.salt, 'hex'), kdfparams.c, kdfparams.dklen, 'sha256');
    } else if (kdf === 'scrypt') {
        // FIXME: support progress reporting callback
        kdfparams.n = options.n || 8192; // 2048 4096 8192 16384
        kdfparams.r = options.r || 8;
        kdfparams.p = options.p || 1;
        derivedKey = scrypt(Buffer.from(password), Buffer.from(kdfparams.salt, 'hex'), kdfparams.n, kdfparams.r, kdfparams.p, kdfparams.dklen);
    } else {
        throw new Error('Unsupported kdf');
    }

    var cipher = cryp.createCipheriv(options.cipher || 'aes-128-ctr', derivedKey.slice(0, 16), iv);
    if (!cipher) {
        throw new Error('Unsupported cipher');
    }

    var ciphertext = Buffer.concat([cipher.update(Buffer.from(account.privateKey.replace('0x', ''), 'hex')), cipher.final()]);

    var mac = "";
    if (this.hashType === 'sm3') {
        mac = sm3(String.fromCharCode.apply(null, utils.hexToBytes("0x" + Buffer.concat([derivedKey.slice(16, 32), Buffer.from(ciphertext, 'hex')]).toString('hex'))));
    } else {
        mac = utils.sha3(Buffer.concat([derivedKey.slice(16, 32), Buffer.from(ciphertext, 'hex')])).replace('0x', '');
    }

    return {
        version: 3,
        id: uuid.v4({random: options.uuid || cryp.randomBytes(16)}),
        //address: account.address.toLowerCase().replace('0x', ''),
        address: account.address,
        crypto: {
            ciphertext: ciphertext.toString('hex'),
            cipherparams: {
                iv: iv.toString('hex')
            },
            cipher: options.cipher || 'aes-128-ctr',
            kdf: kdf,
            kdfparams: kdfparams,
            mac: mac.toString('hex')
        }
    };
};


// Note: this is trying to follow closely the specs on
// http://web3js.readthedocs.io/en/1.0/web3-eth-accounts.html

function Wallet(accounts) {
    this._accounts = accounts;
    this.length = 0;
    this.defaultKeyName = 'web3js_wallet';
}

Wallet.prototype._findSafeIndex = function(pointer) {
    pointer = pointer || 0;
    if (_.has(this, pointer)) {
        return this._findSafeIndex(pointer + 1);
    } else {
        return pointer;
    }
};

Wallet.prototype._currentIndexes = function() {
    var keys = Object.keys(this);
    var indexes = keys
        .map(function(key) {
            return parseInt(key);
        })
        .filter(function(n) {
            return (n < 9e20);
        });

    return indexes;
};

Wallet.prototype.create = function(numberOfAccounts, entropy) {
    for (var i = 0; i < numberOfAccounts; ++i) {
        this.add(this._accounts.create(entropy).privateKey);
    }
    return this;
};

Wallet.prototype.add = function(account) {

    if (_.isString(account)) {
        account = this._accounts.privateKeyToAccount(account);
    }
    if (!this[account.address]) {
        account = this._accounts.privateKeyToAccount(account.privateKey);
        account.index = this._findSafeIndex();

        this[account.index] = account;
        //this[account.address.toLowerCase()] = account;
        this[account.address] = account;
        this.length++;

        return account;
    } else {
        return this[account.address];
    }
};

Wallet.prototype.remove = function(addressOrIndex) {
    var account = this[addressOrIndex];

    if (account && account.address) {
        // address
        this[account.address].privateKey = null;
        delete this[account.address];
        // address lowercase
        //this[account.address.toLowerCase()].privateKey = null;
        //delete this[account.address.toLowerCase()];

        // index
        this[account.index].privateKey = null;
        delete this[account.index];

        this.length--;

        return true;
    } else {
        return false;
    }
};

Wallet.prototype.clear = function() {
    var _this = this;
    var indexes = this._currentIndexes();

    indexes.forEach(function(index) {
        _this.remove(index);
    });

    return this;
};

Wallet.prototype.encrypt = function(password, options) {
    var _this = this;
    var indexes = this._currentIndexes();

    var accounts = indexes.map(function(index) {
        return _this[index].encrypt(password, options);
    });

    return accounts;
};


Wallet.prototype.decrypt = function(encryptedWallet, password) {
    var _this = this;

    encryptedWallet.forEach(function(keystore) {
        var account = _this._accounts.decrypt(keystore, password);

        if (account) {
            _this.add(account);
        } else {
            throw new Error('Couldn\'t decrypt accounts. Password wrong?');
        }
    });

    return this;
};

Wallet.prototype.save = function(password, keyName) {
    localStorage.setItem(keyName || this.defaultKeyName, JSON.stringify(this.encrypt(password)));

    return true;
};

Wallet.prototype.load = function(password, keyName) {
    var keystore = localStorage.getItem(keyName || this.defaultKeyName);

    if (keystore) {
        try {
            keystore = JSON.parse(keystore);
        } catch (e) {

        }
    }

    return this.decrypt(keystore || [], password);
};

if (!storageAvailable('localStorage')) {
    delete Wallet.prototype.save;
    delete Wallet.prototype.load;
}

/**
 * Checks whether a storage type is available or not
 * For more info on how this works, please refer to MDN documentation
 * https://developer.mozilla.org/en-US/docs/Web/API/Web_Storage_API/Using_the_Web_Storage_API#Feature-detecting_localStorage
 *
 * @method storageAvailable
 * @param {String} type the type of storage ('localStorage', 'sessionStorage')
 * @returns {Boolean} a boolean indicating whether the specified storage is available or not
 */
function storageAvailable(type) {
    var storage;
    try {
        storage = window[type];
        var x = '__storage_test__';
        storage.setItem(x, x);
        storage.removeItem(x);
        return true;
    } catch (e) {
        return e && (
                // everything except Firefox
            e.code === 22 ||
            // Firefox
            e.code === 1014 ||
            // test name field too, because code might not be present
            // everything except Firefox
            e.name === 'QuotaExceededError' ||
            // Firefox
            e.name === 'NS_ERROR_DOM_QUOTA_REACHED') &&
            // acknowledge QuotaExceededError only if there's something already stored
            (storage && storage.length !== 0);
    }
}

module.exports = Accounts;
