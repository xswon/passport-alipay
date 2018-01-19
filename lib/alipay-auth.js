'use strict';

const fs = require('fs');
const crypto = require('crypto');

const iconv = require('iconv-lite');
const request = require('request');
const moment = require('moment');

const Promise = require('bluebird');
const NodeRSA = require('node-rsa');

const debug = require('debug')('alipay-auth');
const util = require('util');

// gateway settings
const GATEWAY_URL =
	'https://openapi.alipay.com/gateway.do',
	GATEWAY_SANDBOX =
	'https://openapi.alipaydev.com/gateway.do';

// openauth settings
const OPENAUTH_URL =
	'https://openauth.alipay.com/oauth2/publicAppAuthorize.htm',
	OPENAUTH_SANDBOX =
	'https://openauth.alipaydev.com/oauth2/publicAppAuthorize.htm';

function createPromiseCallback() {
	let cb;
	let promise = new Promise(function(resolve, reject) {
		cb = function(err, data) {
			if (err) return reject(err);
			return resolve(data);
		};
	});
	cb.promise = promise;
	return cb;
}

// 除去数组中的空值和签名参数
let paramsFilter = function(params) {
	let result = {};
	if (!params) {
		return result;
	}
	for (let k in params) {
		if (!params[k] || params[k] === '' || k === 'sign') {
			continue;
		}
		result[k] = params[k];
	}
	return result;
};

// 将所有参数按照“参数=参数值”的模式用“&”字符拼接成字符串
let toQueryString = function(params) {
	let result = '';
	let sortKeys = Object.keys(params).sort();
	for (let i in sortKeys) {
		result += sortKeys[i] + '=' + params[sortKeys[i]] + '&';
	}
	if (result.length > 0) {
		console.log(result);
		return result.slice(0, -1);
	} else {
		return result;
	}
};

// constructor of Alipay
let Alipay = function(options) {
	this._options = options;
	if (options.isDev) {
		this._gateway = GATEWAY_SANDBOX;
		this._authUrl = OPENAUTH_SANDBOX;
	} else {
		this._gateway = GATEWAY_URL;
		this._authUrl = OPENAUTH_URL;
	}
	return this;
};

Alipay.prototype._encryptedParams = function(params) {
	let qs = toQueryString(paramsFilter(params));
	let key = new NodeRSA(fs.readFileSync(this._options.aliKeyPath), {
		encryptionScheme: 'pkcs1'
	});
	let encrypted = key.encrypt(qs, 'base64');
	return encrypted;
};

Alipay.prototype._decryptedParams = function(toDecrypt) {
	let key = new NodeRSA(fs.readFileSync(this._options.privateKeyPath), {
		encryptionScheme: 'pkcs1'
	});
	let decrypted = key.decrypt(toDecrypt, 'utf8');
	return decrypted;
};

Alipay.prototype._generateSign = function(params) {
	let qs = toQueryString(paramsFilter(params));
	let signed = crypto.createSign('sha256WithRSAEncryption')
		.update(new Buffer(qs, 'utf8'))
		.sign(fs.readFileSync(this._options.privateKeyPath), 'base64');
	return signed;
};

Alipay.prototype._verifySign = function(params, signature) {
	let qs = toQueryString(paramsFilter(params));
	let verified = crypto.createVerify('sha256WithRSAEncryption')
		.update(new Buffer(qs, 'utf8'))
		.verify(fs.readFileSync(this._options.aliKeyPath),
			signature, 'base64');
	return verified;
};

Alipay.prototype.getAccessToken = function(code, cb) {
	cb = cb || createPromiseCallback();

	let self = this;

	let params = {
		app_id: self._options.AppID,
		method: 'alipay.system.oauth.token',
		format: 'JSON',
		charset: 'gbk',
		sign_type: 'RSA2',
		timestamp: moment().format('YYYY-MM-DD HH:mm:ss'),
		version: '1.0',
		grant_type: 'authorization_code',
		code: code
	};
	params.sign = self._generateSign(params);
	console.log(util.inspect(params));
	console.log(self._gateway);


	request({
		url: self._gateway,
		method: 'POST',
		form: params,
		encoding: null
	}, function(err, response, body) {
		if (err) {
			cb(err)
		} else {
			let data = JSON.parse(iconv.decode(body, 'GBK'));

			if (data.error_response) {
				cb(new Error(data.error_response.msg));
			} else {
				cb(null, data.alipay_system_oauth_token_response || {});
			}
		}
	});

	return cb.promise;
};

Alipay.prototype.getUser = function(token, cb) {
	cb = cb || createPromiseCallback();

	let self = this;

	let params = {
		app_id: self._options.AppID,
		method: 'alipay.user.info.share',
		format: 'JSON',
		charset: 'gbk',
		sign_type: 'RSA2',
		timestamp: moment().format('YYYY-MM-DD HH:mm:ss'),
		version: '1.0',
		auth_token: token
	};
	params.sign = self._generateSign(params);
	console.log(JSON.stringify(params));
	debug('params: \n'+ JSON.stringify(params));

	request({
		url: self._gateway,
		method: 'POST',
		form: params,
		encoding: null
	}, function(err, response, body) {
		if (err) {
			cb(err)
		} else {
			let data = JSON.parse(iconv.decode(body, 'GBK'));

			if (data.error_response) {
				cb(new Error(data.error_response.msg));
			} else {
				cb(null, data.alipay_user_info_share_response || {});
			}
		}
	});

	return cb.promise;
};

module.exports = Alipay;