'use strict';

let util = require('util');
let passport = require('passport-strategy');
let debug = require('debug')('passport-alipay');

let Alipay = require('./alipay-auth');
let JSON = require('json3');

// options should contain fields:
// AppID

// constructor of AlipayStrategy
function AlipayStrategy(options, verify) {
	options = options || {};

	if (!verify) {
		throw new TypeError('AlipayStrategy required a verify callback');
	}

	if (typeof verify !== 'function') {
		throw new TypeError('_verify must be function');
	}

	if (!options.AppID) {
		throw new TypeError('AlipayStrategy requires a AppID option');
	}

	passport.Strategy.call(this, options, verify);

	this.name = options.name || 'alipay';

	this._verify = verify;
	this._oauth = new Alipay(options); // 实例化
	this._AppID = options.AppID;
	this._scope = options.scope || 'auth_user';
	this._state = options.state || 'ALIPAY';
	this._authUrl = this._oauth._authUrl;
	this._gateway = this._oauth._gateway;
	this._callbackURL = options.callbackURL;
	this._passReqToCallback = options.passReqToCallback;
}

/**
 * Inherit from 'passort.Strategy'
 */
util.inherits(AlipayStrategy, passport.Strategy);

AlipayStrategy.prototype.authenticate = function(req, options) {
	let self = this;

	if (!req._passport) {
		return self.error(
			new Error('passport.initialize() middleware not in use'));
	}

	options = options || {};

	// 获取auth_code,并校验相关参数的合法性
	if (req.query && req.query.state && !req.query.auth_code) {
		return self.fail(401);
	}

	if (req.query && req.query.auth_code) {
		// to get accessToken with auth_code 
		let scope = options.scope || self._scope || 'auth_user';
		let auth_code = req.query.auth_code;

		debug('Alipay callback -> \n %s', req.url);

		self._oauth.getAccessToken(auth_code, function(err, params) {
			// 校验完成信息
			function verified(err, user, info) {
				if (err) {
					return self.error(err);
				}
				if (!user) {
					return self.fail(info);
				}
				self.success(user, info);
			}

			if (err) {
				return self.error(err);
			}

			debug('fetch accessToken -> \n %s', JSON.stringify(params));

			if (~scope.indexOf('auth_base')) {
				let profile = {
					id: params.user_id,
					user_id: params.user_id
				};

				try {
					if (self._passReqToCallback) {
						self._verify(req, params['access_token'],
							params['refresh_token'], profile, verified);
					} else {
						self._verify(params['access_token'],
							params['refresh_token'], profile, verified);
					}
				} catch (ex) {
					return self.error(ex);
				}
			} else {
				self._oauth.getUser(params['access_token'],
					function(err, profile) {
						if (err) {
							debug('fetch user info by access_token error ->',
								err.message);
							return self.error(err);
						}

						profile.id = profile.user_id;

						debug('fetch user info -> \n %s',
							JSON.stringify(profile));

						try {
							if (self._passReqToCallback) {
								self._verify(req, params['access_token'],
									params['refresh_token'], profile, verified);
							} else {
								self._verify(params['access_token'],
									params['refresh_token'], profile, verified);
							}
						} catch (ex) {
							return self.error(ex);
						}
					});
			}
		});
	} else { // to get auth_code
		let AppID = options.AppID || self._AppID;
		let scope = options.scope || self._scope || 'auth_user';
		let state = options.state || self._state || 'ALIPAY';
		let callbackURL = options.callbackURL || self._callbackURL;
		let auth_url = self._oauth._authUrl + '?app_id=' + AppID +
			'&scope=' + scope + '&state=' + state + '&redirect_uri=' +
			encodeURIComponent(callbackURL);
		debug('redirect -> \n%s', auth_url);

		self.redirect(auth_url, 302);
	}
};

module.exports = AlipayStrategy;