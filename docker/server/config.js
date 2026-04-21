'use strict';

exports.port = 8000;
exports.bindaddress = '0.0.0.0';

exports.loginserver = process.env.LOGIN_SERVER_URL || 'http://login:3001/api/';
exports.loginserverkeyalgo = "RSA-SHA1";
exports.loginserverpublickeyid = 1;
exports.loginserverpublickey =
	`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1rhkcUW0oAcjEqsIr9SR
8klKeVhPDa5NbEWmqii2YCaL+igZM3Q2ZYFqKFS1L/KpURO69gq/abhdWwiB4+lV
zI8ZmYXYGxxZCxwwPu4rBKlCq/TCdj3L8ocYFxAz3rcNU0AjUsjxB22cg7dC9SzE
GbPrw9kSKDhqKrfufag+cNj2ZctVn0i2N01VSM7ViWW8TBdvHreTRDDDDFjPW/VU
qFCCzJLp11zBZ8bmJGv5e6jE24wdaFqonFzcynoWye2Bzr3zRmokSYPFWT0uYlok
msnbpVBVfY31zeknrGNYqygkXv1pI/4vcZK2Rv5b29HbW+iso1k+Kh2lIvbr0Ev9
5wIDAQAB
-----END PUBLIC KEY-----`;

exports.routes = {
	root: 'localhost',
	client: 'localhost',
	dex: 'dex.pokemonshowdown.com',
	replays: 'localhost',
};

exports.crashguard = true;
exports.reportjoins = true;
exports.reportbattles = true;
exports.reportbattlejoins = true;
exports.forcetimer = true;
exports.backdoor = false;
exports.consoleips = ['127.0.0.1'];
exports.watchconfig = true;
exports.logchat = false;
exports.logchallenges = false;

exports.subprocesses = {
	network: 1,
	simulator: 1,
	validator: 1,
	verifier: 1,
};
