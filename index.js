const crypto = require('crypto');

module.exports = function(options) {
  this.lifecycle = (options && options.tokenLifecycle >= 0)
    ? Math.ceil(options.tokenLifecycle * 1000)
    : 180000; // 3 minutes

  this.iter = (options && options.pbkdf2Iterations > 1)
    ? Math.ceil(options.pbkdf2Iterations)
    : 1; // single SHA-256 iteration

  this.len = (options && options.hmacLength >= 16 && options.hmacLength <= 32)
    ? Math.ceil(options.hmacLength)
    : 16; // SHA-256 truncated to 16 octets

  this.pwd = crypto.randomBytes(32);

  this.generate = function(payload, callback) {
    if (typeof payload !== 'string') {
      callback(new Error('Input data is not a string'));
      return;
    }
    if (this.lifecycle > 0) {
      var data = JSON.stringify({p: payload, e: Date.now() + this.lifecycle});
    } else {
      var data = JSON.stringify({p: payload});
    }
    var salt = crypto.randomBytes(16);
    crypto.pbkdf2(this.pwd, salt, this.iter, 16, 'sha256', (error, key) => {
      if (error) {
        callback(error);
        return;
      }
      var hash = crypto.createHmac('sha256', key);
      hash.update(data);
      var mac = Buffer.concat([salt, hash.digest().slice(0, this.len)]);
      var dataB64u = b64tob64url(Buffer.from(data).toString('base64'));
      callback(null, dataB64u + '.' + b64tob64url(mac.toString('base64')));
    });
  }

  this.verify = function(token, callback) {
    if (typeof token !== 'string') {
      callback(new Error('Invalid token'));
      return;
    }
    var tokenComponents = token.split('.');
    var data = Buffer.from(tokenComponents[0], 'base64');
    var mac = Buffer.from(tokenComponents[1] || '', 'base64');
    var salt = mac.slice(0, 16);
    crypto.pbkdf2(this.pwd, salt, this.iter, 16, 'sha256', (error, key) => {
      if (error) {
        callback(error);
        return;
      }
      var hash = crypto.createHmac('sha256', key);
      hash.update(data);
      if (!mac.slice(16).equals(hash.digest().slice(0, this.len))) {
        callback(new Error('Invalid token'));
        return;
      }
      safeParse(data.toString(), (error, parsedData) => {
        if (error) {
          callback(error);
        } else if (parsedData.e && Date.now() > parsedData.e) {
          callback(new Error('Expired token'));
        } else {
          callback(null, parsedData.p);
        }
      });
    });
  }
}

// ============================================================================

function b64tob64url(str) {
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function safeParse(str, callback) {
  try {
    callback(null, JSON.parse(str));
  } catch (error) {
    callback(error);
  }
}
