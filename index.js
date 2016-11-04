const crypto = require('crypto');

module.exports = function(options) {
  this.lifecycle = (options && options.tokenLifecycle >= 0)
    ? Math.ceil(options.tokenLifecycle * 1000)
    : 180000; // 3 minutes

  this.iter = (options && options.pbkdf2Iterations > 1)
    ? Math.ceil(options.pbkdf2Iterations)
    : 1; // single iteration

  this.len = (options && options.hmacLength >= 16 && options.hmacLength <= 32)
    ? Math.ceil(options.hmacLength)
    : 16; // 16 octets

  this.pwd = crypto.randomBytes(32);

  this.generate = function(payload, callback) {
    if (typeof payload !== 'string') {
      callback('Error: Input data is not a string');
    } else {
      if (this.lifecycle > 0) {
        var data = JSON.stringify({p: payload, e: Date.now() + this.lifecycle});
      } else {
        var data = JSON.stringify({p: payload});
      }
      var salt = crypto.randomBytes(16);
      crypto.pbkdf2(this.pwd, salt, this.iter, 16, 'sha256', (error, key) => {
        if (error) {
          callback('Error: Could not generate signature key');
        } else {
          var hash = crypto.createHmac('sha256', key);
          hash.update(data);
          var mac = Buffer.concat([salt, hash.digest().slice(0, this.len)]);
          var dataB64u = b64tob64url(Buffer.from(data).toString('base64'));
          callback(null, dataB64u + '.' + b64tob64url(mac.toString('base64')));
        }
      });
    }
  }

  this.verify = function(token, callback) {
    var tokenComponents = token.split('.');
    var data = Buffer.from(tokenComponents[0], 'base64');
    var mac = Buffer.from(tokenComponents[1] || '', 'base64');
    var salt = mac.slice(0, 16);
    crypto.pbkdf2(this.pwd, salt, this.iter, 16, 'sha256', (error, key) => {
      if (error) {
        callback('Error: Could not verify token');
      } else {
        var hash = crypto.createHmac('sha256', key);
        hash.update(data);
        if (mac.slice(16).equals(hash.digest().slice(0, this.len))) {
          try {
            var parsedData = JSON.parse(data.toString());
            if (parsedData.e && Date.now() > parsedData.e) {
              callback('Error: Expired token');
            } else {
              callback(null, parsedData.p);
            }
          } catch (error) {
            callback('Error: Invalid token');
          }
        } else {
          callback('Error: Invalid token');
        }
      }
    });
  }
}

// ============================================================================

function b64tob64url(str) {
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
