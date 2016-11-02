const crypto = require('crypto');

module.exports = function(options) {
  this.lifecycle = (options && options.tokenLifecycle > 0)
    ? Math.ceil(options.tokenLifecycle * 1000)
    : 18000; // 3 minutes

  this.iter = (options && options.pbkdf2Iterations > 1)
    ? Math.ceil(options.pbkdf2Iterations)
    : 1; // single iteration

  this.pwd = crypto.randomBytes(32);

  this.generate = function(payload, callback) {
    if (typeof payload !== 'string') {
      callback('Error: Input data is not a string');
    } else {
      var data = JSON.stringify({p: payload, e: Date.now() + this.lifecycle});
      var salt = crypto.randomBytes(16);
      crypto.pbkdf2(this.pwd, salt, this.iter, 16, 'sha256', (error, key) => {
        if (error) {
          callback('Error: Could not generate signature key');
        } else {
          var hash = crypto.createHmac('sha256', key);
          hash.update(data);
          var signature = Buffer.concat([salt, hash.digest().slice(0, 16)]);
          callback(null, b64urlencode(data) + '.' + b64urlencode(signature));
        }
      });
    }
  }

  this.verify = function(token, callback) {
    var tokenComponents = token.split('.');
    var data = b64urldecode(tokenComponents[0]);
    var signature = b64urldecode(tokenComponents[1] || '');
    var salt = signature.slice(0, 16);
    crypto.pbkdf2(this.pwd, salt, this.iter, 16, 'sha256', (error, key) => {
      if (error) {
        callback('Error: Could not verify token');
      } else {
        var hash = crypto.createHmac('sha256', key);
        hash.update(data);
        if (signature.slice(16).equals(hash.digest().slice(0, 16))) {
          try {
            var parsedData = JSON.parse(data.toString());
            if (Date.now() > parsedData.e) {
              callback('Error: Expired token');
            } else {
              callback(null, parsedData.p);
            }
          } catch (error) {
            callback('Error: Invalid token -');
          }
        } else {
          callback('Error: Invalid token');
        }
      }
    });
  }
}

// ============================================================================

function b64urlencode(str) {
  return Buffer.from(str)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function b64urldecode(str) {
  return Buffer.from(str.replace(/\-/g, '+').replace(/_/g, '/'), 'base64');
}
