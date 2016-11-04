const TokenHandler = require('node-selftoken');

// ===== INITIALIZE THE TOKEN HANDLER =====

var selftoken = new TokenHandler({
  tokenLifecycle: 3,  // This is a very short-lived token (3 seconds)
  pbkdf2Iterations: 10,
  hmacLength: 32
});

// ===== TEST CASES =====

// INVALID INPUT
console.log('\nCalling token generation API with input other than string...');
selftoken.generate(1000, (error, token) => {
  console.log('Error message:\n', error.message);

  // POSITIVE CASE
  console.log('\nCalling token generation API with valid input...');
  var str = 'Hello Node.js world!';
  console.log('Input string:\n', str);
  selftoken.generate(str, (error, token) => {
    console.log('Token:\n', token);
    console.log('\nVerifying the token...');
    selftoken.verify(token, (error, result) => {
      console.log('Error object:\n', error);
      console.log('Validated string:\n', result);

      // EXPIRED TOKEN
      console.log('\nGenerating a fresh token...');
      selftoken.generate(str, (error, token) => {
        console.log('Waiting for 5s and then verifying the token...');
        setTimeout(() => {
          selftoken.verify(token, (error, result) => {
            console.log('Error message:\n', error.message);

            // TAMPERED TOKEN - TRIVIAL CHAR REPLACEMENT CASE
            console.log('\nGenerating a new token...');
            selftoken.generate(str, (error, token) => {
              console.log('Creating tampered version of the token...');
              var tamperedToken = token.replace(token[10], '&');
              console.log('Verifying the tampered token...');
              selftoken.verify(tamperedToken, (error, result) => {
                console.log('Error message:\n', error.message);
              });
            });
          });
        }, 5000); // 5s wait
      });
    });
  });
});
