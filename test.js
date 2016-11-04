const TokenHandler = require('node-selftoken');

// INITIALIZE THE TOKEN HANDLER

var selftoken = new TokenHandler({
  tokenLifecycle: 3,  // This is a very short-lived token (3 seconds)
  pbkdf2Iterations: 10,
  hmacLength: 32
});

// SIMPLE TEST CASES

var str = 'Hello world!';

selftoken.generate(str, (error, token) => {
  console.log('\nHere is the token:', token);

  console.log('\nVerifying the token...\n');
  selftoken.verify(token, (error, result) => {
    console.log('Returned error:', error, '\nRecovered string:', result);

    console.log('\nCreating tampered copy of the token (one char change)...');

    console.log('Verifying the tampered copy of the token...\n');

    selftoken.verify(token.replace(token[10], '&'), (error, result) => {
      console.log('Returned error:', error, '\nRecovered string:', result);

      console.log('\nWaiting 5s and then verifying again the original token...\n');
      setTimeout(() => {
        selftoken.verify(token, (error, result) => {
          console.log('Returned error:', error, '\nRecovered string:', result);
        });
      }, 5000);
    });
  });
});
