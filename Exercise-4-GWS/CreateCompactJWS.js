// Licensed Materials - Property of IBM
// IBM WebSphere DataPower Appliances
// Copyright IBM Corporation 2015. All Rights Reserved.
// US Government Users Restricted Rights - Use, duplication or disclosure
// restricted by GSA ADP Schedule Contract with IBM Corp.

var jose = require('jose');

// get the input from the request

session.input.readAsBuffer(function(readAsBufferError, jsonData) {
    if (readAsBufferError) {
        console.error('Error on readAsBuffer in CreateCompactJWS.js: ' + readAsBufferError);
    } else {
        try {
            debugger;
            // Create a JWSHeader object to define the header parameters for the JWS
            // First arg is name of config key object; second is alg

            var jwsHdr = jose.createJWSHeader('Sam-privkey', 'RS256');

            // Set a header parameter named 'kid' in the Protected Header to the value
            // 'Sam-privkey' - a string
            // the verifier will use this value to identify the necessary key

            jwsHdr.setProtected('kid', 'Sam-privkey');

            // Create a JWSSigner instance using the parameters defined in the JWSHeader object
            // Update the JWSSigner instance with the payload
            // Create the JWS in the compact format 

            jose.createJWSSigner(jwsHdr).update(jsonData).sign('compact', function(error, jwsObj) {
                if (error) {
                    // An error occurred during the sign process and is passed back
                    // via the error parameter since .sign is an asynchronous call
                    // write the error to the output context
                    session.reject(error.errorMessage);
                    reject;
                } else {
                    // since the operation was successful you can write the
                    // object to the output context
                    session.output.write(jwsObj);
                }
            }); // sign function
        } catch (e) {
            console.error("CreateCompactJWS.js error: " + e);
            session.output.write("CreateCompactJWS.js error: " + e);
        }
    }
});

