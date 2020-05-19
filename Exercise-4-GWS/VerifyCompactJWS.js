// Licensed Materials - Property of IBM
// IBM WebSphere DataPower Appliances
// Copyright IBM Corporation 2015. All Rights Reserved.
// US Government Users Restricted Rights - Use, duplication or disclosure
// restricted by GSA ADP Schedule Contract with IBM Corp.

var jose = require('jose');

// get the input from the request

session.input.readAsBuffer(function(readAsBufferError, jwsObj) {
    if (readAsBufferError) {
        console.error('Error on readAsBuffer: ' + readAsBufferError);
    } else {

        try {
            debugger;

            // parse the jwsObj to get a JWSSignedObject
            var jwsSignedObject = jose.parse(jwsObj);

            // Access the per-signature data and set key for each signature
            //  for verification (since this is compact, there is only 1 signature)

            var signedJWSHeaders = jwsSignedObject.getSignatures();
            for (var i = 0; i < signedJWSHeaders.length; i++) {
                var hdr = signedJWSHeaders[i];

                // Extract the value for the Header Parameter named 'kid'
                var kid = hdr.get('kid');
                switch (kid) {
                    case 'Sam-privkey':
                        // Set the key for the signature verification
                        hdr.setKey('Sam-cert');
                        break;
                    default:
                        break;
                }
            }

            // create a JWSVerifier instance
            var myVerifier = jose.createJWSVerifier(jwsSignedObject);

            // Verify all signatures for which a key has been set
            // At least one signature must have key set
            // .validate automatically processes all with key

            myVerifier.validate(function(error) {
                if (error) {
                    // an error occurred during the verify process
                    // write the error to the output context
                    session.reject(error.errorMessage);
                    return;
                } else {
                    // All signature verifications have succeeded
                    // therefore payload may be trusted
                    var plaintext = jwsSignedObject.getPayload();
                    session.output.write(plaintext);
                }
            });

        } catch (e) {
            console.error("VerifyCompactJWS.js error: " + e);
            session.output.write("VerifyCompactJWS.js error: " + e);
        }
    }
}); // readAsBuffer

