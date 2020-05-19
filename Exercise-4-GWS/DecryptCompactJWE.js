// Licensed Materials - Property of IBM
// IBM WebSphere DataPower Appliances
// Copyright IBM Corporation 2015. All Rights Reserved.
// US Government Users Restricted Rights - Use, duplication or disclosure
// restricted by GSA ADP Schedule Contract with IBM Corp.

var jose = require('jose');

// get the input from the request sent

session.input.readAsBuffer(function(readAsBufferError, jwe) {
    if (readAsBufferError) {
        console.error('Error on readAsBuffer: ' + readAsBufferError);
    } else {

        try {

            debugger;

            // Parse the JWE representation to extract the serialized values for
            // the components of the JWE.  Returns an instance of JWEObject
            // through which you can access the JWE content.

            var jweObj = jose.parse(jwe);

            // Set key configuration object to process the encrypted key

            jweObj.setKey('Emi-privkey');

            // The decrypt will only be attempted if key has been specified
            jose.createJWEDecrypter(jweObj).decrypt(function(error, plaintext) {
                if (error) {
                    // An error occurred during the decrypt process and is passed back
                    // via the error parameter since .decrypt is an asynchronous call
                    // write the error to the output context
                    session.reject(error);
                    return;
                } else {
                    // since the decryption was successful you can write the
                    // plaintext to the output context
                    session.output.write(plaintext);
                }
            }); // decrypt function

        } catch (e) {
            session.reject("DecryptCompactJWE.js error: " + e);
            return;
        }

}}); // readAsBuffer

