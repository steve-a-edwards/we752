// Licensed Materials - Property of IBM
// IBM WebSphere DataPower Appliances
// Copyright IBM Corporation 2015. All Rights Reserved.
// US Government Users Restricted Rights - Use, duplication or disclosure
// restricted by GSA ADP Schedule Contract with IBM Corp.

var jose = require('jose');

// get the input from the request

session.input.readAsBuffer(function(readAsBufferError, jsonData) {
    if (readAsBufferError) {
        console.error('Error on readAsBuffer: ' + readAsBufferError);
    } else {

        try {
            debugger;

            // Create a JWEHeader instance and specify the encryption algorithm to use

            var jweHdr = jose.createJWEHeader('A128CBC-HS256');

            // Set the CEK encryption algorithm header parameter in the protected header

            jweHdr.setProtected('alg', 'RSA1_5');

            // Set the key configuration object to process the encrypted key

            jweHdr.setKey('Emi-cert');

            // Specify which jweHeader defines how to encrypt this message then
            // update the jweEncrypter with the message to be encrypted then
            // encrypt the JWE Encryption object using the compact serialization
            // output_format as specified
            jose.createJWEEncrypter(jweHdr).update(jsonData).encrypt('compact', function(error, jweCompactObj) {
                if (error) {
                    // An error occurred during the encrypt process and is passed back
                    // via the error parameter since .encrypt is an asynchronous call
                    // write the error to the output context
                    session.reject(error);
                    return;
                } else {
                    session.output.write(jweCompactObj);
                }
            }); // encrypt function
        } catch (e) {
            session.reject("EncryptCompactJWE.js error: " + e);
            return;
        }
    }
}); // readAsBuffer

