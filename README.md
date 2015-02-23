# xml-signature

An xml digital signature library for node with a hopefully simpler interface.

Based on [yaronn’s xml-crypto](http://github.com/yaronn/xml-crypto).


## Usage

The signing is configured in one go.

```javascript
    var signed =
      xmlSignature.configureAndSign({
        xml: xml,
        nodeToSign: "//*[local-name(.)='MainElement']",
        insertSignatureAfter: "//*[local-name(.)='SomeOtherElementMaybe']",
        takeUriFromIdInRootElement: true,

        transforms: [
          {algorithm: 'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
           parameters: {}}
        ],
        canonicalization: {
          algorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
          parameters: {
              inclusiveNamespacesPrefixList: 'l'
          }
        },

        digestAlgorithm: 'http://www.w3.org/2000/09/xmldsig#sha1',
        signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",

        signingKey: fs.readFileSync('nopassword-key.pem'),  // node 0.12 or iojs offer password option
        //keyInfoProvider: x509KeyInfo
      });

    // Just the signature
    var signature =
      signed.signature;

    // The real deal
    var signedXml =
      signed.signedXml;

    console.log(signedXml);
```
