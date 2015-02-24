var fs = require('fs');
var crypto = require('crypto');

var xpath = require('xpath.js');
var Dom = require('xmldom').DOMParser;

var utils = require('./utils');
var ExclusiveCanonicalization = require('./exclusive-canonicalization').ExclusiveCanonicalization;
var ExclusiveCanonicalizationWithComments = require('./exclusive-canonicalization').ExclusiveCanonicalizationWithComments;
var EnvelopedSignature = require('./enveloped-signature').EnvelopedSignature;


/**
 * A key info provider implementation
 *
 */
function FileKeyInfo(file) {
  this.file = file

  this.getKeyInfo = function(key) {
    return "<X509Data></X509Data>"
  }

  this.getKey = function(keyInfo) {      
    return fs.readFileSync(this.file)
  }
}

/**
 * Hash algorithm implementation
 *
 */
function SHA1() {
  
  this.getHash = function(xml) {    
    var shasum = crypto.createHash('sha1')
    shasum.update(xml, 'utf8')
    var res = shasum.digest('base64')
    return res
  }

  this.getAlgorithmName = function() {
    return "http://www.w3.org/2000/09/xmldsig#sha1"
  }
}

function SHA256() {
  
  this.getHash = function(xml) {    
    var shasum = crypto.createHash('sha256')
    shasum.update(xml, 'utf8')
    var res = shasum.digest('base64')
    return res
  }

  this.getAlgorithmName = function() {
    return "http://www.w3.org/2001/04/xmlenc#sha256"
  }
}


/**
 * Signature algorithm implementation
 *
 */
function RSASHA1() {
  
  /**
  * Sign the given string using the given key
  *
  */
  this.getSignature = function(signedInfo, signingKey) {            
    var signer = crypto.createSign("RSA-SHA1")
    signer.update(signedInfo)    
    var res = signer.sign(signingKey, 'base64')
    return res
  }

  /**
  * Verify the given signature of the given string using key
  *
  */
  this.verifySignature = function(str, key, signatureValue) {
    var verifier = crypto.createVerify("RSA-SHA1")
    verifier.update(str)
    var res = verifier.verify(key, signatureValue, 'base64')
    return res
  }

  this.getAlgorithmName = function() {
    return "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
  }

}


/**
 * Signature algorithm implementation
 *
 */
function RSASHA256() {
  
  /**
  * Sign the given string using the given key
  *
  */
  this.getSignature = function(signedInfo, signingKey) {            
    var signer = crypto.createSign("RSA-SHA256")
    signer.update(signedInfo)    
    var res = signer.sign(signingKey, 'base64')
    return res
  }

  /**
  * Verify the given signature of the given string using key
  *
  */
  this.verifySignature = function(str, key, signatureValue) {
    var verifier = crypto.createVerify("RSA-SHA256")
    verifier.update(str)
    var res = verifier.verify(key, signatureValue, 'base64')
    return res
  }

  this.getAlgorithmName = function() {
    return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
  }

}

/**
 * Signature algorithm implementation
 *
 */
function RSASHA512() {
  
  /**
  * Sign the given string using the given key
  *
  */
  this.getSignature = function(signedInfo, signingKey) {            
    var signer = crypto.createSign("RSA-SHA512")
    signer.update(signedInfo)    
    var res = signer.sign(signingKey, 'base64')
    return res
  }

  /**
  * Verify the given signature of the given string using key
  *
  */
  this.verifySignature = function(str, key, signatureValue) {
    var verifier = crypto.createVerify("RSA-SHA512")
    verifier.update(str)
    var res = verifier.verify(key, signatureValue, 'base64')
    return res
  }

  this.getAlgorithmName = function() {
    return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
  }
}

/**
* Xml signature implementation
*
* @param {string} idMode. Value of "wssecurity" will create/validate id's with the ws-security namespace
*/
function SignedXml(idMode, options) {  
  this.options = options || {};
  this.idMode = idMode
  this.references = []
  this.id = 0
  this.signingKey = null
  this.signatureAlgorithm = this.options.signatureAlgorithm || "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
  this.keyInfoProvider = null
  this.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#"
  this.signedXml = ""
  this.signatureXml = ""
  this.signatureXmlDoc = null
  this.signatureValue = ""
  this.originalXmlWithIds = ""
  this.validationErrors = []
  this.keyInfo = null
  this.idAttributes = [ 'Id', 'ID' ];
  if (this.options.idAttribute) this.idAttributes.splice(0, 0, this.options.idAttribute);
}

SignedXml.CanonicalizationAlgorithms = {
  'http://www.w3.org/2001/10/xml-exc-c14n#': ExclusiveCanonicalization,
  'http://www.w3.org/2001/10/xml-exc-c14n#WithComments': ExclusiveCanonicalizationWithComments,
  'http://www.w3.org/2000/09/xmldsig#enveloped-signature': EnvelopedSignature
}

SignedXml.HashAlgorithms = {
  'http://www.w3.org/2000/09/xmldsig#sha1': SHA1,
  'http://www.w3.org/2001/04/xmlenc#sha256': SHA256
}

SignedXml.SignatureAlgorithms = {
  'http://www.w3.org/2000/09/xmldsig#rsa-sha1': RSASHA1,
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': RSASHA256,
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512': RSASHA512
}


function makeTransform(name, options) {
  var algo = SignedXml.CanonicalizationAlgorithms[name];

  if (!algo) {
    throw new Error("canonicalization algorithm '" + name + "' is not supported");
  }

  return new algo(options);
}

function makeSignatureAlgorithm(name) {
  var algo = SignedXml.SignatureAlgorithms[name]
  if (algo) return new algo()
  else throw new Error("signature algorithm '" + name + "' is not supported");
}

function makeDigestAlgorithm(name) {
  var algo = SignedXml.HashAlgorithms[name]
  if (algo) return new algo()
  else throw new Error("hash algorithm '" + name + "' is not supported");
}




// Creation stuff




/**
 *  Configure how and which part to sign.
 *
 *  Only supports signing a single reference.
 */
SignedXml.prototype.configureAndSign = function(config) {
  // Prefetch the algorithms
  config.c14n =
    makeTransform(config.canonicalization.algorithm, config.canonicalization.parameters);

  config.transforms =
      config.transforms
          .map(function (t) { return makeTransform(t.algorithm, t.parameters); })
          .concat(config.c14n);

  config.digestAlgo =
      makeDigestAlgorithm(config.digestAlgorithm);

  config.signatureAlgo =
      makeSignatureAlgorithm(config.signatureAlgorithm);

  var doc =
    new Dom().parseFromString(config.xml);

  var referenceNode =
    this.createReferenceNode(doc, config.nodeToSign, config.takeUriFromIdInRootElement, config.transforms, config.digestAlgo);

  var signedInfo =
    this.createSignedInfo(doc, config.c14n, config.signatureAlgo, referenceNode);

  var signatureValue =
    this.createSignature(signedInfo, config.c14n, config.signatureAlgo, config.signingKey);

  var signatureXml =
    '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">' + "\n" +
    signedInfo +
    signatureValue +
    this.getKeyInfo(config.keyInfoProvider) +
    '</ds:Signature>';

  var signatureDoc =
    new Dom().parseFromString(signatureXml);

  // Fsking mutation
  var signature =
    signatureDoc.toString();

  if (config.insertSignatureAfter) {
    var nodes =
      xpath(doc, config.insertSignatureAfter);

    if (!nodes || nodes.length !== 1) {
      throw new Error('None or multiple nodes found to insert after' + config.insertSignatureAfter);
    }

    doc.documentElement.insertBefore(signatureDoc.documentElement, nodes[0].nextSibling);

  } else {
    doc.documentElement.appendChild(signatureDoc.documentElement);
  }

  return {
    signature: signature,
    signedXml: doc.toString()
  };
}



/**
 * Create the SignedInfo element
 *
 */
SignedXml.prototype.createSignedInfo = function(doc, c14n, signatureAlgorithm, referenceNode) {
  var res =
    '<ds:SignedInfo>' + "\n" +
    '<ds:CanonicalizationMethod Algorithm="' + c14n.getAlgorithmName() + '" />' + "\n" +
    '<ds:SignatureMethod Algorithm="' + signatureAlgorithm.getAlgorithmName() + '" />' + "\n" +
    referenceNode +
    '</ds:SignedInfo>' + "\n";

  return res;
}


/**
 * Create the Signature element
 *
 */
SignedXml.prototype.createSignature = function(signedInfo, c14n, signatureAlgorithm, signingKey) {
  //the canonicalization requires to get a valid xml node. 
  //we need to wrap the info in a dummy signature since it contains the default namespace.
  //
  // Whattheactual…
  var dummySignatureWrapper =
    '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">' +
    signedInfo +
    '</ds:Signature>';

  var xml =
    new Dom().parseFromString(dummySignatureWrapper);

  var node =
    xml.documentElement.firstChild;

  var canonizedSignedInfo =
    c14n.process(node);

  var signatureValue =
    signatureAlgorithm.getSignature(canonizedSignedInfo, signingKey);

  return '<ds:SignatureValue>' + signatureValue + '</ds:SignatureValue>';
}


SignedXml.prototype.getKeyInfo = function(keyInfoProvider) {
  var res = ""
  if (keyInfoProvider) {
    res += "<ds:KeyInfo>"
    res += keyInfoProvider.getKeyInfo(this.signingKey)
    res += "</ds:KeyInfo>"
  }
  return res
}


/**
 *  Generate the Reference node.
 */
SignedXml.prototype.createReferenceNode = function(doc, nodeToSign, takeUriFromIdInRootElement, transforms, digestAlgorithm) {

  var res = "";

  var nodes =
    xpath(doc, nodeToSign);

  if (nodes.length !== 1) {
    throw new Error('No or multiple reference nodes' + nodeToSign);
  }

  var node =
    nodes[0];

  if (takeUriFromIdInRootElement) {
    res += '<ds:Reference URI="#' + this.ensureHasId(node) + '">' + "\n";
  } else {
    res += '<ds:Reference URI="">';
  }

  res += '<ds:Transforms>' + "\n";

  transforms.forEach(function (transform) {
    res += transform.getTransformDescriptionXml();
  });

  var transformedCanonXml =
    this.applyTransforms(transforms, node);

  res +=  '</ds:Transforms>' + "\n" +
          '<ds:DigestMethod Algorithm="' + digestAlgorithm.getAlgorithmName() + '" />'+ "\n" +
          '<ds:DigestValue>' + digestAlgorithm.getHash(transformedCanonXml) + '</ds:DigestValue>'+ "\n" +
          '</ds:Reference>' + "\n";

  return res;
}


SignedXml.prototype.applyTransforms = function(transforms, node) {
  var transformed =
    transforms.reduce(function (xml, transform) {
      return transform.process(xml);
    }, node);

  return transformed;
}

/**
 * Ensure an element has Id attribute. If not create it with unique value.
 * Work with both normal and wssecurity Id flavour
 */
SignedXml.prototype.ensureHasId = function(node) {
  var attr

  if (this.idMode=="wssecurity") {
    attr = utils.findAttr(node, 
      "Id", 
      "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd")
  }
  else {
    for (var index in this.idAttributes) {
      if (!this.idAttributes.hasOwnProperty(index)) continue;

      attr = utils.findAttr(node, this.idAttributes[index], null);
      if (attr) break;
    }
  }

  if (attr) return attr.value
  
  //add the attribute
  var id = "_" + this.id++

  if (this.idMode=="wssecurity") {
    node.setAttributeNS("http://www.w3.org/2000/xmlns/", 
      "xmlns:wsu", 
      "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd")
    node.setAttributeNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", 
      "wsu:Id", 
      id)
  }
  else {
   node.setAttribute("Id", id) 
  }

  return id
}


/**
 *  Entry function to hide away the entire object system for now.
 *
 */
function configureAndSign(config) {
  var eww =
    new SignedXml();

  return eww.configureAndSign(config);
}


module.exports = {
  configureAndSign: configureAndSign
};
