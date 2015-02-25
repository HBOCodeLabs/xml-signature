/**
 *  Noop
 */
function InclusiveCanonicalization(options) { };


InclusiveCanonicalization.prototype.process = function(node) {
  return node.toString();
};

InclusiveCanonicalization.prototype.getAlgorithmName = function() {
  return 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
};

InclusiveCanonicalization.prototype.getTransformDescriptionXml = function() {
  return '<ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />';
};


exports.InclusiveCanonicalization = InclusiveCanonicalization;
