const jwt = require('jsonwebtoken'); 
 
console.log('Loading jwtAuthorizer'); 
 
let AWS = require('aws-sdk'), 
    region = process.env.AWS_REGION, 
    extensionSecretName = "TCGExtensionSecret", 
    extensionSecret; 
 
// Create a Secrets Manager client 
let awsclient = new AWS.SecretsManager({ 
    region: region 
}); 
 
exports.handler = function(event, context, callback) { 
  console.log('Received event', JSON.stringify(event, null, 2)); 
 
  // remove the 'Bearer ' prefix from the auth token 
  const token = event.authorizationToken.replace(/Bearer /g, ''); 
 
  // parse all API options from the event, in case we need some of them 
  const apiOptions = getApiOptions(event); 
  console.log('API Options', JSON.stringify(apiOptions, null, 2)); 
 
    awsclient.getSecretValue({SecretId: extensionSecretName}, function (err, data) { 
        if (err) { 
            console.log('Error: ' + err); 
            // Secrets Manager can't decrypt the protected secret text using the provided KMS key. 
            // Deal with the exception here, and/or rethrow at your discretion. 
            console.log('ERROR getting secret.'); 
            callback(err); 
            return; 
        } else { 
            extensionSecret = JSON.parse(data.SecretString); 
        } 
 
        console.log('Extension Secret Acquired'); 
 
        // Extension Secret acquired, verify token 
 
        // Shared secret to verify token, base64 encoded by twitch, thus need to decode it. 
        const secret = Buffer.from(extensionSecret.twitchSecret, 'base64'); 
 
        // verify the token with publicKey and secret and return proper AWS policy document 
        jwt.verify(token, secret, (err, verified) => { 
            if (err) { 
                console.error('JWT Error', err, err.stack); 
                callback(null, denyPolicy('anonymous', event.methodArn)); 
            } else { 
                callback(null, allowPolicy(verified.user_id, event.methodArn)); 
            } 
        }); 
    }); 
 
}; 
 
const getApiOptions = function(event) { 
  const apiOptions = {}; 
  const tmp = event.methodArn.split(':'); 
  const apiGatewayArnTmp = tmp[5].split('/'); 
  apiOptions.awsAccountId = tmp[4]; 
  apiOptions.region = tmp[3]; 
  apiOptions.restApiId = apiGatewayArnTmp[0]; 
  apiOptions.stageName = apiGatewayArnTmp[1]; 
  return apiOptions; 
}; 
 
const denyPolicy = function(principalId, resource) { 
  console.log("Denying access for ID " + principalId); 
  return generatePolicy(principalId, 'Deny', resource); 
}; 
 
const allowPolicy = function(principalId, resource) { 
  console.log("Allowing access for ID " + principalId); 
  return generatePolicy(principalId, 'Allow', resource); 
}; 
 
const generatePolicy = function(principalId, effect, resource) { 
    const authResponse = {}; 
    authResponse.principalId = principalId; 
    if (effect && resource) { 
        const policyDocument = {}; 
        policyDocument.Version = '2012-10-17'; // default version 
        policyDocument.Statement = []; 
        const statementOne = {}; 
        statementOne.Action = 'execute-api:Invoke'; // default action 
        statementOne.Effect = effect; 
        statementOne.Resource = resource; 
        policyDocument.Statement[0] = statementOne; 
        authResponse.policyDocument = policyDocument; 
    } 
    return authResponse; 
};
