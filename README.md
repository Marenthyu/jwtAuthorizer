# jwtAuthorizer
A Lambda Function for Node 8 that acts as an Authorizer for AWS API Gateway

# Notes
This is the code tailored to my usecase, some things need to be considered to use it for you:
 * The ``extensionSecretName`` needs to be adjusted or read from an environment variable or similar to reflect the name in Secret Manager
 * It is assumed the Secret Manager is in the same region as the Lambda Function; Override ``region`` as required.
 * It assumes the Secret Manager is reachable from within the VPC the Lambda Function is in. (This may require a VPC Endpoint)
 * The Secret consists of one JSON Object with a single attribute ``twitchSecret``. Change as is used in your environment.
 * It sets the principalID to the ``user_id`` of the JWT Payload if available (i.e. the User has shared their identity with the Extension), else to ``opaque_user_id``.
 * It is tested with Node 8 only, YMMV with newer versions.
 * It is meant to be used as an Authorizer for API Gateway, my configuration uses the ``Token Source`` ``Authorization``, no Token Validation (should be ok to use), no caching and a Lambda Event Payload of ``Token``.
 * In the end, it expects the JWT Token in the Authorization Header as a ``Bearer`` Token.
