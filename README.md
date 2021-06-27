# X.509 Certificate based Lambda authorizer
A simple Lambda authorizer that extracts incoming X.509 certificate parameters and uses these to
verify the identity of the caller and authorize them to call specific APIs/resources/methods

The implementation extracts three certificate fields to generate a hash value using SHA256 algorithm:
- Issuer Common Name (CN)
- Subject Common Name (CN)
- Certificate SerialNumber

The generated hash value is used to identify the caller and is further looked up in a persistent store to fetch the list of API resources/methods that the caller is authorized to execute/access. This sample authorizer loads the API permissions file (JSON format) from Amazon S3 and then looks up the hash value in it.
The API permissions file format considered is as below:

{\
"\<hash-value\>": [\
 {\
 "api": "arn:aws:execute-api:\<region-code\>:\<aws-acct-id\>:\<api-id\>",\
 "resource": "\<resource-1\>",\
 "stage": "\<stage\>",\
 "method": "\<http-verb\>",\
 "effect": "\<Allow | Deny\>"\
},\
{\
"api": "arn:aws:execute-api:\<region-code\>:\<aws-acct-id\>:\<api-id\>",\
"resource": "\<resource-2\>",\
"stage": "\<stage\>",\
"method": "\<http-verb\>",\
"effect": "\<Allow | Deny\>"\
}\
],\
"\<hash-value\>":[\
...\
]\
}\


This authorization scheme does NOT consider user context. It simply extends the transport layer authentication (based on X.509 certificates) and creates an authorization scheme.

For example: If we want to give access to a set of API resources/methods to a partner organization based on the X.509 trusted certificate used by the partner, we can leverage this authorizer. However, if we have to provide different API permissions to different users of the same partner organization then we will have to implement some additional access token based scheme.


> For a detailed explanation around how to use this authorizer and associated caveats, visit:
> https://medium.com/@adrin-mukherjee/easy-api-authorization-with-aws-api-gateway-and-mutual-tls-db05261d5a9e


