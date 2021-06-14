# X.509 Certificate based Lambda authorizer
A simple Lambda authorizer that extracts incoming X.509 certificate parameters and uses these to
verify the identity of the caller and authorize them to call specific APIs/resources/methods

The implementation uses three certificate fields to create a hash (uses [SHA256] algorithm):
- Issuer Common Name
- Subject Common Name
- Certificate SerialNumber



> For a detailed explanation around how to this authorizer and related caveats, visit:
> https://medium.com/@adrin-mukherjee/easy-api-authorization-with-aws-api-gateway-and-mutual-tls-db05261d5a9e


