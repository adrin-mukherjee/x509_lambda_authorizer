/**
 * @author: adrin.mukherjee@gmail.com
 * 
 * Sample implementation of a Lambda authorizer that extracts parameters 
 * from an incoming X509 certificate and uses these to generate a hash value.
 * Further, this hash value is looked up in a persistent store and the list of
 * APIs (along with resources and methods) that can be executed by the partner 
 * are fetched to generate an IAM policy. This policy is then returned to 
 * AWS API Gateway
 */
const forge = require('node-forge')
const {sha256} = require('crypto-hash');

// A lame implementation of a map of partners' hash values with list of permitted APIs
/**
 * Partner1 can access specific resources of both 'customer' and 'products' APIs 
 * Partner2 can access specific resources of only 'products' API
 */
const api_permissions = 
    {
        "<hash-value>": [   // partner1
            {
                api: "arn:aws:execute-api:<region-code>:<acct-id>:<api-id>",
                resource: "customer/*",
                stage: "DEV",
                method: "GET",
                effect: "Allow"
            },
            {
                api: "arn:aws:execute-api:<region-code>:<acct-id>:<api-id>",
                resource: "products*",
                stage: "DEV",
                method: "GET",
                effect: "Allow"
            }
        ],
        "<hash-value>":[  // partner2
            {
                api: "arn:aws:execute-api:<region-code>:<acct-id>:<api-id>",
                resource: "products*",
                stage: "DEV",
                method: "GET",
                effect: "Allow"
            }
        ]
    };

exports.handler = async (event)=>{
    console.log("Incoming event = ", JSON.stringify(event));
    
    // Check if the request context has a certificate
    if(event && event.requestContext.identity.clientCert){
        const certPEMContent = event.requestContext.identity.clientCert.clientCertPem;

        try{
            // Parse certificate and create a hashed identifier
            const cert = forge.pki.certificateFromPem(certPEMContent);

            let iss   = cert.issuer.getField('CN').value.trim();
            let sub   = cert.subject.getField('CN').value.trim();
            let srlno = cert.serialNumber.trim();

            let identifier = iss + ':' + sub + ':' + srlno;
            console.log("<Issuer CN>:<Subject CN>:<Certificate Serial No.> = ", identifier);    
            
            const hash = await sha256(identifier);
            console.log("Hash value = ", hash);

            /**
             * TODO: Use some persistent store to lookup the partner's hash value in order 
             * fetch the list of permitted APIs and corresponding resources and methods
             */
            let permissions = api_permissions[hash]; // Should be replaced by actual lookup to persistent store
            if(permissions){
                // Generate IAM policy based on the permissions
                let policy = generate_iam_policy(sub, permissions);
                console.log("IAM Policy = ", JSON.stringify(policy));
                return policy;
            }
            else{
                console.error("No permissions");
                return generate_deny_all_iam_policy(sub);
            }
        }
        catch(err){
            console.error("Unable to parse certificate content");
            return generate_deny_all_iam_policy();
        }
    }
    else{
        console.error("Client certificate is not present in the request");
        return generate_deny_all_iam_policy();
    }
};

function generate_iam_policy(principal, permissions){
    let response = {};
    let policyDocument = {};

    policyDocument.Version = '2012-10-17'; 
    policyDocument.Statement = [];
    
    // generate statements based on permissions
    let index = 0;
    for(index in permissions){
        let statement = {};
        statement.Action = 'execute-api:Invoke'; 
        statement.Effect = permissions[index].effect;
        statement.Resource = permissions[index].api + '/' 
                            + permissions[index].stage + '/' 
                            + permissions[index].method + '/' 
                            + permissions[index].resource;
        policyDocument.Statement.push(statement);
    }
    response.principalId = principal;
    response.policyDocument = policyDocument;

    return response;
}

function generate_deny_all_iam_policy(principal){
    return {
        "principalId": (principal ? principal:'subject'),
        "policyDocument":{
          "Version":"2012-10-17",
          "Statement":[
            {
              "Action":"execute-api:Invoke",
              "Effect":"Deny",
              "Resource":"*"
            }
          ]
        }
      };
}
