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
const AWS      = require('aws-sdk');
const Config   = require('./config.js');
const forge    = require('node-forge');
const {sha256} = require('crypto-hash');

exports.handler = async (event)=>{
    console.log("Incoming event- ", JSON.stringify(event));
    
    // Check if the request context has a certificate
    if(event && event.requestContext.identity.clientCert){
        const certPEMContent = event.requestContext.identity.clientCert.clientCertPem;

        try{
            // Parse certificate and create a hashed identifier
            const cert = forge.pki.certificateFromPem(certPEMContent);
            let iss    = cert.issuer.getField('CN').value.trim();
            let sub    = cert.subject.getField('CN').value.trim();
            let srlno  = cert.serialNumber.trim();

            let identifier = iss + ':' + sub + ':' + srlno;
            console.log("<Issuer CN>:<Subject CN>:<Certificate Serial No.> - ", identifier);    
            
            const hash = await sha256(identifier);
            console.log("Hash value- ", hash);

            /** 
             * TODO: In practice, we should make calls to a persistent store to fetch the 
             * API mappings against the generated hash value   
             */ 
            
            // Load entire api permissions file from S3   
            const api_permissions = await get_api_permissions_from_S3();
            let permissions = api_permissions[hash]; // get permissions for the specific partner

            if(permissions && permissions instanceof Array){
                let policy = generate_iam_policy(sub, permissions);
                console.log("IAM Policy- ", JSON.stringify(policy));
                return policy;
            }
            else{
                console.error("No permissions");
                return generate_deny_all_iam_policy(sub);
            }
        }
        catch(err){
            console.error("Unable to authorize- ", err);
            return generate_deny_all_iam_policy();
        }
    }
    else{
        console.error("Client certificate is not present in the request");
        return generate_deny_all_iam_policy();
    }
};

async function get_api_permissions_from_S3(){
    var api_permissions = {};
    var S3 = new AWS.S3({region: Config.REGION});

    var params = {
        Bucket: Config.BUCKET_NAME, 
        Key: Config.API_PERMISSION_FILE
    };

    try{    
        let data = await S3.getObject(params).promise();
        if(data && data.Body instanceof Buffer){
            api_permissions = JSON.parse(data.Body.toString('utf-8'));
            console.log("Loaded API Permission file- ", api_permissions);
        }
        else{
            api_permissions = {};
            console.error("Unable to read api permissions file");
            // TODO: send SNS notification to concerned teams
        }
    }
    catch(err){
        console.error("Unable to retrieve api permissions- ", err);
        // TODO: send SNS notification to concerned teams
        api_permissions = {};
    }
    return api_permissions;
}

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
