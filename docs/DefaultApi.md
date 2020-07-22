# SwaggerClient::DefaultApi

All URIs are relative to *https://127.0.0.1:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**assoc_role_am**](DefaultApi.md#assoc_role_am) | **POST** /assoc-role-am | Create an association between role and auth method
[**auth**](DefaultApi.md#auth) | **POST** /auth | Authenticate to the service and returns a token to be used as a profile to execute the CLI without the need for re-authentication
[**configure**](DefaultApi.md#configure) | **POST** /configure | Configure client profile.
[**create_auth_method**](DefaultApi.md#create_auth_method) | **POST** /create-auth-method | Create a new Auth Method in the account
[**create_auth_method_aws_iam**](DefaultApi.md#create_auth_method_aws_iam) | **POST** /create-auth-method-aws-iam | Create a new Auth Method that will be able to authenticate using AWS IAM credentials
[**create_auth_method_azure_ad**](DefaultApi.md#create_auth_method_azure_ad) | **POST** /create-auth-method-azure-ad | Create a new Auth Method that will be able to authenticate using Azure Active Directory credentials
[**create_auth_method_ldap**](DefaultApi.md#create_auth_method_ldap) | **POST** /create-auth-method-ldap | Create a new Auth Method that will be able to authenticate using LDAP
[**create_auth_method_oauth2**](DefaultApi.md#create_auth_method_oauth2) | **POST** /create-auth-method-oauth2 | Create a new Auth Method that will be able to authenticate using OpenId/OAuth2
[**create_auth_method_saml**](DefaultApi.md#create_auth_method_saml) | **POST** /create-auth-method-saml | Create a new Auth Method that will be able to authenticate using SAML
[**create_dynamic_secret**](DefaultApi.md#create_dynamic_secret) | **POST** /create-dynamic-secret | Creates a new dynamic secret item
[**create_key**](DefaultApi.md#create_key) | **POST** /create-key | Creates a new key
[**create_pki_cert_issuer**](DefaultApi.md#create_pki_cert_issuer) | **POST** /create-pki-cert-issuer | Creates a new PKI certificate issuer
[**create_role**](DefaultApi.md#create_role) | **POST** /create-role | Creates a new role
[**create_secret**](DefaultApi.md#create_secret) | **POST** /create-secret | Creates a new secret item
[**create_ssh_cert_issuer**](DefaultApi.md#create_ssh_cert_issuer) | **POST** /create-ssh-cert-issuer | Creates a new SSH certificate issuer
[**decrypt**](DefaultApi.md#decrypt) | **POST** /decrypt | Decrypts ciphertext into plaintext by using an AES key
[**decrypt_file**](DefaultApi.md#decrypt_file) | **POST** /decrypt-file | Decrypts a file by using an AES key
[**decrypt_pkcs1**](DefaultApi.md#decrypt_pkcs1) | **POST** /decrypt-pkcs1 | Decrypts a plaintext using RSA and the padding scheme from PKCS#1 v1.5
[**delete_assoc**](DefaultApi.md#delete_assoc) | **POST** /delete-assoc | Delete an association between role and auth method
[**delete_auth_method**](DefaultApi.md#delete_auth_method) | **POST** /delete-auth-method | Delete the Auth Method
[**delete_item**](DefaultApi.md#delete_item) | **POST** /delete-item | Delete an item
[**delete_role**](DefaultApi.md#delete_role) | **POST** /delete-role | Delete a role
[**delete_role_rule**](DefaultApi.md#delete_role_rule) | **POST** /delete-role-rule | Delete a rule from a role
[**describe_item**](DefaultApi.md#describe_item) | **POST** /describe-item | Returns the item details
[**encrypt**](DefaultApi.md#encrypt) | **POST** /encrypt | Encrypts plaintext into ciphertext by using an AES key
[**encrypt_file**](DefaultApi.md#encrypt_file) | **POST** /encrypt-file | Encrypts a file by using an AES key
[**encrypt_pkcs1**](DefaultApi.md#encrypt_pkcs1) | **POST** /encrypt-pkcs1 | Encrypts the given message with RSA and the padding scheme from PKCS#1 v1.5
[**get_auth_method**](DefaultApi.md#get_auth_method) | **POST** /get-auth-method | Returns an information about the Auth Method
[**get_cloud_identity**](DefaultApi.md#get_cloud_identity) | **POST** /get-cloud-identity | Get Cloud Identity Token (relevant only for access-type&#x3D;azure_ad,aws_iam)
[**get_dynamic_secret_value**](DefaultApi.md#get_dynamic_secret_value) | **POST** /get-dynamic-secret-value | Get dynamic secret value
[**get_kube_exec_creds**](DefaultApi.md#get_kube_exec_creds) | **POST** /get-kube-exec-creds | Get credentials for authentication with Kubernetes cluster based on a PKI Cert Issuer
[**get_pki_certificate**](DefaultApi.md#get_pki_certificate) | **POST** /get-pki-certificate | Generates PKI certificate
[**get_role**](DefaultApi.md#get_role) | **POST** /get-role | Get role details
[**get_rsa_public**](DefaultApi.md#get_rsa_public) | **POST** /get-rsa-public | Obtain the public key from a specific RSA private key
[**get_secret_value**](DefaultApi.md#get_secret_value) | **POST** /get-secret-value | Get static secret value
[**get_ssh_certificate**](DefaultApi.md#get_ssh_certificate) | **POST** /get-ssh-certificate | Generates SSH certificate
[**help**](DefaultApi.md#help) | **POST** /help | help text
[**list_auth_methods**](DefaultApi.md#list_auth_methods) | **POST** /list-auth-methods | Returns a list of all the Auth Methods in the account
[**list_items**](DefaultApi.md#list_items) | **POST** /list-items | Returns a list of all accessible items
[**list_roles**](DefaultApi.md#list_roles) | **POST** /list-roles | Returns a list of all roles in the account
[**set_role_rule**](DefaultApi.md#set_role_rule) | **POST** /set-role-rule | Set a rule to a role
[**sign_pkcs1**](DefaultApi.md#sign_pkcs1) | **POST** /sign-pkcs1 | Calculates the signature of hashed using RSASSA-PKCS1-V1_5-SIGN from RSA PKCS#1 v1.5
[**unconfigure**](DefaultApi.md#unconfigure) | **POST** /unconfigure | Remove Configuration of client profile.
[**update**](DefaultApi.md#update) | **POST** /update | Update a new AKEYLESS CLI version
[**update_item**](DefaultApi.md#update_item) | **POST** /update-item | Update item name and metadata
[**update_role**](DefaultApi.md#update_role) | **POST** /update-role | Update role details
[**update_secret_val**](DefaultApi.md#update_secret_val) | **POST** /update-secret-val | Update static secret value
[**upload_pkcs12**](DefaultApi.md#upload_pkcs12) | **POST** /upload-pkcs12 | Upload a PKCS#12 key and certificates
[**upload_rsa**](DefaultApi.md#upload_rsa) | **POST** /upload-rsa | Upload RSA key
[**verify_pkcs1**](DefaultApi.md#verify_pkcs1) | **POST** /verify-pkcs1 | Verifies an RSA PKCS#1 v1.5 signature


# **assoc_role_am**
> ReplyObj assoc_role_am(role_name, am_name, token, opts)

Create an association between role and auth method

Create an association between role and auth method Options:   role-name -    The role name to associate   am-name -    The auth method name to associate   sub-claims -    key/val of sub claims, ex. group=admins,developers   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

role_name = 'role_name_example' # String | The role name to associate

am_name = 'am_name_example' # String | The auth method name to associate

token = 'token_example' # String | Access token

opts = { 
  sub_claims: 'sub_claims_example' # String | key/val of sub claims, ex. group=admins,developers
}

begin
  #Create an association between role and auth method
  result = api_instance.assoc_role_am(role_name, am_name, token, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->assoc_role_am: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **role_name** | **String**| The role name to associate | 
 **am_name** | **String**| The auth method name to associate | 
 **token** | **String**| Access token | 
 **sub_claims** | **String**| key/val of sub claims, ex. group&#x3D;admins,developers | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **auth**
> ReplyObj auth(access_id, opts)

Authenticate to the service and returns a token to be used as a profile to execute the CLI without the need for re-authentication

Authenticate to the service and returns a token to be used as a profile to execute the CLI without the need for re-authentication Options:   access-id -    Access ID   access-type -    Access Type (access_key/saml/ldap/azure_ad/aws_iam)   access-key -    Access key (relevant only for access-type=access_key)   cloud-id -    The cloued identity (relevant only for access-type=azure_ad,awd_im,auid)   ldap_proxy_url -    Address URL for LDAP proxy (relevant only for access-type=ldap)

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

access_id = 'access_id_example' # String | Access ID

opts = { 
  access_type: 'access_type_example', # String | Access Type (access_key/saml/ldap/azure_ad/aws_iam)
  access_key: 'access_key_example', # String | Access key (relevant only for access-type=access_key)
  cloud_id: 'cloud_id_example', # String | The cloued identity (relevant only for access-type=azure_ad,awd_im,auid)
  ldap_proxy_url: 'ldap_proxy_url_example' # String | Address URL for LDAP proxy (relevant only for access-type=ldap)
}

begin
  #Authenticate to the service and returns a token to be used as a profile to execute the CLI without the need for re-authentication
  result = api_instance.auth(access_id, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->auth: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **access_id** | **String**| Access ID | 
 **access_type** | **String**| Access Type (access_key/saml/ldap/azure_ad/aws_iam) | [optional] 
 **access_key** | **String**| Access key (relevant only for access-type&#x3D;access_key) | [optional] 
 **cloud_id** | **String**| The cloued identity (relevant only for access-type&#x3D;azure_ad,awd_im,auid) | [optional] 
 **ldap_proxy_url** | **String**| Address URL for LDAP proxy (relevant only for access-type&#x3D;ldap) | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **configure**
> ReplyObj configure(access_id, opts)

Configure client profile.

Configure client profile. Options:   access-id -    Access ID   access-key -    Access Key   access-type -    Access Type (access_key/azure_ad/saml/ldap/aws_iam)   ldap_proxy_url -    Address URL for ldap proxy (relevant only for access-type=ldap)   azure_ad_object_id -    Azure Active Directory ObjectId (relevant only for access-type=azure_ad)

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

access_id = 'access_id_example' # String | Access ID

opts = { 
  access_key: 'access_key_example', # String | Access Key
  access_type: 'access_type_example', # String | Access Type (access_key/azure_ad/saml/ldap/aws_iam)
  ldap_proxy_url: 'ldap_proxy_url_example', # String | Address URL for ldap proxy (relevant only for access-type=ldap)
  azure_ad_object_id: 'azure_ad_object_id_example' # String | Azure Active Directory ObjectId (relevant only for access-type=azure_ad)
}

begin
  #Configure client profile.
  result = api_instance.configure(access_id, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->configure: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **access_id** | **String**| Access ID | 
 **access_key** | **String**| Access Key | [optional] 
 **access_type** | **String**| Access Type (access_key/azure_ad/saml/ldap/aws_iam) | [optional] 
 **ldap_proxy_url** | **String**| Address URL for ldap proxy (relevant only for access-type&#x3D;ldap) | [optional] 
 **azure_ad_object_id** | **String**| Azure Active Directory ObjectId (relevant only for access-type&#x3D;azure_ad) | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **create_auth_method**
> ReplyObj create_auth_method(name, token, opts)

Create a new Auth Method in the account

Create a new Auth Method in the account Options:   name -    Auth Method name   access-expires -    Access expiration date in Unix timestamp (select 0 for access without expiry date)   bound-ips -    A CIDR whitelist with the IPs that the access is restricted to   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

name = 'name_example' # String | Auth Method name

token = 'token_example' # String | Access token

opts = { 
  access_expires: 'access_expires_example', # String | Access expiration date in Unix timestamp (select 0 for access without expiry date)
  bound_ips: 'bound_ips_example' # String | A CIDR whitelist with the IPs that the access is restricted to
}

begin
  #Create a new Auth Method in the account
  result = api_instance.create_auth_method(name, token, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->create_auth_method: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Auth Method name | 
 **token** | **String**| Access token | 
 **access_expires** | **String**| Access expiration date in Unix timestamp (select 0 for access without expiry date) | [optional] 
 **bound_ips** | **String**| A CIDR whitelist with the IPs that the access is restricted to | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **create_auth_method_aws_iam**
> ReplyObj create_auth_method_aws_iam(name, bound_aws_account_id, token, opts)

Create a new Auth Method that will be able to authenticate using AWS IAM credentials

Create a new Auth Method that will be able to authenticate using AWS IAM credentials Options:   name -    Auth Method name   access-expires -    Access expiration date in Unix timestamp (select 0 for access without expiry date)   bound-ips -    A CIDR whitelist of the IPs that the access is restricted to   sts-url -    sts URL   bound-AWS-account-id -    A list of AWS account-IDs that the access is restricted to   bound-arn -    A list of full arns that the access is restricted to   bound-role-name -    A list of full role-name that the access is restricted to   bound-role-id -    A list of full role ids that the access is restricted to   bound-resource-id -    A list of full resource ids that the access is restricted to   bound-user-name -    A list of full user-name that the access is restricted to   bound-user-id -    A list of full user ids that the access is restricted to   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

name = 'name_example' # String | Auth Method name

bound_aws_account_id = 'bound_aws_account_id_example' # String | A list of AWS account-IDs that the access is restricted to

token = 'token_example' # String | Access token

opts = { 
  access_expires: 'access_expires_example', # String | Access expiration date in Unix timestamp (select 0 for access without expiry date)
  bound_ips: 'bound_ips_example', # String | A CIDR whitelist of the IPs that the access is restricted to
  sts_url: 'sts_url_example', # String | sts URL
  bound_arn: 'bound_arn_example', # String | A list of full arns that the access is restricted to
  bound_role_name: 'bound_role_name_example', # String | A list of full role-name that the access is restricted to
  bound_role_id: 'bound_role_id_example', # String | A list of full role ids that the access is restricted to
  bound_resource_id: 'bound_resource_id_example', # String | A list of full resource ids that the access is restricted to
  bound_user_name: 'bound_user_name_example', # String | A list of full user-name that the access is restricted to
  bound_user_id: 'bound_user_id_example' # String | A list of full user ids that the access is restricted to
}

begin
  #Create a new Auth Method that will be able to authenticate using AWS IAM credentials
  result = api_instance.create_auth_method_aws_iam(name, bound_aws_account_id, token, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->create_auth_method_aws_iam: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Auth Method name | 
 **bound_aws_account_id** | **String**| A list of AWS account-IDs that the access is restricted to | 
 **token** | **String**| Access token | 
 **access_expires** | **String**| Access expiration date in Unix timestamp (select 0 for access without expiry date) | [optional] 
 **bound_ips** | **String**| A CIDR whitelist of the IPs that the access is restricted to | [optional] 
 **sts_url** | **String**| sts URL | [optional] 
 **bound_arn** | **String**| A list of full arns that the access is restricted to | [optional] 
 **bound_role_name** | **String**| A list of full role-name that the access is restricted to | [optional] 
 **bound_role_id** | **String**| A list of full role ids that the access is restricted to | [optional] 
 **bound_resource_id** | **String**| A list of full resource ids that the access is restricted to | [optional] 
 **bound_user_name** | **String**| A list of full user-name that the access is restricted to | [optional] 
 **bound_user_id** | **String**| A list of full user ids that the access is restricted to | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **create_auth_method_azure_ad**
> ReplyObj create_auth_method_azure_ad(name, bound_tenant_id, token, opts)

Create a new Auth Method that will be able to authenticate using Azure Active Directory credentials

Create a new Auth Method that will be able to authenticate using Azure Active Directory credentials Options:   name -    Auth Method name   access-expires -    Access expiration date in Unix timestamp (select 0 for access without expiry date)   bound-ips -    A CIDR whitelist of the IPs that the access is restricted to   bound-tenant-id -    The Azure tenant id that the access is restricted to   issuer -    Issuer URL   jwks-uri -    The URL to the JSON Web Key Set (JWKS) that containing the public keys that should be used to verify any JSON Web Token (JWT) issued by the authorization server.   audience -    The audience in the JWT   bound-spid -    A list of service principal IDs that the access is restricted to   bound-group-id -    A list of group ids that the access is restricted to   bound-sub-id -    A list of subscription ids that the access is restricted to   bound-rg-id -    A list of resource groups that the access is restricted to   bound-providers -    A list of resource providers that the access is restricted to (e.g, Microsoft.Compute, Microsoft.ManagedIdentity, etc)   bound-resource-types -    A list of resource types that the access is restricted to (e.g, virtualMachines, userAssignedIdentities, etc)   bound-resource-names -    A list of resource names that the access is restricted to (e.g, a virtual machine name, scale set name, etc).   bound-resource-id -    A list of full resource ids that the access is restricted to   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

name = 'name_example' # String | Auth Method name

bound_tenant_id = 'bound_tenant_id_example' # String | The Azure tenant id that the access is restricted to

token = 'token_example' # String | Access token

opts = { 
  access_expires: 'access_expires_example', # String | Access expiration date in Unix timestamp (select 0 for access without expiry date)
  bound_ips: 'bound_ips_example', # String | A CIDR whitelist of the IPs that the access is restricted to
  issuer: 'issuer_example', # String | Issuer URL
  jwks_uri: 'jwks_uri_example', # String | The URL to the JSON Web Key Set (JWKS) that containing the public keys that should be used to verify any JSON Web Token (JWT) issued by the authorization server.
  audience: 'audience_example', # String | The audience in the JWT
  bound_spid: 'bound_spid_example', # String | A list of service principal IDs that the access is restricted to
  bound_group_id: 'bound_group_id_example', # String | A list of group ids that the access is restricted to
  bound_sub_id: 'bound_sub_id_example', # String | A list of subscription ids that the access is restricted to
  bound_rg_id: 'bound_rg_id_example', # String | A list of resource groups that the access is restricted to
  bound_providers: 'bound_providers_example', # String | A list of resource providers that the access is restricted to (e.g, Microsoft.Compute, Microsoft.ManagedIdentity, etc)
  bound_resource_types: 'bound_resource_types_example', # String | A list of resource types that the access is restricted to (e.g, virtualMachines, userAssignedIdentities, etc)
  bound_resource_names: 'bound_resource_names_example', # String | A list of resource names that the access is restricted to (e.g, a virtual machine name, scale set name, etc).
  bound_resource_id: 'bound_resource_id_example' # String | A list of full resource ids that the access is restricted to
}

begin
  #Create a new Auth Method that will be able to authenticate using Azure Active Directory credentials
  result = api_instance.create_auth_method_azure_ad(name, bound_tenant_id, token, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->create_auth_method_azure_ad: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Auth Method name | 
 **bound_tenant_id** | **String**| The Azure tenant id that the access is restricted to | 
 **token** | **String**| Access token | 
 **access_expires** | **String**| Access expiration date in Unix timestamp (select 0 for access without expiry date) | [optional] 
 **bound_ips** | **String**| A CIDR whitelist of the IPs that the access is restricted to | [optional] 
 **issuer** | **String**| Issuer URL | [optional] 
 **jwks_uri** | **String**| The URL to the JSON Web Key Set (JWKS) that containing the public keys that should be used to verify any JSON Web Token (JWT) issued by the authorization server. | [optional] 
 **audience** | **String**| The audience in the JWT | [optional] 
 **bound_spid** | **String**| A list of service principal IDs that the access is restricted to | [optional] 
 **bound_group_id** | **String**| A list of group ids that the access is restricted to | [optional] 
 **bound_sub_id** | **String**| A list of subscription ids that the access is restricted to | [optional] 
 **bound_rg_id** | **String**| A list of resource groups that the access is restricted to | [optional] 
 **bound_providers** | **String**| A list of resource providers that the access is restricted to (e.g, Microsoft.Compute, Microsoft.ManagedIdentity, etc) | [optional] 
 **bound_resource_types** | **String**| A list of resource types that the access is restricted to (e.g, virtualMachines, userAssignedIdentities, etc) | [optional] 
 **bound_resource_names** | **String**| A list of resource names that the access is restricted to (e.g, a virtual machine name, scale set name, etc). | [optional] 
 **bound_resource_id** | **String**| A list of full resource ids that the access is restricted to | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **create_auth_method_ldap**
> ReplyObj create_auth_method_ldap(name, public_key_file_path, token, opts)

Create a new Auth Method that will be able to authenticate using LDAP

Create a new Auth Method that will be able to authenticate using LDAP Options:   name -    Auth Method name   access-expires -    Access expiration date in Unix timestamp (select 0 for access without expiry date)   bound-ips -    A CIDR whitelist of the IPs that the access is restricted to   public-key-file-path -    A public key generated for LDAP authentication method on Akeyless [RSA2048]   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

name = 'name_example' # String | Auth Method name

public_key_file_path = 'public_key_file_path_example' # String | A public key generated for LDAP authentication method on Akeyless [RSA2048]

token = 'token_example' # String | Access token

opts = { 
  access_expires: 'access_expires_example', # String | Access expiration date in Unix timestamp (select 0 for access without expiry date)
  bound_ips: 'bound_ips_example' # String | A CIDR whitelist of the IPs that the access is restricted to
}

begin
  #Create a new Auth Method that will be able to authenticate using LDAP
  result = api_instance.create_auth_method_ldap(name, public_key_file_path, token, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->create_auth_method_ldap: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Auth Method name | 
 **public_key_file_path** | **String**| A public key generated for LDAP authentication method on Akeyless [RSA2048] | 
 **token** | **String**| Access token | 
 **access_expires** | **String**| Access expiration date in Unix timestamp (select 0 for access without expiry date) | [optional] 
 **bound_ips** | **String**| A CIDR whitelist of the IPs that the access is restricted to | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **create_auth_method_oauth2**
> ReplyObj create_auth_method_oauth2(name, bound_clients_ids, issuer, jwks_uri, audience, token, opts)

Create a new Auth Method that will be able to authenticate using OpenId/OAuth2

Create a new Auth Method that will be able to authenticate using OpenId/OAuth2 Options:   name -    Auth Method name   access-expires -    Access expiration date in Unix timestamp (select 0 for access without expiry date)   bound-ips -    A CIDR whitelist of the IPs that the access is restricted to   bound-clients-ids -    The clients ids that the access is restricted to   issuer -    Issuer URL   jwks-uri -    The URL to the JSON Web Key Set (JWKS) that containing the public keys that should be used to verify any JSON Web Token (JWT) issued by the authorization server.   audience -    The audience in the JWT   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

name = 'name_example' # String | Auth Method name

bound_clients_ids = 'bound_clients_ids_example' # String | The clients ids that the access is restricted to

issuer = 'issuer_example' # String | Issuer URL

jwks_uri = 'jwks_uri_example' # String | The URL to the JSON Web Key Set (JWKS) that containing the public keys that should be used to verify any JSON Web Token (JWT) issued by the authorization server.

audience = 'audience_example' # String | The audience in the JWT

token = 'token_example' # String | Access token

opts = { 
  access_expires: 'access_expires_example', # String | Access expiration date in Unix timestamp (select 0 for access without expiry date)
  bound_ips: 'bound_ips_example' # String | A CIDR whitelist of the IPs that the access is restricted to
}

begin
  #Create a new Auth Method that will be able to authenticate using OpenId/OAuth2
  result = api_instance.create_auth_method_oauth2(name, bound_clients_ids, issuer, jwks_uri, audience, token, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->create_auth_method_oauth2: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Auth Method name | 
 **bound_clients_ids** | **String**| The clients ids that the access is restricted to | 
 **issuer** | **String**| Issuer URL | 
 **jwks_uri** | **String**| The URL to the JSON Web Key Set (JWKS) that containing the public keys that should be used to verify any JSON Web Token (JWT) issued by the authorization server. | 
 **audience** | **String**| The audience in the JWT | 
 **token** | **String**| Access token | 
 **access_expires** | **String**| Access expiration date in Unix timestamp (select 0 for access without expiry date) | [optional] 
 **bound_ips** | **String**| A CIDR whitelist of the IPs that the access is restricted to | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **create_auth_method_saml**
> ReplyObj create_auth_method_saml(name, idp_metadata_url, token, opts)

Create a new Auth Method that will be able to authenticate using SAML

Create a new Auth Method that will be able to authenticate using SAML Options:   name -    Auth Method name   access-expires -    Access expiration date in Unix timestamp (select 0 for access without expiry date)   bound-ips -    A CIDR whitelist of the IPs that the access is restricted to   idp-metadata-url -    IDP metadata url   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

name = 'name_example' # String | Auth Method name

idp_metadata_url = 'idp_metadata_url_example' # String | IDP metadata url

token = 'token_example' # String | Access token

opts = { 
  access_expires: 'access_expires_example', # String | Access expiration date in Unix timestamp (select 0 for access without expiry date)
  bound_ips: 'bound_ips_example' # String | A CIDR whitelist of the IPs that the access is restricted to
}

begin
  #Create a new Auth Method that will be able to authenticate using SAML
  result = api_instance.create_auth_method_saml(name, idp_metadata_url, token, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->create_auth_method_saml: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Auth Method name | 
 **idp_metadata_url** | **String**| IDP metadata url | 
 **token** | **String**| Access token | 
 **access_expires** | **String**| Access expiration date in Unix timestamp (select 0 for access without expiry date) | [optional] 
 **bound_ips** | **String**| A CIDR whitelist of the IPs that the access is restricted to | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **create_dynamic_secret**
> ReplyObj create_dynamic_secret(name, token, opts)

Creates a new dynamic secret item

Creates a new dynamic secret item Options:   name -    Dynamic secret name   metadata -    Metadata about the dynamic secret   key -    The name of a key that used to encrypt the dynamic secret values (if empty, the account default protectionKey key will be used)   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

name = 'name_example' # String | Dynamic secret name

token = 'token_example' # String | Access token

opts = { 
  metadata: 'metadata_example', # String | Metadata about the dynamic secret
  key: 'key_example' # String | The name of a key that used to encrypt the dynamic secret values (if empty, the account default protectionKey key will be used)
}

begin
  #Creates a new dynamic secret item
  result = api_instance.create_dynamic_secret(name, token, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->create_dynamic_secret: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Dynamic secret name | 
 **token** | **String**| Access token | 
 **metadata** | **String**| Metadata about the dynamic secret | [optional] 
 **key** | **String**| The name of a key that used to encrypt the dynamic secret values (if empty, the account default protectionKey key will be used) | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **create_key**
> ReplyObj create_key(name, alg, token, opts)

Creates a new key

Creates a new key Options:   name -    Key name   alg -    Key type. options- [AES128GCM, AES256GCM, AES128SIV, AES256SIV, RSA1024, RSA2048]   metadata -    Metadata about the key   split-level -    The number of fragments that the item will be split into (not includes customer fragment)   customer-frg-id -    The customer fragment ID that will be used to create the key (if empty, the key will be created independently of a customer fragment)   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

name = 'name_example' # String | Key name

alg = 'alg_example' # String | Key type. options- [AES128GCM, AES256GCM, AES128SIV, AES256SIV, RSA1024, RSA2048]

token = 'token_example' # String | Access token

opts = { 
  metadata: 'metadata_example', # String | Metadata about the key
  split_level: 'split_level_example', # String | The number of fragments that the item will be split into (not includes customer fragment)
  customer_frg_id: 'customer_frg_id_example' # String | The customer fragment ID that will be used to create the key (if empty, the key will be created independently of a customer fragment)
}

begin
  #Creates a new key
  result = api_instance.create_key(name, alg, token, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->create_key: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Key name | 
 **alg** | **String**| Key type. options- [AES128GCM, AES256GCM, AES128SIV, AES256SIV, RSA1024, RSA2048] | 
 **token** | **String**| Access token | 
 **metadata** | **String**| Metadata about the key | [optional] 
 **split_level** | **String**| The number of fragments that the item will be split into (not includes customer fragment) | [optional] 
 **customer_frg_id** | **String**| The customer fragment ID that will be used to create the key (if empty, the key will be created independently of a customer fragment) | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **create_pki_cert_issuer**
> ReplyObj create_pki_cert_issuer(name, signer_key_name, ttl, token, opts)

Creates a new PKI certificate issuer

Creates a new PKI certificate issuer Options:   name -    PKI certificate issuer name   signer-key-name -    A key to sign the certificate with   allowed-domains -    A list of the allowed domains that clients can request to be included in the certificate (in a comma-delimited list)   allowed-uri-sans -    A list of the allowed URIs that clients can request to be included in the certificate as part of the URI Subject Alternative Names (in a comma-delimited list)   allow-subdomains -    If set, clients can request certificates for subdomains and wildcard subdomains of the allowed domains   not-enforce-hostnames -    If set, any names are allowed for CN and SANs in the certificate and not only a valid host name   allow-any-name -    If set, clients can request certificates for any CN   not-require-cn -    If set, clients can request certificates without a CN   server-flag -    If set, certificates will be flagged for server auth use   client-flag -    If set, certificates will be flagged for client auth use   code-signing-flag -    If set, certificates will be flagged for code signing use   key-usage -    A comma-separated string or list of key usages   organization-units -    A comma-separated list of organizational units (OU) that will be set in the issued certificate   organizations -    A comma-separated list of organizations (O) that will be set in the issued certificate   country -    A comma-separated list of the country that will be set in the issued certificate   locality -    A comma-separated list of the locality that will be set in the issued certificate   province -    A comma-separated list of the province that will be set in the issued certificate   street-address -    A comma-separated list of the street address that will be set in the issued certificate   postal-code -    A comma-separated list of the postal code that will be set in the issued certificate   ttl -    The requested Time To Live for the certificate, use second units   metadata -    A metadata about the issuer   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

name = 'name_example' # String | PKI certificate issuer name

signer_key_name = 'signer_key_name_example' # String | A key to sign the certificate with

ttl = 'ttl_example' # String | The requested Time To Live for the certificate, use second units

token = 'token_example' # String | Access token

opts = { 
  allowed_domains: 'allowed_domains_example', # String | A list of the allowed domains that clients can request to be included in the certificate (in a comma-delimited list)
  allowed_uri_sans: 'allowed_uri_sans_example', # String | A list of the allowed URIs that clients can request to be included in the certificate as part of the URI Subject Alternative Names (in a comma-delimited list)
  allow_subdomains: 'allow_subdomains_example', # String | If set, clients can request certificates for subdomains and wildcard subdomains of the allowed domains
  not_enforce_hostnames: 'not_enforce_hostnames_example', # String | If set, any names are allowed for CN and SANs in the certificate and not only a valid host name
  allow_any_name: 'allow_any_name_example', # String | If set, clients can request certificates for any CN
  not_require_cn: 'not_require_cn_example', # String | If set, clients can request certificates without a CN
  server_flag: 'server_flag_example', # String | If set, certificates will be flagged for server auth use
  client_flag: 'client_flag_example', # String | If set, certificates will be flagged for client auth use
  code_signing_flag: 'code_signing_flag_example', # String | If set, certificates will be flagged for code signing use
  key_usage: 'key_usage_example', # String | A comma-separated string or list of key usages
  organization_units: 'organization_units_example', # String | A comma-separated list of organizational units (OU) that will be set in the issued certificate
  organizations: 'organizations_example', # String | A comma-separated list of organizations (O) that will be set in the issued certificate
  country: 'country_example', # String | A comma-separated list of the country that will be set in the issued certificate
  locality: 'locality_example', # String | A comma-separated list of the locality that will be set in the issued certificate
  province: 'province_example', # String | A comma-separated list of the province that will be set in the issued certificate
  street_address: 'street_address_example', # String | A comma-separated list of the street address that will be set in the issued certificate
  postal_code: 'postal_code_example', # String | A comma-separated list of the postal code that will be set in the issued certificate
  metadata: 'metadata_example' # String | A metadata about the issuer
}

begin
  #Creates a new PKI certificate issuer
  result = api_instance.create_pki_cert_issuer(name, signer_key_name, ttl, token, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->create_pki_cert_issuer: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| PKI certificate issuer name | 
 **signer_key_name** | **String**| A key to sign the certificate with | 
 **ttl** | **String**| The requested Time To Live for the certificate, use second units | 
 **token** | **String**| Access token | 
 **allowed_domains** | **String**| A list of the allowed domains that clients can request to be included in the certificate (in a comma-delimited list) | [optional] 
 **allowed_uri_sans** | **String**| A list of the allowed URIs that clients can request to be included in the certificate as part of the URI Subject Alternative Names (in a comma-delimited list) | [optional] 
 **allow_subdomains** | **String**| If set, clients can request certificates for subdomains and wildcard subdomains of the allowed domains | [optional] 
 **not_enforce_hostnames** | **String**| If set, any names are allowed for CN and SANs in the certificate and not only a valid host name | [optional] 
 **allow_any_name** | **String**| If set, clients can request certificates for any CN | [optional] 
 **not_require_cn** | **String**| If set, clients can request certificates without a CN | [optional] 
 **server_flag** | **String**| If set, certificates will be flagged for server auth use | [optional] 
 **client_flag** | **String**| If set, certificates will be flagged for client auth use | [optional] 
 **code_signing_flag** | **String**| If set, certificates will be flagged for code signing use | [optional] 
 **key_usage** | **String**| A comma-separated string or list of key usages | [optional] 
 **organization_units** | **String**| A comma-separated list of organizational units (OU) that will be set in the issued certificate | [optional] 
 **organizations** | **String**| A comma-separated list of organizations (O) that will be set in the issued certificate | [optional] 
 **country** | **String**| A comma-separated list of the country that will be set in the issued certificate | [optional] 
 **locality** | **String**| A comma-separated list of the locality that will be set in the issued certificate | [optional] 
 **province** | **String**| A comma-separated list of the province that will be set in the issued certificate | [optional] 
 **street_address** | **String**| A comma-separated list of the street address that will be set in the issued certificate | [optional] 
 **postal_code** | **String**| A comma-separated list of the postal code that will be set in the issued certificate | [optional] 
 **metadata** | **String**| A metadata about the issuer | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **create_role**
> ReplyObj create_role(name, token, opts)

Creates a new role

Creates a new role Options:   name -    Role name   comment -    Comment about the role   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

name = 'name_example' # String | Role name

token = 'token_example' # String | Access token

opts = { 
  comment: 'comment_example' # String | Comment about the role
}

begin
  #Creates a new role
  result = api_instance.create_role(name, token, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->create_role: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Role name | 
 **token** | **String**| Access token | 
 **comment** | **String**| Comment about the role | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **create_secret**
> ReplyObj create_secret(name, value, token, opts)

Creates a new secret item

Creates a new secret item Options:   name -    Secret name   value -    The secret value   metadata -    Metadata about the secret   key -    The name of a key that used to encrypt the secret value (if empty, the account default protectionKey key will be used)   multiline -    The provided value is a multiline value (separated by '\\n')   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

name = 'name_example' # String | Secret name

value = 'value_example' # String | The secret value

token = 'token_example' # String | Access token

opts = { 
  metadata: 'metadata_example', # String | Metadata about the secret
  key: 'key_example', # String | The name of a key that used to encrypt the secret value (if empty, the account default protectionKey key will be used)
  multiline: true # BOOLEAN | The provided value is a multiline value (separated by '\\n')
}

begin
  #Creates a new secret item
  result = api_instance.create_secret(name, value, token, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->create_secret: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Secret name | 
 **value** | **String**| The secret value | 
 **token** | **String**| Access token | 
 **metadata** | **String**| Metadata about the secret | [optional] 
 **key** | **String**| The name of a key that used to encrypt the secret value (if empty, the account default protectionKey key will be used) | [optional] 
 **multiline** | **BOOLEAN**| The provided value is a multiline value (separated by &#39;\\n&#39;) | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **create_ssh_cert_issuer**
> ReplyObj create_ssh_cert_issuer(name, signer_key_name, allowed_users, ttl, token, opts)

Creates a new SSH certificate issuer

Creates a new SSH certificate issuer Options:   name -    SSH certificate issuer name   signer-key-name -    A key to sign the certificate with   allowed-users -    Users allowed to fetch the certificate, ex. root,ubuntu   principals -    Signed certificates with principal, ex. example_role1,example_role2   extensions -    Signed certificates with extensions, ex. permit-port-forwarding=\"\"   ttl -    The requested Time To Live for the certificate, use second units   metadata -    A metadata about the issuer   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

name = 'name_example' # String | SSH certificate issuer name

signer_key_name = 'signer_key_name_example' # String | A key to sign the certificate with

allowed_users = 'allowed_users_example' # String | Users allowed to fetch the certificate, ex. root,ubuntu

ttl = 'ttl_example' # String | The requested Time To Live for the certificate, use second units

token = 'token_example' # String | Access token

opts = { 
  principals: 'principals_example', # String | Signed certificates with principal, ex. example_role1,example_role2
  extensions: 'extensions_example', # String | Signed certificates with extensions, ex. permit-port-forwarding=\"\"
  metadata: 'metadata_example' # String | A metadata about the issuer
}

begin
  #Creates a new SSH certificate issuer
  result = api_instance.create_ssh_cert_issuer(name, signer_key_name, allowed_users, ttl, token, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->create_ssh_cert_issuer: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| SSH certificate issuer name | 
 **signer_key_name** | **String**| A key to sign the certificate with | 
 **allowed_users** | **String**| Users allowed to fetch the certificate, ex. root,ubuntu | 
 **ttl** | **String**| The requested Time To Live for the certificate, use second units | 
 **token** | **String**| Access token | 
 **principals** | **String**| Signed certificates with principal, ex. example_role1,example_role2 | [optional] 
 **extensions** | **String**| Signed certificates with extensions, ex. permit-port-forwarding&#x3D;\&quot;\&quot; | [optional] 
 **metadata** | **String**| A metadata about the issuer | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **decrypt**
> ReplyObj decrypt(key_name, ciphertext, token, opts)

Decrypts ciphertext into plaintext by using an AES key

Decrypts ciphertext into plaintext by using an AES key Options:   key-name -    The name of the key to use in the decryption process   ciphertext -    Ciphertext to be decrypted in base64 encoded format   encryption-context -    The encryption context. If this was specified in the encrypt command, it must be specified here or the decryption operation will fail   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

key_name = 'key_name_example' # String | The name of the key to use in the decryption process

ciphertext = 'ciphertext_example' # String | Ciphertext to be decrypted in base64 encoded format

token = 'token_example' # String | Access token

opts = { 
  encryption_context: 'encryption_context_example' # String | The encryption context. If this was specified in the encrypt command, it must be specified here or the decryption operation will fail
}

begin
  #Decrypts ciphertext into plaintext by using an AES key
  result = api_instance.decrypt(key_name, ciphertext, token, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->decrypt: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **key_name** | **String**| The name of the key to use in the decryption process | 
 **ciphertext** | **String**| Ciphertext to be decrypted in base64 encoded format | 
 **token** | **String**| Access token | 
 **encryption_context** | **String**| The encryption context. If this was specified in the encrypt command, it must be specified here or the decryption operation will fail | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **decrypt_file**
> ReplyObj decrypt_file(key_name, _in, token, opts)

Decrypts a file by using an AES key

Decrypts a file by using an AES key Options:   key-name -    The name of the key to use in the decryption process   in -    Path to the file to be decrypted. If not provided, the content will be taken from stdin   out -    Path to the output file. If not provided, the output will be sent to stdout   encryption-context -    The encryption context. If this was specified in the encrypt command, it must be specified here or the decryption operation will fail   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

key_name = 'key_name_example' # String | The name of the key to use in the decryption process

_in = '_in_example' # String | Path to the file to be decrypted. If not provided, the content will be taken from stdin

token = 'token_example' # String | Access token

opts = { 
  out: 'out_example', # String | Path to the output file. If not provided, the output will be sent to stdout
  encryption_context: 'encryption_context_example' # String | The encryption context. If this was specified in the encrypt command, it must be specified here or the decryption operation will fail
}

begin
  #Decrypts a file by using an AES key
  result = api_instance.decrypt_file(key_name, _in, token, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->decrypt_file: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **key_name** | **String**| The name of the key to use in the decryption process | 
 **_in** | **String**| Path to the file to be decrypted. If not provided, the content will be taken from stdin | 
 **token** | **String**| Access token | 
 **out** | **String**| Path to the output file. If not provided, the output will be sent to stdout | [optional] 
 **encryption_context** | **String**| The encryption context. If this was specified in the encrypt command, it must be specified here or the decryption operation will fail | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **decrypt_pkcs1**
> ReplyObj decrypt_pkcs1(key_name, ciphertext, token)

Decrypts a plaintext using RSA and the padding scheme from PKCS#1 v1.5

Decrypts a plaintext using RSA and the padding scheme from PKCS#1 v1.5 Options:   key-name -    The name of the RSA key to use in the decryption process   ciphertext -    Ciphertext to be decrypted in base64 encoded format   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

key_name = 'key_name_example' # String | The name of the RSA key to use in the decryption process

ciphertext = 'ciphertext_example' # String | Ciphertext to be decrypted in base64 encoded format

token = 'token_example' # String | Access token


begin
  #Decrypts a plaintext using RSA and the padding scheme from PKCS#1 v1.5
  result = api_instance.decrypt_pkcs1(key_name, ciphertext, token)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->decrypt_pkcs1: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **key_name** | **String**| The name of the RSA key to use in the decryption process | 
 **ciphertext** | **String**| Ciphertext to be decrypted in base64 encoded format | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **delete_assoc**
> ReplyObj delete_assoc(assoc_id, token)

Delete an association between role and auth method

Delete an association between role and auth method Options:   assoc-id -    The association id to be deleted   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

assoc_id = 'assoc_id_example' # String | The association id to be deleted

token = 'token_example' # String | Access token


begin
  #Delete an association between role and auth method
  result = api_instance.delete_assoc(assoc_id, token)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->delete_assoc: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **assoc_id** | **String**| The association id to be deleted | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **delete_auth_method**
> ReplyObj delete_auth_method(name, token)

Delete the Auth Method

Delete the Auth Method Options:   name -    Auth Method name   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

name = 'name_example' # String | Auth Method name

token = 'token_example' # String | Access token


begin
  #Delete the Auth Method
  result = api_instance.delete_auth_method(name, token)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->delete_auth_method: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Auth Method name | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **delete_item**
> ReplyObj delete_item(name, token)

Delete an item

Delete an item Options:   name -    Item name   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

name = 'name_example' # String | Item name

token = 'token_example' # String | Access token


begin
  #Delete an item
  result = api_instance.delete_item(name, token)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->delete_item: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Item name | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **delete_role**
> ReplyObj delete_role(name, token)

Delete a role

Delete a role Options:   name -    Role name   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

name = 'name_example' # String | Role name

token = 'token_example' # String | Access token


begin
  #Delete a role
  result = api_instance.delete_role(name, token)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->delete_role: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Role name | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **delete_role_rule**
> ReplyObj delete_role_rule(role_name, path, token)

Delete a rule from a role

Delete a rule from a role Options:   role-name -    The role name to be updated   path -    The path the rule refers to   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

role_name = 'role_name_example' # String | The role name to be updated

path = 'path_example' # String | The path the rule refers to

token = 'token_example' # String | Access token


begin
  #Delete a rule from a role
  result = api_instance.delete_role_rule(role_name, path, token)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->delete_role_rule: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **role_name** | **String**| The role name to be updated | 
 **path** | **String**| The path the rule refers to | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **describe_item**
> ReplyObj describe_item(name, token)

Returns the item details

Returns the item details Options:   name -    Item name   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

name = 'name_example' # String | Item name

token = 'token_example' # String | Access token


begin
  #Returns the item details
  result = api_instance.describe_item(name, token)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->describe_item: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Item name | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **encrypt**
> ReplyObj encrypt(key_name, plaintext, token, opts)

Encrypts plaintext into ciphertext by using an AES key

Encrypts plaintext into ciphertext by using an AES key Options:   key-name -    The name of the key to use in the encryption process   plaintext -    Data to be encrypted   encryption-context -    name-value pair that specifies the encryption context to be used for authenticated encryption. If used here, the same value must be supplied to the decrypt command or decryption will fail   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

key_name = 'key_name_example' # String | The name of the key to use in the encryption process

plaintext = 'plaintext_example' # String | Data to be encrypted

token = 'token_example' # String | Access token

opts = { 
  encryption_context: 'encryption_context_example' # String | name-value pair that specifies the encryption context to be used for authenticated encryption. If used here, the same value must be supplied to the decrypt command or decryption will fail
}

begin
  #Encrypts plaintext into ciphertext by using an AES key
  result = api_instance.encrypt(key_name, plaintext, token, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->encrypt: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **key_name** | **String**| The name of the key to use in the encryption process | 
 **plaintext** | **String**| Data to be encrypted | 
 **token** | **String**| Access token | 
 **encryption_context** | **String**| name-value pair that specifies the encryption context to be used for authenticated encryption. If used here, the same value must be supplied to the decrypt command or decryption will fail | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **encrypt_file**
> ReplyObj encrypt_file(key_name, _in, token, opts)

Encrypts a file by using an AES key

Encrypts a file by using an AES key Options:   key-name -    The name of the key to use in the encryption process   in -    Path to the file to be encrypted. If not provided, the content will be taken from stdin   out -    Path to the output file. If not provided, the output will be sent to stdout   encryption-context -    name-value pair that specifies the encryption context to be used for authenticated encryption. If used here, the same value must be supplied to the decrypt command or decryption will fail   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

key_name = 'key_name_example' # String | The name of the key to use in the encryption process

_in = '_in_example' # String | Path to the file to be encrypted. If not provided, the content will be taken from stdin

token = 'token_example' # String | Access token

opts = { 
  out: 'out_example', # String | Path to the output file. If not provided, the output will be sent to stdout
  encryption_context: 'encryption_context_example' # String | name-value pair that specifies the encryption context to be used for authenticated encryption. If used here, the same value must be supplied to the decrypt command or decryption will fail
}

begin
  #Encrypts a file by using an AES key
  result = api_instance.encrypt_file(key_name, _in, token, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->encrypt_file: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **key_name** | **String**| The name of the key to use in the encryption process | 
 **_in** | **String**| Path to the file to be encrypted. If not provided, the content will be taken from stdin | 
 **token** | **String**| Access token | 
 **out** | **String**| Path to the output file. If not provided, the output will be sent to stdout | [optional] 
 **encryption_context** | **String**| name-value pair that specifies the encryption context to be used for authenticated encryption. If used here, the same value must be supplied to the decrypt command or decryption will fail | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **encrypt_pkcs1**
> ReplyObj encrypt_pkcs1(key_name, plaintext, token)

Encrypts the given message with RSA and the padding scheme from PKCS#1 v1.5

Encrypts the given message with RSA and the padding scheme from PKCS#1 v1.5 Options:   key-name -    The name of the RSA key to use in the encryption process   plaintext -    Data to be encrypted   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

key_name = 'key_name_example' # String | The name of the RSA key to use in the encryption process

plaintext = 'plaintext_example' # String | Data to be encrypted

token = 'token_example' # String | Access token


begin
  #Encrypts the given message with RSA and the padding scheme from PKCS#1 v1.5
  result = api_instance.encrypt_pkcs1(key_name, plaintext, token)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->encrypt_pkcs1: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **key_name** | **String**| The name of the RSA key to use in the encryption process | 
 **plaintext** | **String**| Data to be encrypted | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **get_auth_method**
> ReplyObj get_auth_method(name, token)

Returns an information about the Auth Method

Returns an information about the Auth Method Options:   name -    Auth Method name   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

name = 'name_example' # String | Auth Method name

token = 'token_example' # String | Access token


begin
  #Returns an information about the Auth Method
  result = api_instance.get_auth_method(name, token)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->get_auth_method: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Auth Method name | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **get_cloud_identity**
> ReplyObj get_cloud_identity(token, opts)

Get Cloud Identity Token (relevant only for access-type=azure_ad,aws_iam)

Get Cloud Identity Token (relevant only for access-type=azure_ad,aws_iam) Options:   azure_ad_object_id -    Azure Active Directory ObjectId (relevant only for access-type=azure_ad)   url_safe -    escapes the token so it can be safely placed inside a URL query   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

token = 'token_example' # String | Access token

opts = { 
  azure_ad_object_id: 'azure_ad_object_id_example', # String | Azure Active Directory ObjectId (relevant only for access-type=azure_ad)
  url_safe: 'url_safe_example' # String | escapes the token so it can be safely placed inside a URL query
}

begin
  #Get Cloud Identity Token (relevant only for access-type=azure_ad,aws_iam)
  result = api_instance.get_cloud_identity(token, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->get_cloud_identity: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **token** | **String**| Access token | 
 **azure_ad_object_id** | **String**| Azure Active Directory ObjectId (relevant only for access-type&#x3D;azure_ad) | [optional] 
 **url_safe** | **String**| escapes the token so it can be safely placed inside a URL query | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **get_dynamic_secret_value**
> ReplyObj get_dynamic_secret_value(name, token)

Get dynamic secret value

Get dynamic secret value Options:   name -    Dynamic secret name   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

name = 'name_example' # String | Dynamic secret name

token = 'token_example' # String | Access token


begin
  #Get dynamic secret value
  result = api_instance.get_dynamic_secret_value(name, token)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->get_dynamic_secret_value: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Dynamic secret name | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **get_kube_exec_creds**
> ReplyObj get_kube_exec_creds(cert_issuer_name, key_file_path, token, opts)

Get credentials for authentication with Kubernetes cluster based on a PKI Cert Issuer

Get credentials for authentication with Kubernetes cluster based on a PKI Cert Issuer Options:   cert-issuer-name -    The name of the PKI certificate issuer   key-file-path -    The client public or private key file path (in case of a private key, it will be use to extract the public key)   common-name -    The common name to be included in the PKI certificate   alt-names -    The Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list)   uri-sans -    The URI Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list)   outfile -    Output file path with the certificate. If not provided, the file with the certificate will be created in the same location of the provided public key with the -cert extension   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

cert_issuer_name = 'cert_issuer_name_example' # String | The name of the PKI certificate issuer

key_file_path = 'key_file_path_example' # String | The client public or private key file path (in case of a private key, it will be use to extract the public key)

token = 'token_example' # String | Access token

opts = { 
  common_name: 'common_name_example', # String | The common name to be included in the PKI certificate
  alt_names: 'alt_names_example', # String | The Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list)
  uri_sans: 'uri_sans_example', # String | The URI Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list)
  outfile: 'outfile_example' # String | Output file path with the certificate. If not provided, the file with the certificate will be created in the same location of the provided public key with the -cert extension
}

begin
  #Get credentials for authentication with Kubernetes cluster based on a PKI Cert Issuer
  result = api_instance.get_kube_exec_creds(cert_issuer_name, key_file_path, token, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->get_kube_exec_creds: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **cert_issuer_name** | **String**| The name of the PKI certificate issuer | 
 **key_file_path** | **String**| The client public or private key file path (in case of a private key, it will be use to extract the public key) | 
 **token** | **String**| Access token | 
 **common_name** | **String**| The common name to be included in the PKI certificate | [optional] 
 **alt_names** | **String**| The Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list) | [optional] 
 **uri_sans** | **String**| The URI Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list) | [optional] 
 **outfile** | **String**| Output file path with the certificate. If not provided, the file with the certificate will be created in the same location of the provided public key with the -cert extension | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **get_pki_certificate**
> ReplyObj get_pki_certificate(cert_issuer_name, key_file_path, token, opts)

Generates PKI certificate

Generates PKI certificate Options:   cert-issuer-name -    The name of the PKI certificate issuer   key-file-path -    The client public or private key file path (in case of a private key, it will be use to extract the public key)   common-name -    The common name to be included in the PKI certificate   alt-names -    The Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list)   uri-sans -    The URI Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list)   outfile -    Output file path with the certificate. If not provided, the file with the certificate will be created in the same location of the provided public key with the -cert extension   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

cert_issuer_name = 'cert_issuer_name_example' # String | The name of the PKI certificate issuer

key_file_path = 'key_file_path_example' # String | The client public or private key file path (in case of a private key, it will be use to extract the public key)

token = 'token_example' # String | Access token

opts = { 
  common_name: 'common_name_example', # String | The common name to be included in the PKI certificate
  alt_names: 'alt_names_example', # String | The Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list)
  uri_sans: 'uri_sans_example', # String | The URI Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list)
  outfile: 'outfile_example' # String | Output file path with the certificate. If not provided, the file with the certificate will be created in the same location of the provided public key with the -cert extension
}

begin
  #Generates PKI certificate
  result = api_instance.get_pki_certificate(cert_issuer_name, key_file_path, token, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->get_pki_certificate: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **cert_issuer_name** | **String**| The name of the PKI certificate issuer | 
 **key_file_path** | **String**| The client public or private key file path (in case of a private key, it will be use to extract the public key) | 
 **token** | **String**| Access token | 
 **common_name** | **String**| The common name to be included in the PKI certificate | [optional] 
 **alt_names** | **String**| The Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list) | [optional] 
 **uri_sans** | **String**| The URI Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list) | [optional] 
 **outfile** | **String**| Output file path with the certificate. If not provided, the file with the certificate will be created in the same location of the provided public key with the -cert extension | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **get_role**
> ReplyObj get_role(name, token)

Get role details

Get role details Options:   name -    Role name   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

name = 'name_example' # String | Role name

token = 'token_example' # String | Access token


begin
  #Get role details
  result = api_instance.get_role(name, token)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->get_role: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Role name | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **get_rsa_public**
> ReplyObj get_rsa_public(name, token)

Obtain the public key from a specific RSA private key

Obtain the public key from a specific RSA private key Options:   name -    Name of key to be created   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

name = 'name_example' # String | Name of key to be created

token = 'token_example' # String | Access token


begin
  #Obtain the public key from a specific RSA private key
  result = api_instance.get_rsa_public(name, token)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->get_rsa_public: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Name of key to be created | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **get_secret_value**
> ReplyObj get_secret_value(name, token)

Get static secret value

Get static secret value Options:   name -    Secret name   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

name = 'name_example' # String | Secret name

token = 'token_example' # String | Access token


begin
  #Get static secret value
  result = api_instance.get_secret_value(name, token)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->get_secret_value: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Secret name | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **get_ssh_certificate**
> ReplyObj get_ssh_certificate(cert_username, cert_issuer_name, public_key_file_path, token, opts)

Generates SSH certificate

Generates SSH certificate Options:   cert-username -    The username to sign in the SSH certificate   cert-issuer-name -    The name of the SSH certificate issuer   public-key-file-path -    SSH public key   outfile -    Output file path with the certificate. If not provided, the file with the certificate will be created in the same location of the provided public key with the -cert extension   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

cert_username = 'cert_username_example' # String | The username to sign in the SSH certificate

cert_issuer_name = 'cert_issuer_name_example' # String | The name of the SSH certificate issuer

public_key_file_path = 'public_key_file_path_example' # String | SSH public key

token = 'token_example' # String | Access token

opts = { 
  outfile: 'outfile_example' # String | Output file path with the certificate. If not provided, the file with the certificate will be created in the same location of the provided public key with the -cert extension
}

begin
  #Generates SSH certificate
  result = api_instance.get_ssh_certificate(cert_username, cert_issuer_name, public_key_file_path, token, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->get_ssh_certificate: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **cert_username** | **String**| The username to sign in the SSH certificate | 
 **cert_issuer_name** | **String**| The name of the SSH certificate issuer | 
 **public_key_file_path** | **String**| SSH public key | 
 **token** | **String**| Access token | 
 **outfile** | **String**| Output file path with the certificate. If not provided, the file with the certificate will be created in the same location of the provided public key with the -cert extension | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **help**
> ReplyObj help

help text

help text

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

begin
  #help text
  result = api_instance.help
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->help: #{e}"
end
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **list_auth_methods**
> ReplyObj list_auth_methods(token, opts)

Returns a list of all the Auth Methods in the account

Returns a list of all the Auth Methods in the account Options:   pagination-token -    Next page reference   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

token = 'token_example' # String | Access token

opts = { 
  pagination_token: 'pagination_token_example' # String | Next page reference
}

begin
  #Returns a list of all the Auth Methods in the account
  result = api_instance.list_auth_methods(token, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->list_auth_methods: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **token** | **String**| Access token | 
 **pagination_token** | **String**| Next page reference | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **list_items**
> ReplyObj list_items(token, opts)

Returns a list of all accessible items

Returns a list of all accessible items Options:   type -    The item types list of the requested items. In case it is empty, all types of items will be returned. options- [key, static-secret, dynamic-secret]   ItemsTypes -    ItemsTypes   filter -    Filter by item name or part of it   path -    Path to folder   pagination-token -    Next page reference   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

token = 'token_example' # String | Access token

opts = { 
  type: 'type_example', # String | The item types list of the requested items. In case it is empty, all types of items will be returned. options- [key, static-secret, dynamic-secret]
  items_types: 'items_types_example', # String | ItemsTypes
  filter: 'filter_example', # String | Filter by item name or part of it
  path: 'path_example', # String | Path to folder
  pagination_token: 'pagination_token_example' # String | Next page reference
}

begin
  #Returns a list of all accessible items
  result = api_instance.list_items(token, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->list_items: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **token** | **String**| Access token | 
 **type** | **String**| The item types list of the requested items. In case it is empty, all types of items will be returned. options- [key, static-secret, dynamic-secret] | [optional] 
 **items_types** | **String**| ItemsTypes | [optional] 
 **filter** | **String**| Filter by item name or part of it | [optional] 
 **path** | **String**| Path to folder | [optional] 
 **pagination_token** | **String**| Next page reference | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **list_roles**
> ReplyObj list_roles(token, opts)

Returns a list of all roles in the account

Returns a list of all roles in the account Options:   pagination-token -    Next page reference   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

token = 'token_example' # String | Access token

opts = { 
  pagination_token: 'pagination_token_example' # String | Next page reference
}

begin
  #Returns a list of all roles in the account
  result = api_instance.list_roles(token, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->list_roles: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **token** | **String**| Access token | 
 **pagination_token** | **String**| Next page reference | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **set_role_rule**
> ReplyObj set_role_rule(role_name, path, capability, token)

Set a rule to a role

Set a rule to a role Options:   role-name -    The role name to be updated   path -    The path the rule refers to   capability -    List of the approved/denied capabilities in the path options- [read, create, update, delete, list, deny]   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

role_name = 'role_name_example' # String | The role name to be updated

path = 'path_example' # String | The path the rule refers to

capability = 'capability_example' # String | List of the approved/denied capabilities in the path options- [read, create, update, delete, list, deny]

token = 'token_example' # String | Access token


begin
  #Set a rule to a role
  result = api_instance.set_role_rule(role_name, path, capability, token)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->set_role_rule: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **role_name** | **String**| The role name to be updated | 
 **path** | **String**| The path the rule refers to | 
 **capability** | **String**| List of the approved/denied capabilities in the path options- [read, create, update, delete, list, deny] | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **sign_pkcs1**
> ReplyObj sign_pkcs1(key_name, message, token)

Calculates the signature of hashed using RSASSA-PKCS1-V1_5-SIGN from RSA PKCS#1 v1.5

Calculates the signature of hashed using RSASSA-PKCS1-V1_5-SIGN from RSA PKCS#1 v1.5 Options:   key-name -    The name of the RSA key to use in the signing process   message -    The message to be signed   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

key_name = 'key_name_example' # String | The name of the RSA key to use in the signing process

message = 'message_example' # String | The message to be signed

token = 'token_example' # String | Access token


begin
  #Calculates the signature of hashed using RSASSA-PKCS1-V1_5-SIGN from RSA PKCS#1 v1.5
  result = api_instance.sign_pkcs1(key_name, message, token)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->sign_pkcs1: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **key_name** | **String**| The name of the RSA key to use in the signing process | 
 **message** | **String**| The message to be signed | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **unconfigure**
> ReplyObj unconfigure(token)

Remove Configuration of client profile.

Remove Configuration of client profile. Options:   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

token = 'token_example' # String | Access token


begin
  #Remove Configuration of client profile.
  result = api_instance.unconfigure(token)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->unconfigure: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **update**
> ReplyObj update(token)

Update a new AKEYLESS CLI version

Update a new AKEYLESS CLI version Options:   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

token = 'token_example' # String | Access token


begin
  #Update a new AKEYLESS CLI version
  result = api_instance.update(token)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->update: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **update_item**
> ReplyObj update_item(name, token, opts)

Update item name and metadata

Update item name and metadata Options:   name -    Current item name   new-name -    New item name   new-metadata -    New item metadata   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

name = 'name_example' # String | Current item name

token = 'token_example' # String | Access token

opts = { 
  new_name: 'new_name_example', # String | New item name
  new_metadata: 'new_metadata_example' # String | New item metadata
}

begin
  #Update item name and metadata
  result = api_instance.update_item(name, token, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->update_item: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Current item name | 
 **token** | **String**| Access token | 
 **new_name** | **String**| New item name | [optional] 
 **new_metadata** | **String**| New item metadata | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **update_role**
> ReplyObj update_role(name, token, opts)

Update role details

Update role details Options:   name -    Role name   new-name -    New Role name   new-comment -    New comment about the role   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

name = 'name_example' # String | Role name

token = 'token_example' # String | Access token

opts = { 
  new_name: 'new_name_example', # String | New Role name
  new_comment: 'new_comment_example' # String | New comment about the role
}

begin
  #Update role details
  result = api_instance.update_role(name, token, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->update_role: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Role name | 
 **token** | **String**| Access token | 
 **new_name** | **String**| New Role name | [optional] 
 **new_comment** | **String**| New comment about the role | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **update_secret_val**
> ReplyObj update_secret_val(name, value, token, opts)

Update static secret value

Update static secret value Options:   name -    Secret name   value -    The new secret value   key -    The name of a key that used to encrypt the secret value (if empty, the account default protectionKey key will be used)   multiline -    The provided value is a multiline value (separated by '\\n')   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

name = 'name_example' # String | Secret name

value = 'value_example' # String | The new secret value

token = 'token_example' # String | Access token

opts = { 
  key: 'key_example', # String | The name of a key that used to encrypt the secret value (if empty, the account default protectionKey key will be used)
  multiline: true # BOOLEAN | The provided value is a multiline value (separated by '\\n')
}

begin
  #Update static secret value
  result = api_instance.update_secret_val(name, value, token, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->update_secret_val: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Secret name | 
 **value** | **String**| The new secret value | 
 **token** | **String**| Access token | 
 **key** | **String**| The name of a key that used to encrypt the secret value (if empty, the account default protectionKey key will be used) | [optional] 
 **multiline** | **BOOLEAN**| The provided value is a multiline value (separated by &#39;\\n&#39;) | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **upload_pkcs12**
> ReplyObj upload_pkcs12(name, _in, passphrase, token, opts)

Upload a PKCS#12 key and certificates

Upload a PKCS#12 key and certificates Options:   name -    Name of key to be created   in -    PKCS#12 input file (private key and certificate only)   passphrase -    Passphrase to unlock the pkcs#12 bundle   metadata -    A metadata about the key   split-level -    The number of fragments that the item will be split into   customer-frg-id -    The customer fragment ID that will be used to split the key (if empty, the key will be created independently of a customer fragment)   cert -    Path to a file that contain the certificate in a PEM format. If this parameter is not empty, the certificate will be taken from here and not from the PKCS#12 input file   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

name = 'name_example' # String | Name of key to be created

_in = '_in_example' # String | PKCS#12 input file (private key and certificate only)

passphrase = 'passphrase_example' # String | Passphrase to unlock the pkcs#12 bundle

token = 'token_example' # String | Access token

opts = { 
  metadata: 'metadata_example', # String | A metadata about the key
  split_level: 'split_level_example', # String | The number of fragments that the item will be split into
  customer_frg_id: 'customer_frg_id_example', # String | The customer fragment ID that will be used to split the key (if empty, the key will be created independently of a customer fragment)
  cert: 'cert_example' # String | Path to a file that contain the certificate in a PEM format. If this parameter is not empty, the certificate will be taken from here and not from the PKCS#12 input file
}

begin
  #Upload a PKCS#12 key and certificates
  result = api_instance.upload_pkcs12(name, _in, passphrase, token, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->upload_pkcs12: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Name of key to be created | 
 **_in** | **String**| PKCS#12 input file (private key and certificate only) | 
 **passphrase** | **String**| Passphrase to unlock the pkcs#12 bundle | 
 **token** | **String**| Access token | 
 **metadata** | **String**| A metadata about the key | [optional] 
 **split_level** | **String**| The number of fragments that the item will be split into | [optional] 
 **customer_frg_id** | **String**| The customer fragment ID that will be used to split the key (if empty, the key will be created independently of a customer fragment) | [optional] 
 **cert** | **String**| Path to a file that contain the certificate in a PEM format. If this parameter is not empty, the certificate will be taken from here and not from the PKCS#12 input file | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **upload_rsa**
> ReplyObj upload_rsa(name, alg, rsa_key_file_path, token, opts)

Upload RSA key

Upload RSA key Options:   name -    Name of key to be created   alg -    Key type. options- [RSA1024, RSA2048]   rsa-key-file-path -    RSA private key file path   cert -    Path to a file that contain the certificate in a PEM format.   metadata -    A metadata about the key   split-level -    The number of fragments that the item will be split into   customer-frg-id -    The customer fragment ID that will be used to split the key (if empty, the key will be created independently of a customer fragment)   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

name = 'name_example' # String | Name of key to be created

alg = 'alg_example' # String | Key type. options- [RSA1024, RSA2048]

rsa_key_file_path = 'rsa_key_file_path_example' # String | RSA private key file path

token = 'token_example' # String | Access token

opts = { 
  cert: 'cert_example', # String | Path to a file that contain the certificate in a PEM format.
  metadata: 'metadata_example', # String | A metadata about the key
  split_level: 'split_level_example', # String | The number of fragments that the item will be split into
  customer_frg_id: 'customer_frg_id_example' # String | The customer fragment ID that will be used to split the key (if empty, the key will be created independently of a customer fragment)
}

begin
  #Upload RSA key
  result = api_instance.upload_rsa(name, alg, rsa_key_file_path, token, opts)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->upload_rsa: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **String**| Name of key to be created | 
 **alg** | **String**| Key type. options- [RSA1024, RSA2048] | 
 **rsa_key_file_path** | **String**| RSA private key file path | 
 **token** | **String**| Access token | 
 **cert** | **String**| Path to a file that contain the certificate in a PEM format. | [optional] 
 **metadata** | **String**| A metadata about the key | [optional] 
 **split_level** | **String**| The number of fragments that the item will be split into | [optional] 
 **customer_frg_id** | **String**| The customer fragment ID that will be used to split the key (if empty, the key will be created independently of a customer fragment) | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



# **verify_pkcs1**
> ReplyObj verify_pkcs1(key_name, message, signature, token)

Verifies an RSA PKCS#1 v1.5 signature

Verifies an RSA PKCS#1 v1.5 signature Options:   key-name -    The name of the RSA key to use in the verification process   message -    The message to be verified   signature -    The message's signature   token -    Access token

### Example
```ruby
# load the gem
require 'swagger_client'

api_instance = SwaggerClient::DefaultApi.new

key_name = 'key_name_example' # String | The name of the RSA key to use in the verification process

message = 'message_example' # String | The message to be verified

signature = 'signature_example' # String | The message's signature

token = 'token_example' # String | Access token


begin
  #Verifies an RSA PKCS#1 v1.5 signature
  result = api_instance.verify_pkcs1(key_name, message, signature, token)
  p result
rescue SwaggerClient::ApiError => e
  puts "Exception when calling DefaultApi->verify_pkcs1: #{e}"
end
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **key_name** | **String**| The name of the RSA key to use in the verification process | 
 **message** | **String**| The message to be verified | 
 **signature** | **String**| The message&#39;s signature | 
 **token** | **String**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json



