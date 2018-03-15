# token-support (WORK IN PROGRESS)
This project consist of common modules to support security token handling in a java spring microservices architecture, with emphasis on OpenID Connect ID Tokens. The source code is based on the output from a Proof-of-concept with Azure AD B2C - found here https://github.com/navikt/AzureAdPoc - many thanks to the original author.

Applications can use these modules in order to be able to verify tokens on exposed HTTP endpoints, according to the configured OIDC providers they trust. Multiple providers are allowed, and various validation rules for various OIDC providers can be applied to rest controllers at the method level. Tokens will be transported through the service, and will be attached to the client request as "Bearer" token when calling another service/api. 

## Main components

### oidc-support

Provides token validation support through servlet filters, using the [Nimbus OAuth 2.0 SDK with OpenID Connect extensions](https://connect2id.com/products/nimbus-oauth-openid-connect-sdk). Please see **`no.nav.security.oidc.filter.OIDCTokenValidationFilter.java`** for more details. Token signing keys are cached in a single-ton instance of the **`no.nav.security.oidc.validation.OIDCTokenValidator`**, using the  **`com.nimbusds.openid.connect.sdk.validators.IDTokenValidator`**. Token signing keys are fetched from the jwt_keys endpoint configured in the OIDC provider configuration meta data endpoint when required (e.g. new signing keys are detected). This module can be used standalone if you do not use Spring, if you are using spring you can use the module described below.

### oidc-spring-support

Spring Boot specific wrapper around the oidc-support library above. To enable the oidc token validation for a spring boot application, simply annotate your SpringApplication with **`@EnableOIDCTokenValidation`**. Optionally list the packages or classses you dont want token validations for (e.g. error controllers). A good start is listing the **`org.springframework`** - e.g. **`@EnableOIDCTokenValidation(ignore="org.springframework")`**. Use the **`@Unprotected`** or **`@Protected`** annotation at rest controller method level to indicate if token is required or not for your method. The Protected annotation can also have the issuer name specified. This will require a token from that specific issuer - e.g. **`@Protected(issuer="selbetjening")`**

#### SpringApplication sample

This annotation will enable token validation and token transportation/propagation through the service

```java
package io.ztpoc.product.service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import io.ztpoc.spring.oidc.validation.api.EnableOIDCTokenValidation;

@SpringBootApplication(scanBasePackages="io.ztpoc")
@EnableOIDCTokenValidation(ignore="org.springframework")
public class ProductServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(ProductServiceApplication.class, args);
	}
}

```

#### Rest controller sample

This example shows

- First method - An unprotected endpoint. No token is required to use this endpoint.
- Second method - A protected endpoint. This endpoint will require a valid token from the "employee" issuer. 
- Third method - A protected endpoint. This endpoint will require a valid token from one of the configured issuers.
- Fourth method - A non-annotated endpoint. This endpoint will not be accessible from outside the server (will return a 501 NOT_IMPLEMENTED). 
- Fifth method - A protected endpoint. This endpoint will require a valid token from one of the configured issuers. If no valid token is found, a 302 redirect to the configured url of "loginurlemployee" will be returned. This is typical scenario for ui application, or for a redirect aware SPA application using this API

```java
@RestController
public class ProductController {
	
	@Autowired
	ProductService productService;
	
	@Unprotected
	@RequestMapping(value = "/product/{id}", method = RequestMethod.GET)
	public Product read(@PathVariable("id") String id) {
		return productService.read(id);
	}
	
	@Protected(issuer="employee")
	@RequestMapping(value = "/product", method = RequestMethod.POST)
	public Product create(@RequestBody Product product) {		
		return productService.create(product);
	}

	@Protected
	@RequestMapping(value = "/product/sample", method = RequestMethod.GET)
	public Product sample() {
		Product product = Product.sample();
		product.setId(UUID.randomUUID().toString());
		return product;
	}

	@Protected(issuer="employee", redirectEnvKey="loginurlemployee")
	@RequestMapping(value = "/productui", method = RequestMethod.POST)
	public Product create(@RequestBody Product product) {		
		return productService.create(product);
	}

	@RequestMapping(value = "/product/{id}/variant", method = RequestMethod.GET)
	public Variant readVariant(@PathVariable("id") String id) {
		return productService.readVariant(id);
	}

}
```



## Configuration

Add the modules as Maven dependencies.

With Spring:

```xml
   <dependency>     
        <groupId>no.nav.security</groupId>
        <artifactId>oidc-spring-support</artifactId>
        <version>${oidc-spring-support.version}</version>
    </dependency>
```
Without Spring: Add only the oidc-support artifact.

If using Spring the modules will be autoconfigured in the applicationcontext.

The following properties must be defined in the environment where your application run, or you can adjust the application.properties files. The same properties can be configured in your environment. Replace all **`dots`** with under score, e.g. **`server.port`** can also be specified in an environment using **`server_port`**. This is valid for all configuration/properties. 

### Properties

- **`no.nav.security.oidc.issuers`** - a comma separated list of issuers names (not the actual issuer value from the OIDC token, but a chosen name to represent config for the actual OIDC issuer) you trust, e.g. **`citizen,employee`**
- **`no.nav.security.oidc.issuer.[issuer name].uri`** - The OIDC provider configuration endpoint (meta-data)
- **`no.nav.security.oidc.issuer.[issuer name].accepted_audience`** - The value of the audience (aud) claim in the ID token. For OIDC it is the client ID of the client responsible for aquiring the token.

## Proxy support

Request to external endpoints (i.e. your OpenID Connect provider) can be configured to use a proxy server. By default, the servers tries to read the property/environment value **`http.proxy`** or **`http_proxy`**. The value must be a valid URL, containing protocol, hostname and port - e.g. **`http://myproxy:8080`**. If no proxy configuration is specified, all communication to external services (internet bound), will be achieved without proxy (direct communication). If the **`http.proxy`** parameter name does not fit your environment (e.g. you want a common name for proxy config for all servers other than **`http.proxy`**, you can specify your own parameter name by configuring the **`http.proxy.parametername`**, or **`http_proxy_parametername`**. Example: **`http_proxy_parametername=http_proxy_uri`**. 

## Running inside an Istio enabled Kubernetes cluster

When running inside an [Istio](https://istio.io) enabled Kubernetes cluster, outbound SSL connections are required to go through the PODs Envoy proxy sitting in front of the application. The way [Istio recommends doing this](https://istio.io/docs/tasks/traffic-management/egress.html), is by translating all https://hostname/path requests to http://hostname:443/path, and let the request be routed through the Envoy proxy. The Envoy proxy will establish the SSL connection to the request host. From a security point of view, the POD it self is considered the trusted security context for the application in an Istio enabled cluster. To enable this for all outgoing SSL communication,  **`https.plaintext`** must be set to **`true`**. This means that all communication using the SpringHttpClient will be translated to a plaintext request on port 443. For applications using the spring-oidc-support libraries, this means that all request to OIDC provider metadata endpoints, OIDC provider token endpoints and the OIDC token signing keys retrieval endpoints will be handled this way. 
