[![Build Status](https://travis-ci.org/navikt/token-support.svg?branch=master)](https://travis-ci.org/navikt/token-support)
[![Published on Maven](https://img.shields.io/maven-metadata/v/http/central.maven.org/maven2/no/nav/security/token-support/maven-metadata.xml.svg)](http://central.maven.org/maven2/no/nav/security/token-support/)

# token-support
This project consist of common modules to support security token handling in a java spring microservices architecture, with emphasis on OpenID Connect ID Tokens. The source code is based on the output from a Proof-of-concept with Azure AD B2C - found here https://github.com/navikt/AzureAdPoc - many thanks to the original author.

Applications can use these modules in order to verify security tokens on exposed HTTP endpoints, according to the configured OIDC providers they trust. Multiple providers are allowed, and can be applied to rest controllers through annotations. Tokens can be propagated through the service and attached to client requests as a "Bearer" token when calling another service/api. 

## Main components

### oidc-support

Provides token validation support through servlet filters, using the [Nimbus OAuth 2.0 SDK with OpenID Connect extensions](https://connect2id.com/products/nimbus-oauth-openid-connect-sdk). Please see **`no.nav.security.oidc.filter.OIDCTokenValidationFilter.java`** for more details. Token signing keys are cached in a singleton instance of the **`no.nav.security.oidc.validation.OIDCTokenValidator`**, using the  **`com.nimbusds.openid.connect.sdk.validators.IDTokenValidator`**. Token signing keys will be fetched from the jwt_keys endpoint configured in the OIDC provider configuration metadata endpoint when required (e.g. new signing keys are detected). This module can be used standalone (if you do not use Spring). If you do use Spring you can use the module described below, providing Spring specific mechanisms for securing rest controllers.

### oidc-spring-support

Spring Boot specific wrapper around oidc-support. To enable oidc token validation for a spring boot application, simply annotate your SpringApplication class with **`@EnableOIDCTokenValidation`**. Optionally list the packages or classses you dont want token validations for (e.g. error controllers). A good start is listing the **`org.springframework`** - e.g. **`@EnableOIDCTokenValidation(ignore="org.springframework")`**. Use the **`@Unprotected`** or **`@Protected`** annotations at rest controller method/class level to indicate if token validation is required or not. 

 

#### SpringApplication sample

This annotation will enable token validation and token transportation/propagation through the service

```java
package io.ztpoc.product.service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import io.ztpoc.spring.oidc.validation.api.EnableOIDCTokenValidation;

@SpringBootApplication
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

	@RequestMapping(value = "/product/{id}/variant", method = RequestMethod.GET)
	public Variant readVariant(@PathVariable("id") String id) {
		return productService.readVariant(id);
	}

}
```


### oidc-jersey-support

JAX-RS wrapper around oidc-support. Two steps are necessary to enable token validation:
* Register the servlet filter **`JaxrsOIDCTokenValidationFilter`** with your servlet container to pick up the token of incoming requests  
* Register the **`OidcContainerRequestFilter`** with your **`Application`** (plain JAX-RS) or **`ResourceConfig`** (Jersey) 
  
Use the **`@Unprotected`**, **`@Protected`** or **`@ProtectedWithClaims`** annotations on resource methods and/or classes indicate if token validation is required or not. Method annotations have precedence
One additional step is required to pass the token do other services

* Register **`OidcClientRequestFilter`** with your client


#### Example

Register the servlet filter with your container, as done in spring boots **`@SpringBootConfiguration`** in the snippet below. How you get hold of the configuration map of issuers is up to the implementor.

```java
    @Bean
    public FilterRegistrationBean<OIDCTokenValidationFilter> oidcTokenValidationFilterBean(MultiIssuerConfiguraton config) {
        return new FilterRegistrationBean<>(new JaxrsOIDCTokenValidationFilter(config));
    }

    @Bean
    public MultiIssuerConfiguraton multiIssuerConfiguration(Map<String, IssuerProperties> issuerConfiguration, OIDCResourceRetriever resourceRetriever) {
        return new MultiIssuerConfiguraton(issuerConfiguration, resourceRetriever);
    }

    @Bean
    public OIDCResourceRetriever oidcResourceRetriever() {
        return new OIDCResourceRetriever();
    }
```

How you configure the servlet filter is dependent on how you lauch your app, e.g. if you use spring or not, and wether you use tomcat or jetty

#### Configure jersey

There are two options, explicit registering of resources
```java
new ResourceConfig()
  .register(OidcContainerRequestFilter.class)
  // ...
  .register(Resource.class);
```
or let jersey scan for Resources and/or **`@Provider`**-annotated classes
```java
new ResourceConfig()
  .packages("no.nav.security.oidc.jaxrs", "x.y.z.resourcepackage");
```

#### Rest controller sample with method annotations

This example shows

- First method - An unprotected endpoint. No token is required to use this endpoint.
- Second method - A protected endpoint. This endpoint will require a valid token from the "employee" issuer. 
- Third method - A protected endpoint. This endpoint will require a valid token from one of the configured issuers.
- Fourth method - A non-annotated endpoint. This endpoint will not be accessible from outside the server (will return a 501 NOT_IMPLEMENTED). 

```java
@Path("/rest")
public class ProductResource {
	
    // ...
	
  @GET
  @PATH("/product/")
  @Unprotected
  public List<Product> list() {
    return service.list();
  }
	
  @POST
  @PATH("/product")
  @Protected
  public Product add(Product product) {		
    return service.create(product);
  }
	
  @DELETE
  @PATH("/product/{id}")
  @ProtectedWithClaims(issuer = "manager", claimMap = { "acr=Level4" })
  public void add(String id) {		
    return service.delete(id);   
  }

}
```



## Configuration

Add the modules that you need as Maven dependencies.
* oidc-spring-support:
```xml
   <dependency>     
        <groupId>no.nav.security</groupId>
        <artifactId>oidc-spring-support</artifactId>
        <version>${oidc-support.version}</version>
    </dependency>
```
* oidc-jersey-support:
```xml
   <dependency>     
        <groupId>no.nav.security</groupId>
        <artifactId>oidc-jersey-support</artifactId>
        <version>${oidc-support.version}</version>
    </dependency>
```
* oidc-support:
```xml
   <dependency>     
        <groupId>no.nav.security</groupId>
        <artifactId>oidc-support</artifactId>
        <version>${oidc-support.version}</version>
    </dependency>
```

### Required properties (yaml or properties)

- **`no.nav.security.oidc.issuer.[issuer shortname]`** - all properties relevant for a particular issuer must be listed under a short name for that issuer (not the actual issuer value from the OIDC token, but a chosen name to represent config for the actual OIDC issuer) you trust, e.g. **`citizen`** or **`employee`** 
- **`no.nav.security.oidc.issuer.[issuer shortname].discoveryurl`** - The OIDC provider configuration/discovery endpoint (metadata)
- **`no.nav.security.oidc.issuer.[issuer shortname].accepted_audience`** - The value of the audience (aud) claim in the ID token. For OIDC it is the client ID of the client responsible for acquiring the token.
- **`no.nav.security.oidc.issuer.[issuer shortname].cookiename`** - The value of the cookie containing the ID token (not required, only neccessary if your api receives calls from a browser)

## Proxy support

Request to external endpoints (i.e. your OpenID Connect provider) can be configured to use a proxy server. By default, the module tries to read the property/environment value **`http.proxy`** or **`http_proxy`**. The value must be a valid URL, containing protocol, hostname and port - e.g. **`http://myproxy:8080`**. If no proxy configuration is specified, all communication to external services (internet bound), will be achieved without proxy (direct communication). If the **`http.proxy`** parameter name does not fit your environment (e.g. you want a common name for proxy config for all servers other than **`http.proxy`**, you can specify your own parameter name by configuring the **`http.proxy.parametername`**, or **`http_proxy_parametername`**. Example: **`http_proxy_parametername=http_proxy_uri`**. 

## Running inside an Istio enabled Kubernetes cluster

When running inside an [Istio](https://istio.io) enabled Kubernetes cluster, outbound SSL connections are required to go through the PODs Envoy proxy sitting in front of the application. The way [Istio recommends doing this](https://istio.io/docs/tasks/traffic-management/egress.html), is by translating all https://hostname/path requests to http://hostname:443/path, and let the request be routed through the Envoy proxy. The Envoy proxy will establish the SSL connection to the request host. From a security point of view, the POD it self is considered the trusted security context for the application in an Istio enabled cluster. To enable this for all outgoing SSL communication,  **`https.plaintext`** must be set to **`true`**. This means that all communication using the OidcResourceRetriever will be translated to a plaintext request on port 443. For applications using the spring-oidc-support libraries, this means that all request to OIDC provider metadata endpoints, OIDC provider token endpoints and the OIDC token signing keys retrieval endpoints will be handled this way. 

## Running your app locally while using these modules

There is a separate module **oidc-spring-test** which you can use to generate tokens for local use. Please see separate [README](https://github.com/navikt/token-support/tree/master/oidc-spring-test) for more information. *Please make sure to never use the local mode properties in any other environment than your local development environment as the private keys to sign the token provided by oidc-spring-test is fully available here on github for all to see and use.*

## Build & Release

### NAV internal Nexus

#### Snapshot versions

Every commit to the `master` branch (or merged pull request) will trigger a
release to the NAV internal snaphot repository

#### Releases

In order to release a new version run the following job in Jenkins -https://jenkins-bris.adeo.no/job/token-support-release/

### Sonatype OSS & Maven Central (coming soon)

The repo is currently set to private so releasing to Sonatype OSS and Maven Central will not work until the repo is set to public (in order for Travis to perform the build). 

#### Snapshot versions

Every commit to the `master` branch (or merged pull request) will trigger a
release to the [Sonatype OSS snapshot repository](https://oss.sonatype.org/content/repositories/snapshots/no/nav/security/).

#### Releases

In order to release a new version (provided you have access), clone this repository, and

```bash
# make sure we're up to date!
git checkout master && git pull

# This is the release command itself
mvn -Pdeploy-to-sonatype release:prepare

# This will clean up any local temporary files
# that were used during the release.
mvn release:clean
```

The `mvn release:prepare` command will ask for a version number to release,
as well as which version number to bump to. This command will also do
a `git push` on your behalf, which will update the remote git repository.
Then, Travis CI will trigger a build, and deploy the artifact.

First, it will appear in [Sonatype OSS releases](https://oss.sonatype.org/content/repositories/releases/no/nav/security/),
before eventually (a couple of minutes later) it is synced to [Maven Central](http://central.maven.org/maven2/no/nav/security/).


## Contact

If you have any questions, please open an issue on the Github issue tracker.
For NAV employees, you can ask questions at the Slack channel #bris.
