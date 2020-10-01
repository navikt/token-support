[![Build](https://github.com/navikt/token-support/workflows/Build%20master/badge.svg)](https://github.com/navikt/token-support/actions)
[![Known Vulnerabilities](https://snyk.io/test/github/navikt/token-support/badge.svg)](https://snyk.io/test/github/navikt/token-support)
[![Maven Central](https://img.shields.io/maven-central/v/no.nav.security/token-support?color=green&logo=Apache%20Maven)](https://search.maven.org/artifact/no.nav.security/token-support)

# token-support
This project provides several standalone modules supporting common security token handling in Java and Kotlin applications, e.g. either as an OAuth 2.0 client or a OAuth 2.0 Resource Server with JWT validation. 

The main motivation behind the project is to support **multiple** token issuers/identity providers with as much ease as possible.

The modules are roughly split in two:

* **token-client-*** (support for multiple OAuth 2.0 grants/flows as a client)
* **token-validation-*** (support for JWT token validation following best practice and OAuth 2.0 specifications)

The client and validation modules provide a core module and specific "wrapper" implementations for some well known libraries such as Spring Boot, JAX-RS and KTOR.

## Main components

This project is mainly composed of modules wrapping other well known libraries. Currently there is support for:
* Spring Boot and Spring Web MVC
* JAX-RS
* Plain Java
* Kotlin with ktor

### token-validation-core

Provides the core token validation support, using the [Nimbus OAuth 2.0 SDK with OpenID Connect extensions](https://connect2id.com/products/nimbus-oauth-openid-connect-sdk). Token signing keys are retrieved from the external issuer and cached in the **`JwtTokenValidator`**, using the  **`com.nimbusds.openid.connect.sdk.validators.IDTokenValidator`** (this validator also works well for validating access_tokens). Token signing keys will be fetched from the jwt_keys endpoint configured in the provider configuration metadata endpoint (e.g. **`/.well-known/openid-configuration`**) when required (e.g. new signing keys are detected). 

This module can be used standalone (e.g. if you do not use Spring or JAX-RS). You will however need to code the part to "hook in" enforcement and trigger the token validation (e.g. as done in the token-validation-filter module). If you use Spring, JAX-RS or Ktor you should use the specific module for your framework. 

### token-validation-filter

Simple servlet filter using the token-validation-core components for validating tokens on inbound HTTP requests. Can be used standalone but is more commonly used together with Spring or JAX-RS.  

### token-validation-spring

Spring Boot (Spring Web) specific wrapper around token-validation-core and token-validation-filter providing auto configuration of the relevant components. 
To enable token validation for a spring boot application, simply annotate your SpringApplication class or any Spring Configuration class with **`@EnableJwtTokenValidation`**. Optionally list the packages or classses you dont want token validations for (e.g. error controllers). The package **`org.springframework`** - e.g. **`@EnableJwtTokenValidation(ignore="org.springframework")`** is listed as ignored by default if you dont specify a ignore list. Use the **`@Unprotected`** or **`@Protected`**/**`@ProtectedWithClaims`** annotations at rest controller method/class level to indicate if token validation is required or not. 

There is a short sample below, however more detailed samples are available in the **`token-validation-spring-demo`** module. 

#### SpringApplication sample

This annotation will enable token validation and token transportation/propagation through the service

```java

@SpringBootApplication
@EnableJwtTokenValidation
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
class ProductController {
	
	private final ProductService productService;
  
  ProductController(ProductService productService){
    this.productService = productService;
  }
	
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

### token-validation-jaxrs

JAX-RS wrapper around token-validation-core and token-validation-filter. Two steps are necessary to enable token validation:
* Register the servlet filter **`JaxrsJwtTokenValidationFilter`** with your servlet container to pick up the token of incoming requests  
* Register the **`JwtTokenContainerRequestFilter`** with your **`Application`** (plain JAX-RS) or **`ResourceConfig`** (Jersey) 
  

Use the **`@Unprotected`**, **`@Protected`** or **`@ProtectedWithClaims`** annotations on resource methods and/or classes indicate if token validation is required or not. Method annotations have precedence
One additional step is required to pass the token do other services

* Register **`JwtTokenClientRequestFilter`** with your client

#### Example

Register the servlet filter with your container, as done in spring boots **`@SpringBootConfiguration`** in the snippet below. How you get hold of the configuration map of issuers is up to the implementor.

```java
    @Bean
    public FilterRegistrationBean<JwtTokenValidationFilter> jwtTokenValidationFilterBean(MultiIssuerConfiguraton config) {
        return new FilterRegistrationBean<>(new JaxrsJwtTokenValidationFilter(config));
    }

    @Bean
    public MultiIssuerConfiguraton multiIssuerConfiguration(Map<String, IssuerProperties> issuerConfiguration, ProxyAwareResourceRetriever resourceRetriever) {
        return new MultiIssuerConfiguraton(issuerConfiguration, resourceRetriever);
    }

    @Bean
    public ProxyAwareResourceRetriever proxyAwareResourceRetriever() {
        return new ProxyAwareResourceRetriever();
    }
```

How you configure the servlet filter depends on how you launch your app, e.g. if you use spring or not, and whether you use tomcat or jetty

#### Configure jersey

There are two options, explicit registering of resources
```java
new ResourceConfig()
  .register(JwtTokenContainerRequestFilter.class)
  // ...
  .register(Resource.class);
```
or let jersey scan for Resources and/or **`@Provider`**-annotated classes
```java
new ResourceConfig()
  .packages("no.nav.security.token.support.jaxrs", "x.y.z.resourcepackage");
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
### token-validation-ktor

See demo application in **`token-validation-ktor-demo`**.

## Configuration

Add the modules that you need as Maven dependencies.
* token-validation-spring:
```xml
   <dependency>     
        <groupId>no.nav.security</groupId>
        <artifactId>token-validation-spring</artifactId>
        <version>${token-support.version}</version>
    </dependency>
```
* token-validation-jaxrs:
```xml
   <dependency>     
        <groupId>no.nav.security</groupId>
        <artifactId>token-validation-jaxrs</artifactId>
        <version>${token-support.version}</version>
    </dependency>
```
* token-validation-ktor:
```xml
   <dependency>     
        <groupId>no.nav.security</groupId>
        <artifactId>token-validation-ktor</artifactId>
        <version>${token-support.version}</version>
    </dependency>
```
* token-validation-core (included as dependency in all of the above):
```xml
   <dependency>     
        <groupId>no.nav.security</groupId>
        <artifactId>token-validation-core</artifactId>
        <version>${token-support.version}</version>
    </dependency>
```

### Required properties (yaml or properties)

- **`no.nav.security.jwt.issuer.[issuer shortname]`** - all properties relevant for a particular issuer must be listed under a short name for that issuer (not the actual issuer value from the token, but a chosen name to represent config for the actual issuer) you trust, e.g. **`citizen`** or **`employee`** 
- **`no.nav.security.jwt.issuer.[issuer shortname].discoveryurl`** - The identity provider configuration/discovery endpoint (metadata)
- **`no.nav.security.jwt.issuer.[issuer shortname].accepted_audience`** - The value of the audience (aud) claim in the JWT token. For OIDC it is the client ID of the client responsible for acquiring the token, in OAuth 2.0 it should be the identifier for you api.
- **`no.nav.security.jwt.issuer.[issuer shortname].cookiename`** - The value of the cookie containing a ID token (not required, only necessary if your api receives calls directly from a browser)
- **`no.nav.security.jwt.issuer.[issuer shortname].validation.optional-claims`** - A comma separated list of optional claims that will be excluded from default claims.
- **`no.nav.security.jwt.issuer.[issuer shortname].jwks-cache.lifespan`** - Cache the retrieved JWK keys to speed up subsequent look-ups. A non-negative lifespan expressed in minutes. (Default 15 min)
- **`no.nav.security.jwt.issuer.[issuer shortname].jwks-cache.refreshtime`** - A non-negative refresh time expressed in minutes. (Default 5 min)

## "Corporate" proxy support per issuer
Each issuer can be configured to use or not use a proxy by specifying the following properties:
- **`no.nav.security.jwt.issuer.[issuer shortname].proxyurl`** - The full url of the proxy, e.g. http://proxyhost:8088

## Running JUnit tests or running your app locally while using these modules

There is a separate module in **token-validation-spring-test** for Spring apps, see separate [README](token-validation-spring-test/README.md) for more information. 

For apps not using Spring we recommend you use the [mock-oauth2-server](https://github.com/navikt/mock-oauth2-server) and setup your tests/properties accordingly.

## Build & Release

### Sonatype OSS & Maven Central 

#### Releases

In order to release a new version go to https://github.com/navikt/token-support/releases and click edit on the draft release. Edit or approve the changelog and click publish. Github Action will trigger a new release.

First, it will appear in [Sonatype OSS releases](https://oss.sonatype.org/content/repositories/releases/no/nav/security/),
before eventually (a couple of minutes later) it is synced to [Maven Central](http://central.maven.org/maven2/no/nav/security/).

## Contact

If you have any questions, please open an issue on the Github issue tracker.

For NAV employees, you can ask questions at the Slack channel [#token-support](https://nav-it.slack.com/archives/C01381BAT62)
