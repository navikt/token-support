# token-validation-spring-test

Contains Spring auto-configuration for setting up a [mock-oauth2-server](https://github.com/navikt/mock-oauth2-server).

The mock-oauth2-server can be used to represent as many issuers as you'd like supporting OpenID Connect/OAuth 2.0 discovery 
with valid JWKS uris, and should work nicely together with the validation from [token-validation-spring](../token-validation-spring)

## Configuration for local setup

- Add as dependency with **test** scope

- Simply add the annotation `@EnableMockOAuth2Server` to your test configuration:

  ```java
  @EnableMockOAuth2Server	
  ```

- For usage with token-validation-spring set the following properties in your local profile:
  
  `no.nav.security.jwt.issuer.issuer1.discoveryurl=http://localhost:${mock-oauth2-server.port}/issuer1/.well-known/openid-configuration`
  
  `no.nav.security.jwt.issuer.issuer1.acceptedaudience=someaudience`
  
  `no.nav.security.jwt.issuer.issuer1.cookiename=localhost-idtoken`

- For local use of your app there should now be RestController available in your app at <app-contextroot>**/local**

    - providing the following endpoint: **/cookie** with query params as defined in: [MockLoginController.java](src/main/kotlin/no/nav/security/token/support/spring/test/MockLoginController.java)
      
      The query param `issuerId` must match the path after port in the `discoveryurl` - e.g. `issuer1` in `http://localhost:${mock-oauth2-server.port}/issuer1/.well-known/openid-configuration`  

## How to use 

See [token-validation-spring-demo](../token-validation-spring-demo) for usage scenarios when starting your app locally.
* Point your browser to `http://localhost:[app-port]/[app-contextroot]/local/cookie?redirect=/[app-contextroot]/api` in order to get a token and redirect to your api.

For **JUnit** tests, your Spring application context should contain a bean of the type `MockOAuth2Server` which can be used to issue tokens and provides a JWKS endpoint for validation.
* Usage: [DemoControllerTest.java](../token-validation-spring-demo/src/test/java/no/nav/security/token/support/demo/spring/rest/DemoControllerTest.java)
* For detailed usage and features see the [mock-oauth2-server](https://github.com/navikt/mock-oauth2-server) documentation.