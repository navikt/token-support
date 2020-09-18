# token-validation-test-support

:warning: | Deprecated in favour of [token-validation-spring-test](../token-validation-spring-test)
:---: | :---

Contains config for setting up a local signed JWT token generator (can also be used as a static class) which can be used to simulate the ID token received via OpenID Connect (OIDC). The module also contains config to stub OIDC metadata (OIDC Discovery) and JWKS uri for keys used to sign the token, which should work nicely together with the validation in oidc-spring-support.

## Configuration for local setup

- Add as dependency with **test** scope

- Import TokenGeneratorConfiguration in your test configuration:

  ```java
  @Import(TokenGeneratorConfiguration.class)	
  ```

- If your code uses oidc-spring-support for token validation set the following properties in your local profile:

  **Please make sure to never use the local mode properties in any other environment than your local development environment as the private keys to sign the token provided by oidc-spring-test is fully available here on github for all to see and use.**

  
  `no.nav.security.jwt.issuer.[your issuer name].discoveryurl=http://metadata`
  
  `no.nav.security.jwt.issuer.[your issuer name].acceptedaudience=aud-localhost`
  
  `no.nav.security.jwt.issuer.[your issuer name].cookiename=localhost-idtoken`

- There should now be RestController available in your app at <app-contextroot>**/local**

  - Accessing the controller at root you should see list of supported endpoints, some of these listed below:

    - **/jwt** with optional query param subject: 

      Returns a signed jwt in its serialized format

    - **/cookie** with optional query param subject, redirect and cookiename: 

      Sets the token as a cookie and redirect to where you want to use the token

    - **/claims** 

      Generates and shows the content of a token

## How to use 

Local setup for an app that requires token:

Point your browser to: http://localhost:[app-port]/[app-contextroot]/local/cookie?redirect=/[app-contextroot]/api
