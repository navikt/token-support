package no.nav.security.token.support.jaxrs

import com.nimbusds.jose.util.IOUtils.readInputStreamToString
import jakarta.servlet.http.HttpServletRequest
import jakarta.ws.rs.DefaultValue
import jakarta.ws.rs.GET
import jakarta.ws.rs.Path
import jakarta.ws.rs.QueryParam
import jakarta.ws.rs.core.Context
import jakarta.ws.rs.core.NewCookie.Builder
import jakarta.ws.rs.core.Response
import jakarta.ws.rs.core.Response.Status.FOUND
import jakarta.ws.rs.core.Response.Status.OK
import java.net.URI
import java.nio.charset.Charset.defaultCharset
import java.util.Objects.requireNonNull
import no.nav.security.token.support.core.api.Unprotected
import no.nav.security.token.support.jaxrs.JwkGenerator.DEFAULT_JWKSET_FILE
import no.nav.security.token.support.jaxrs.JwkGenerator.jWKSet
import no.nav.security.token.support.jaxrs.JwtTokenGenerator.createSignedJWT

@Path("local")
class TestTokenGeneratorResource {

    @Unprotected
    @GET
    fun endpoints(@Context request: HttpServletRequest) = arrayOf(
        TokenEndpoint("Get JWT as serialized string", "${request.requestURL}/jwt", "subject"),
        TokenEndpoint("Get JWT as SignedJWT object with claims", "${request.requestURL}/claims", "subject"),
        TokenEndpoint("Get JWKS used to sign token", "${request.requestURL}/jwks"),
        TokenEndpoint("Get JWKS used to sign token as JWKSet object", "${request.requestURL}/jwkset"),
        TokenEndpoint("Get token issuer metadata (ref oidc .well-known)", "${request.requestURL}/metadata"))
    @Unprotected
    @Path("/jwt")
    @GET
    fun issueToken(@QueryParam("subject") @DefaultValue("12345678910") subject : String?) = createSignedJWT(subject).serialize()

    @Unprotected
    @Path("/claims")
    @GET
    fun jwtClaims(@QueryParam("subject") @DefaultValue("12345678910") subject : String?) = createSignedJWT(subject)

    @Unprotected
    @GET
    @Path("/jwks")
    fun jwks() = readInputStreamToString(requireNonNull(javaClass.getResourceAsStream(DEFAULT_JWKSET_FILE)), defaultCharset())

    @Unprotected
    @GET
    @Path("jwkset")
    fun jwkSet() = jWKSet

    @Unprotected
    @GET
    @Path("/metadata")
    fun metadata() = readInputStreamToString(requireNonNull(javaClass.getResourceAsStream("/metadata.json")), defaultCharset())

     class TokenEndpoint(val desc : String, val uri : String, vararg val params : String)

}