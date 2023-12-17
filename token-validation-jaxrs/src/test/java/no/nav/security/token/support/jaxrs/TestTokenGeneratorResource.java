package no.nav.security.token.support.jaxrs;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;
import no.nav.security.token.support.core.api.Unprotected;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.Charset;
import java.util.Objects;

@Path("local")
public class TestTokenGeneratorResource {

    @Unprotected
    @GET
    public TokenEndpoint[] endpoints(@Context HttpServletRequest request) {
        String base = request.getRequestURL().toString();
        return new TokenEndpoint[]{
            new TokenEndpoint("Get JWT as serialized string", base + "/jwt", "subject"),
            new TokenEndpoint("Get JWT as SignedJWT object with claims", base + "/claims", "subject"),
            new TokenEndpoint("Add JWT as a cookie, (optional) redirect to secured uri", base + "/cookie", "subject", "redirect", "cookiename"),
            new TokenEndpoint("Get JWKS used to sign token", base + "/jwks"),
            new TokenEndpoint("Get JWKS used to sign token as JWKSet object", base + "/jwkset"),
            new TokenEndpoint("Get token issuer metadata (ref oidc .well-known)", base + "/metadata")};
    }

    @Unprotected
    @Path("/jwt")
    @GET
    public String issueToken(
        @QueryParam("subject") @DefaultValue("12345678910") String subject) {
        return JwtTokenGenerator.createSignedJWT(subject).serialize();
    }

    @Unprotected
    @Path("/claims")
    @GET
    public SignedJWT jwtClaims(
        @QueryParam("subject") @DefaultValue("12345678910") String subject) {
        return JwtTokenGenerator.createSignedJWT(subject);
    }

    @Unprotected
    @Path("cookie")
    @GET
    public Response addCookie(
        @QueryParam("subject") @DefaultValue("12345678910") String subject,
        @QueryParam("cookiename") @DefaultValue("localhost-idtoken") String cookieName,
        @QueryParam("redirect") String redirect,
        @Context HttpServletResponse response) throws IOException {

        SignedJWT token = JwtTokenGenerator.createSignedJWT(subject);
        return Response.status(redirect == null ? Response.Status.OK : Response.Status.FOUND)
            .location(redirect == null ? null : URI.create(redirect))
            .cookie(new NewCookie.Builder(cookieName).value(token.serialize()).path("/").domain("localhost").maxAge(-1).secure(false).build())
            .build();
    }

    @Unprotected
    @GET
    @Path("/jwks")
    public String jwks() throws IOException {
        return IOUtils.readInputStreamToString(
                Objects.requireNonNull(getClass().getResourceAsStream(JwkGenerator.DEFAULT_JWKSET_FILE)),
            Charset.defaultCharset());
    }

    @Unprotected
    @GET
    @Path("jwkset")
    public JWKSet jwkSet() {
        return JwkGenerator.getJWKSet();
    }

    @Unprotected
    @GET
    @Path("/metadata")
    public String metadata() throws IOException {
        return IOUtils.readInputStreamToString(Objects.requireNonNull(getClass().getResourceAsStream("/metadata.json")),
            Charset.defaultCharset());
    }



    private static class TokenEndpoint {
        final String desc;
        final String uri;
        final String[] params;

        private TokenEndpoint(String desc, String uri, String... params) {
            this.desc = desc;
            this.uri = uri;
            this.params = params;

        }

        public String getDesc() {
            return desc;
        }

        public String getUri() {
            return uri;
        }

        public String[] getParams() {
            return params;
        }
    }
}