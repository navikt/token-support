package no.nav.security.token.support.test.jersey;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jwt.SignedJWT;
import no.nav.security.token.support.core.api.Unprotected;
import no.nav.security.token.support.test.JwkGenerator;
import no.nav.security.token.support.test.JwtTokenGenerator;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.Charset;

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
                .cookie(new NewCookie(cookieName, token.serialize(), "/", "localhost", "", -1, false))
                .build();
    }

    @Unprotected
    @GET
    @Path("/jwks")
    public String jwks() throws IOException {
        return IOUtils.readInputStreamToString(
                getClass().getResourceAsStream(JwkGenerator.DEFAULT_JWKSET_FILE),
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
        return IOUtils.readInputStreamToString(getClass().getResourceAsStream("/metadata.json"),
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
