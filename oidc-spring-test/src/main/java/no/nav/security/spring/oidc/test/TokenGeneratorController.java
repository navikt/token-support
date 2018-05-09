package no.nav.security.spring.oidc.test;

import java.io.IOException;
import java.nio.charset.Charset;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jwt.SignedJWT;

import no.nav.security.spring.oidc.validation.api.Unprotected;

@RestController
@RequestMapping("/local")
public class TokenGeneratorController {
	
	@Unprotected
	@GetMapping()
	public TokenEndpoint[] endpoints(HttpServletRequest request){
		String base = request.getRequestURL().toString();
		return new TokenEndpoint[]{	new TokenEndpoint("Get JWT as serialized string", base + "/jwt","subject"),
									new TokenEndpoint("Get JWT as SignedJWT object with claims", base + "/claims","subject"),
									new TokenEndpoint("Add JWT as a cookie, (optional) redirect to secured uri", base + "/cookie", "subject", "redirect", "cookiename"),
									new TokenEndpoint("Get JWKS used to sign token", base + "/jwks"),
									new TokenEndpoint("Get JWKS used to sign token as JWKSet object", base + "/jwkset"),
									new TokenEndpoint("Get token issuer metadata (ref oidc .well-known)", base + "/metadata")};
	}
	
    @Unprotected
    @GetMapping("/jwt")
    public String issueToken(@RequestParam(value = "subject", defaultValue = "12345678910") String subject) {
        return JwtTokenGenerator.createSignedJWT(subject).serialize();
    }

    @Unprotected
    @GetMapping("/claims")
    public SignedJWT jwtClaims(@RequestParam(value = "subject", defaultValue = "12345678910") String subject) {
        return JwtTokenGenerator.createSignedJWT(subject);
    }

    @Unprotected
    @GetMapping("/cookie")
    public Cookie addCookie(@RequestParam(value = "subject", defaultValue = "12345678910") String subject,
            @RequestParam(value = "cookiename", defaultValue = "localhost-idtoken") String cookieName,
            @RequestParam(value = "redirect", required = false) String redirect,
            HttpServletRequest request, HttpServletResponse response) throws IOException {

        SignedJWT token = JwtTokenGenerator.createSignedJWT(subject);
        Cookie cookie = new Cookie(cookieName, token.serialize());
        cookie.setDomain("localhost");
        cookie.setPath("/");
        response.addCookie(cookie);
        if (redirect != null) {
            response.sendRedirect(redirect);
            return null;
        }
        return cookie;
    }

    @Unprotected
    @GetMapping("/jwks")
    public String jwks() throws IOException {
        return IOUtils.readInputStreamToString(getClass().getResourceAsStream(JwkGenerator.DEFAULT_JWKSET_FILE),
                Charset.defaultCharset());
    }

    @Unprotected
    @GetMapping("/jwkset")
    public JWKSet jwkSet() {
        return JwkGenerator.getJWKSet();
    }
    
    @Unprotected
    @GetMapping("/metadata")
    public String metadata() throws IOException {
        return IOUtils.readInputStreamToString(getClass().getResourceAsStream("/metadata.json"),
                Charset.defaultCharset());
    }
    
    class TokenEndpoint {
    	String desc;
    	String uri;
    	String[] params;
		public TokenEndpoint(String desc, String uri, String... params) {
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
