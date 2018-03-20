package no.nav.security.spring.oidc.test;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Optional;

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
	@GetMapping("/jwt")
	public String issueToken(@RequestParam(value="subject", defaultValue = "12345678910") String subject){
		return JwtTokenGenerator.createSignedJWT(subject).serialize();
	}
	
	@Unprotected
	@GetMapping("/jwtclaims")
	public SignedJWT jwtClaims(@RequestParam(value="subject", defaultValue = "12345678910") String subject){
		return JwtTokenGenerator.createSignedJWT(subject);
	}
	
	@Unprotected
	@GetMapping("/cookie")
	public Cookie addCookie(@RequestParam(value="subject", defaultValue = "12345678910") String subject, 
							@RequestParam(value="cookiename", defaultValue = "localhost-idtoken") String cookieName, 
							@RequestParam(value="redirect", required=false) String redirect,  
							HttpServletRequest request, HttpServletResponse response) throws IOException {
		
		SignedJWT token = JwtTokenGenerator.createSignedJWT(subject);
		Cookie cookie = new Cookie(cookieName, token.serialize());
		cookie.setDomain("localhost");
		cookie.setPath("/");
		response.addCookie(cookie);
		if(redirect != null){
			response.sendRedirect(redirect);
		}
		return cookie;	
	}
	
	@Unprotected
	@GetMapping("/jwks")
	public String jwks() throws IOException{
			return IOUtils.readInputStreamToString(getClass().getResourceAsStream(JwkGenerator.DEFAULT_JWKSET_FILE), Charset.defaultCharset());
	}
	
	@Unprotected
	@GetMapping("/metadata")
	public String metadata() throws IOException{
			return IOUtils.readInputStreamToString(getClass().getResourceAsStream("/metadata.json"), Charset.defaultCharset());
	}
	
	@Unprotected
	@GetMapping("/jwksfull")
	public JWKSet jwkSet(){
		return JwkGenerator.getJWKSet();	
	}
	
}
