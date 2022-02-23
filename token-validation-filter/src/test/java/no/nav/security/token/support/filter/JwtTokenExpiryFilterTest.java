package no.nav.security.token.support.filter;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import no.nav.security.token.support.core.JwtTokenConstants;
import no.nav.security.token.support.core.context.TokenValidationContext;
import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import no.nav.security.token.support.core.jwt.JwtTokenClaims;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Collections;
import java.util.Date;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class JwtTokenExpiryFilterTest {

    @Mock
    private HttpServletRequest servletRequest;
    @Mock
    private FilterChain filterChain;
    @Mock
    private HttpServletResponse servletResponse;
    private TokenValidationContextHolder tokenValidationContextHolder;
    private static final long EXPIRY_THRESHOLD = 1;

    @Test
    public void tokenExpiresBeforeThreshold() throws IOException, ServletException {
        setupMocks(LocalDateTime.now().plusMinutes(2));

        JwtTokenExpiryFilter jwtTokenExpiryFilter = new JwtTokenExpiryFilter(tokenValidationContextHolder,
            EXPIRY_THRESHOLD);
        jwtTokenExpiryFilter.doFilter(servletRequest, servletResponse, filterChain);
        verify(servletResponse).setHeader(JwtTokenConstants.TOKEN_EXPIRES_SOON_HEADER, "true");
    }

    @Test
    public void tokenExpiresAfterThreshold() throws IOException, ServletException {
        setupMocks(LocalDateTime.now().plusMinutes(3));

        JwtTokenExpiryFilter jwtTokenExpiryFilter = new JwtTokenExpiryFilter(tokenValidationContextHolder,
            EXPIRY_THRESHOLD);
        jwtTokenExpiryFilter.doFilter(servletRequest, servletResponse, filterChain);
        verify(servletResponse, never()).setHeader(JwtTokenConstants.TOKEN_EXPIRES_SOON_HEADER, "true");
    }

    @Test
    public void noValidToken() throws IOException, ServletException {
        JwtTokenExpiryFilter jwtTokenExpiryFilter = new JwtTokenExpiryFilter(mock(TokenValidationContextHolder.class),
            EXPIRY_THRESHOLD);
        jwtTokenExpiryFilter.doFilter(servletRequest, servletResponse, filterChain);
    }

    private void setupMocks(LocalDateTime expiry) {
        tokenValidationContextHolder = mock(TokenValidationContextHolder.class);
        TokenValidationContext tokenValidationContext = mock(TokenValidationContext.class);
        when(tokenValidationContextHolder.getTokenValidationContext()).thenReturn(tokenValidationContext);
        when(tokenValidationContext.getIssuers()).thenReturn(Collections.singletonList("issuer1"));

        Date expiryDate = Date.from(expiry.atZone(ZoneId.systemDefault())
            .toInstant());
        when(tokenValidationContext.getClaims(anyString())).thenReturn(createOIDCClaims(expiryDate));
    }

    private static JwtTokenClaims createOIDCClaims(Date expiry) {
        try {
            JWT jwt = new PlainJWT(new JWTClaimsSet.Builder()
                .subject("subject")
                .issuer("http//issuer1")
                .expirationTime(expiry).build());
            return new JwtTokenClaims(jwt.getJWTClaimsSet());
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

}
