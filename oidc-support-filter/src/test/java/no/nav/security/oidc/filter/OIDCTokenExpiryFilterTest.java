package no.nav.security.oidc.filter;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Collections;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;

import no.nav.security.oidc.context.OIDCClaims;
import no.nav.security.oidc.context.OIDCRequestContextHolder;
import no.nav.security.oidc.context.OIDCValidationContext;

@ExtendWith(MockitoExtension.class)
public class OIDCTokenExpiryFilterTest {

    @Mock
    private HttpServletRequest servletRequest;
    @Mock
    private FilterChain filterChain;
    @Mock
    private HttpServletResponse servletResponse;
    private OIDCRequestContextHolder oidcRequestContextHolder;
    private OIDCValidationContext oidcValidationContext;
    private static final long EXPIRY_THRESHOLD = 1;

    @Test
    public void tokenExpiresBeforeThreshold() throws IOException, ServletException {
        setupMocks(LocalDateTime.now().plusMinutes(2));

        OIDCTokenExpiryFilter oidcTokenExpiryFilter = new OIDCTokenExpiryFilter(oidcRequestContextHolder,
                EXPIRY_THRESHOLD);
        oidcTokenExpiryFilter.doFilter(servletRequest, servletResponse, filterChain);
        verify(servletResponse).setHeader(OIDCTokenExpiryFilter.TOKEN_EXPIRES_SOON_HEADER, "true");
    }

    @Test
    public void tokenExpiresAfterThreshold() throws IOException, ServletException {
        setupMocks(LocalDateTime.now().plusMinutes(3));

        OIDCTokenExpiryFilter oidcTokenExpiryFilter = new OIDCTokenExpiryFilter(oidcRequestContextHolder,
                EXPIRY_THRESHOLD);
        oidcTokenExpiryFilter.doFilter(servletRequest, servletResponse, filterChain);
        verify(servletResponse, never()).setHeader(OIDCTokenExpiryFilter.TOKEN_EXPIRES_SOON_HEADER, "true");
    }

    @Test
    public void noValidToken() throws IOException, ServletException {
        OIDCTokenExpiryFilter oidcTokenExpiryFilter = new OIDCTokenExpiryFilter(mock(OIDCRequestContextHolder.class),
                EXPIRY_THRESHOLD);
        oidcTokenExpiryFilter.doFilter(servletRequest, servletResponse, filterChain);
    }

    private void setupMocks(LocalDateTime expiry) {
        oidcRequestContextHolder = mock(OIDCRequestContextHolder.class);
        oidcValidationContext = mock(OIDCValidationContext.class);
        when(oidcRequestContextHolder.getOIDCValidationContext()).thenReturn(oidcValidationContext);
        when(oidcValidationContext.getIssuers()).thenReturn(Collections.singletonList("issuer1"));

        Date expiryDate = Date.from(expiry.atZone(ZoneId.systemDefault())
                .toInstant());
        when(oidcValidationContext.getClaims(anyString())).thenReturn(createOIDCClaims(expiryDate));
    }

    private static OIDCClaims createOIDCClaims(Date expiry) {
        JWT jwt = new PlainJWT(new JWTClaimsSet.Builder()
                .subject("subject")
                .issuer("http//issuer1")
                .expirationTime(expiry).build());
        OIDCClaims claims = new OIDCClaims(jwt);
        return claims;
    }

}