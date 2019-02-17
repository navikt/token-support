package no.nav.security.oidc.jaxrs;

import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.servlet.ServletProperties;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.embedded.jetty.JettyServletWebServerFactory;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.boot.web.servlet.server.ServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.web.context.request.RequestContextListener;

import no.nav.security.oidc.config.MultiIssuerProperties;
import no.nav.security.oidc.configuration.MultiIssuerConfiguration;
import no.nav.security.oidc.configuration.OIDCResourceRetriever;
import no.nav.security.oidc.filter.OIDCTokenValidationFilter;
import no.nav.security.oidc.jaxrs.rest.ProtectedClassResource;
import no.nav.security.oidc.jaxrs.rest.ProtectedMethodResource;
import no.nav.security.oidc.jaxrs.rest.ProtectedWithClaimsClassResource;
import no.nav.security.oidc.jaxrs.rest.TokenResource;
import no.nav.security.oidc.jaxrs.rest.UnprotectedClassResource;
import no.nav.security.oidc.jaxrs.rest.WithoutAnnotationsResource;
import no.nav.security.oidc.jaxrs.servlet.JaxrsOIDCTokenValidationFilter;
import no.nav.security.oidc.test.support.FileResourceRetriever;
import no.nav.security.oidc.test.support.jersey.TestTokenGeneratorResource;

@SpringBootConfiguration
@EnableConfigurationProperties(MultiIssuerProperties.class)
public class Config {

    @Bean
    ServletWebServerFactory servletWebServerFactory() {
        return new JettyServletWebServerFactory(0);
    }

    @Bean
    ServletRegistrationBean<?> jerseyServletRegistration() {

        ServletRegistrationBean<?> jerseyServletRegistration = new ServletRegistrationBean<>(new ServletContainer());

        jerseyServletRegistration.addInitParameter(ServletProperties.JAXRS_APPLICATION_CLASS,
                RestConfiguration.class.getName());

        return jerseyServletRegistration;
    }

    @Bean
    public FilterRegistrationBean<OIDCTokenValidationFilter> oidcTokenValidationFilterBean(
            MultiIssuerConfiguration config) {
        return new FilterRegistrationBean<>(new JaxrsOIDCTokenValidationFilter(config));
    }

    @Bean
    public MultiIssuerConfiguration multiIssuerConfiguration(MultiIssuerProperties issuerProperties) {
        return new MultiIssuerConfiguration(issuerProperties.getIssuer(),
                new FileResourceRetriever("/metadata.json", "/jwkset.json"));
    }

    @Bean
    public RequestContextListener requestContextListener() {
        return new RequestContextListener();
    }

    @Bean
    public OIDCResourceRetriever oidcResourceRetriever() {
        return new OIDCResourceRetriever();
    }

    public static class RestConfiguration extends ResourceConfig {

        public RestConfiguration() {

            register(OidcContainerRequestFilter.class);

            register(TokenResource.class);
            register(ProtectedClassResource.class);
            register(ProtectedMethodResource.class);
            register(ProtectedWithClaimsClassResource.class);
            register(UnprotectedClassResource.class);
            register(WithoutAnnotationsResource.class);

            register(TestTokenGeneratorResource.class);
        }

    }

}
