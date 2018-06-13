package no.nav.security.oidc.jaxrs;

import no.nav.security.oidc.config.MultiIssuerProperties;
import no.nav.security.oidc.configuration.MultiIssuerConfiguraton;
import no.nav.security.oidc.configuration.OIDCResourceRetriever;
import no.nav.security.oidc.filter.OIDCTokenValidationFilter;
import no.nav.security.oidc.jaxrs.rest.*;
import no.nav.security.oidc.jaxrs.servlet.JaxrsOIDCTokenValidationFilter;
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

@SpringBootConfiguration
@EnableConfigurationProperties(MultiIssuerProperties.class)
public class Config {

    @Bean
    ServletWebServerFactory servletWebServerFactory() {
        return new JettyServletWebServerFactory();
    }

    @Bean
    ServletRegistrationBean<?> jerseyServletRegistration() {

        ServletRegistrationBean<?> jerseyServletRegistration = new ServletRegistrationBean<>(new ServletContainer());

        jerseyServletRegistration.addInitParameter(ServletProperties.JAXRS_APPLICATION_CLASS, RestConfiguration.class.getName());

        return jerseyServletRegistration;
    }

    @Bean
    public FilterRegistrationBean<OIDCTokenValidationFilter> oidcTokenValidationFilterBean(MultiIssuerConfiguraton config) {
        return new FilterRegistrationBean<>(new JaxrsOIDCTokenValidationFilter(config));
    }

    @Bean
    public MultiIssuerConfiguraton multiIssuerConfiguration(MultiIssuerProperties issuerProperties, OIDCResourceRetriever resourceRetriever) {
        return new MultiIssuerConfiguraton(issuerProperties.getIssuer(), resourceRetriever);
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

        }

    }


}
