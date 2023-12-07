package no.nav.security.token.support.jaxrs;

import no.nav.security.token.support.core.configuration.IssuerProperties;
import no.nav.security.token.support.core.configuration.MultiIssuerConfiguration;
import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever;
import no.nav.security.token.support.filter.JwtTokenValidationFilter;
import no.nav.security.token.support.jaxrs.rest.*;
import no.nav.security.token.support.jaxrs.servlet.JaxrsJwtTokenValidationFilter;
import no.nav.security.token.support.spring.MultiIssuerProperties;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.servlet.ServletProperties;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.boot.web.servlet.server.ServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.web.context.request.RequestContextListener;

import java.util.Map;

@SpringBootConfiguration
@EnableConfigurationProperties(MultiIssuerProperties.class)
public class Config {

    @Bean
    ServletWebServerFactory servletWebServerFactory() {
        return new TomcatServletWebServerFactory(0);
    }

    @Bean
    ServletRegistrationBean<?> jerseyServletRegistration() {

        ServletRegistrationBean<?> jerseyServletRegistration = new ServletRegistrationBean<>(new ServletContainer());

        jerseyServletRegistration.addInitParameter(ServletProperties.JAXRS_APPLICATION_CLASS,
                RestConfiguration.class.getName());

        return jerseyServletRegistration;
    }

    @Bean
    public FilterRegistrationBean<JwtTokenValidationFilter> oidcTokenValidationFilterBean(
            MultiIssuerConfiguration config) {
        return new FilterRegistrationBean<>(new JaxrsJwtTokenValidationFilter(config));
    }

    @ConfigurationProperties("no.nav.security.jwt")
    private static  class MultiIssuerProperties {
         private final Map<String, IssuerProperties> issuer;

         public MultiIssuerProperties(Map<String, IssuerProperties> issuer) {
             this.issuer = issuer;

         }
         public Map<String, IssuerProperties> getIssuer() {
             return issuer;
         }
     }

     @Bean
     public MultiIssuerProperties multiIssuerProperties(Map<String, IssuerProperties> properties) {
         return new MultiIssuerProperties(properties);
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
    public
    ProxyAwareResourceRetriever oidcResourceRetriever() {
        return new ProxyAwareResourceRetriever();
    }

    public static class RestConfiguration extends ResourceConfig {

        public RestConfiguration() {

            register(JwtTokenContainerRequestFilter.class);

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