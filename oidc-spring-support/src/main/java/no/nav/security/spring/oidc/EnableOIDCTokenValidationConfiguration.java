package no.nav.security.spring.oidc;

import java.net.URL;
import java.util.EnumSet;

import javax.servlet.DispatcherType;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportAware;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.web.context.request.RequestContextListener;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import no.nav.security.oidc.configuration.MultiIssuerConfiguration;
import no.nav.security.oidc.configuration.OIDCResourceRetriever;
import no.nav.security.oidc.context.OIDCRequestContextHolder;
import no.nav.security.oidc.filter.OIDCTokenExpiryFilter;
import no.nav.security.oidc.filter.OIDCTokenValidationFilter;
import no.nav.security.spring.oidc.api.EnableOIDCTokenValidation;
import no.nav.security.spring.oidc.validation.interceptor.BearerTokenClientHttpRequestInterceptor;
import no.nav.security.spring.oidc.validation.interceptor.OIDCTokenControllerHandlerInterceptor;

@Configuration
@EnableOIDCTokenValidation
@EnableConfigurationProperties(MultiIssuerProperties.class)
public class EnableOIDCTokenValidationConfiguration implements WebMvcConfigurer, ImportAware {

    private static final Logger LOG = LoggerFactory.getLogger(EnableOIDCTokenValidationConfiguration.class);

    private AnnotationAttributes enableOIDCTokenValidation;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(getControllerInterceptor());
    }

    @Override
    public void setImportMetadata(AnnotationMetadata importMetadata) {
        this.enableOIDCTokenValidation = AnnotationAttributes.fromMap(
                importMetadata.getAnnotationAttributes(EnableOIDCTokenValidation.class.getName(), false));
        if (this.enableOIDCTokenValidation == null) {
            throw new IllegalArgumentException(
                    "@EnableOIDCTokenValidation is not present on importing class " + importMetadata.getClassName());
        }
    }

    @Bean
    public OIDCResourceRetriever oidcResourceRetriever(@Value("${https.plaintext:false}") boolean usePlaintext,
            @Value("${http.proxy}") URL proxy) {
        OIDCResourceRetriever resourceRetriever = new OIDCResourceRetriever();
        resourceRetriever.setProxyUrl(proxy);
        resourceRetriever.setUsePlainTextForHttps(usePlaintext);
        return resourceRetriever;
    }

    @Bean
    public MultiIssuerConfiguration multiIssuerConfiguration(MultiIssuerProperties issuerProperties,
            OIDCResourceRetriever resourceRetriever) {
        return new MultiIssuerConfiguration(issuerProperties.getIssuer(), resourceRetriever);
    }

    @Bean
    public OIDCRequestContextHolder oidcRequestContextHolder() {
        return new SpringOIDCRequestContextHolder();
    }

    @Bean
    public RequestContextListener requestContextListener() {
        return new RequestContextListener();
    }

    @Bean
    public OIDCTokenValidationFilter tokenValidationFilter(MultiIssuerConfiguration config,
            OIDCRequestContextHolder oidcRequestContextHolder) {
        return new OIDCTokenValidationFilter(config, oidcRequestContextHolder);

    }

    @Bean
    public BearerTokenClientHttpRequestInterceptor bearerTokenClientHttpRequestInterceptor(
            OIDCRequestContextHolder oidcRequestContextHolder) {
        LOG.info("creating bean for HttpClientOIDCAuthorizationInterceptor");
        return new BearerTokenClientHttpRequestInterceptor(oidcRequestContextHolder);
    }

    @Bean
    public OIDCTokenControllerHandlerInterceptor getControllerInterceptor() {
        LOG.debug("registering OIDC token controller handler interceptor");
        OIDCTokenControllerHandlerInterceptor c = new OIDCTokenControllerHandlerInterceptor(
                enableOIDCTokenValidation,
                new SpringOIDCRequestContextHolder());
        return c;
    }

    @Bean
    @Qualifier("oidcTokenValidationFilterRegistrationBean")
    public FilterRegistrationBean<OIDCTokenValidationFilter> oidcTokenValidationFilterRegistrationBean(
            OIDCTokenValidationFilter validationFilter) {
        LOG.info("Registering validation filter");
        final FilterRegistrationBean<OIDCTokenValidationFilter> filterRegistration = new FilterRegistrationBean<OIDCTokenValidationFilter>();
        filterRegistration.setFilter(validationFilter);
        filterRegistration.setMatchAfter(false);
        filterRegistration
                .setDispatcherTypes(EnumSet.of(DispatcherType.REQUEST, DispatcherType.FORWARD, DispatcherType.ASYNC));
        filterRegistration.setAsyncSupported(true);
        filterRegistration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return filterRegistration;
    }

    @Bean
    @Qualifier("oidcTokenExpiryFilterRegistrationBean")
    @ConditionalOnProperty(name = "no.nav.security.oidc.expirythreshold", matchIfMissing = false)
    public FilterRegistrationBean<OIDCTokenExpiryFilter> oidcTokenExpiryFilterRegistrationBean(
            OIDCRequestContextHolder oidcRequestContextHolder,
            @Value("${no.nav.security.oidc.expirythreshold}") long expiryThreshold) {
        LOG.info("Registering expiry filter");
        final FilterRegistrationBean<OIDCTokenExpiryFilter> filterRegistration = new FilterRegistrationBean<>();
        filterRegistration.setFilter(new OIDCTokenExpiryFilter(oidcRequestContextHolder, expiryThreshold));
        filterRegistration.setMatchAfter(false);
        filterRegistration
                .setDispatcherTypes(EnumSet.of(DispatcherType.REQUEST, DispatcherType.FORWARD, DispatcherType.ASYNC));
        filterRegistration.setAsyncSupported(true);
        filterRegistration.setOrder(2);
        return filterRegistration;
    }

    AnnotationAttributes getEnableOIDCTokenValidation() {
        return enableOIDCTokenValidation;
    }
}
