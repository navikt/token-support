package no.nav.security.token.support.spring;

import java.net.MalformedURLException;
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
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportAware;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.web.context.request.RequestContextListener;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import no.nav.security.token.support.core.configuration.MultiIssuerConfiguration;
import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever;
import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import no.nav.security.token.support.core.validation.JwtTokenValidationHandler;
import no.nav.security.token.support.filter.JwtTokenExpiryFilter;
import no.nav.security.token.support.filter.JwtTokenValidationFilter;
import no.nav.security.token.support.spring.api.EnableJwtTokenValidation;
import no.nav.security.token.support.spring.validation.interceptor.BearerTokenClientHttpRequestInterceptor;
import no.nav.security.token.support.spring.validation.interceptor.JwtTokenHandlerInterceptor;
import no.nav.security.token.support.spring.validation.interceptor.SpringJwtTokenAnnotationHandler;

@Configuration
@EnableConfigurationProperties(MultiIssuerProperties.class)
public class EnableJwtTokenValidationConfiguration implements WebMvcConfigurer, EnvironmentAware, ImportAware {

    private final Logger logger = LoggerFactory.getLogger(EnableJwtTokenValidationConfiguration.class);

    private Environment env;

    private AnnotationAttributes enableOIDCTokenValidation;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(getControllerInterceptor());
    }

    @Override
    public void setEnvironment(Environment env) {
        this.env = env;
    }

    @Override
    public void setImportMetadata(AnnotationMetadata importMetadata) {
        this.enableOIDCTokenValidation = AnnotationAttributes.fromMap(
                importMetadata.getAnnotationAttributes(EnableJwtTokenValidation.class.getName(), false));
        if (this.enableOIDCTokenValidation == null) {
            throw new IllegalArgumentException(
                    "@EnableJwtTokenValidation is not present on importing class " + importMetadata.getClassName());
        }
    }

    // TODO remove support for global proxy - should be set per issuer config
    @Bean
    public ProxyAwareResourceRetriever oidcResourceRetriever() {
        return new ProxyAwareResourceRetriever(getConfiguredProxy(),
                Boolean.parseBoolean(env.getProperty("https.plaintext", "false")));
    }

    @Bean
    public MultiIssuerConfiguration multiIssuerConfiguration(MultiIssuerProperties issuerProperties,
            ProxyAwareResourceRetriever resourceRetriever) {
        return new MultiIssuerConfiguration(issuerProperties.getIssuer(), resourceRetriever);
    }

    @Bean
    public TokenValidationContextHolder oidcRequestContextHolder() {
        return new SpringTokenValidationContextHolder();
    }

    @Bean
    public RequestContextListener requestContextListener() {
        return new RequestContextListener();
    }

    @Bean
    public JwtTokenValidationFilter tokenValidationFilter(MultiIssuerConfiguration config,
            TokenValidationContextHolder tokenValidationContextHolder) {
        return new JwtTokenValidationFilter(new JwtTokenValidationHandler(config), tokenValidationContextHolder);

    }

    @Bean
    public BearerTokenClientHttpRequestInterceptor bearerTokenClientHttpRequestInterceptor(
            TokenValidationContextHolder tokenValidationContextHolder) {
        logger.info("creating bean for HttpClientOIDCAuthorizationInterceptor");
        return new BearerTokenClientHttpRequestInterceptor(tokenValidationContextHolder);
    }

    @Bean
    public JwtTokenHandlerInterceptor getControllerInterceptor() {
        logger.debug("registering OIDC token controller handler interceptor");
        return new JwtTokenHandlerInterceptor(enableOIDCTokenValidation,
                new SpringJwtTokenAnnotationHandler(new SpringTokenValidationContextHolder()));
    }

    @Bean
    @Qualifier("oidcTokenValidationFilterRegistrationBean")
    public FilterRegistrationBean<JwtTokenValidationFilter> oidcTokenValidationFilterRegistrationBean(
            JwtTokenValidationFilter validationFilter) {
        logger.info("Registering validation filter");
        final FilterRegistrationBean<JwtTokenValidationFilter> filterRegistration = new FilterRegistrationBean<>();
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
    @ConditionalOnProperty(name = "no.nav.security.jwt.expirythreshold", matchIfMissing = false)
    public FilterRegistrationBean<JwtTokenExpiryFilter> oidcTokenExpiryFilterRegistrationBean(
            TokenValidationContextHolder tokenValidationContextHolder,
            @Value("${no.nav.security.jwt.expirythreshold}") long expiryThreshold) {
        logger.info("Registering expiry filter");
        final FilterRegistrationBean<JwtTokenExpiryFilter> filterRegistration = new FilterRegistrationBean<>();
        filterRegistration.setFilter(new JwtTokenExpiryFilter(tokenValidationContextHolder, expiryThreshold));
        filterRegistration.setMatchAfter(false);
        filterRegistration
                .setDispatcherTypes(EnumSet.of(DispatcherType.REQUEST, DispatcherType.FORWARD, DispatcherType.ASYNC));
        filterRegistration.setAsyncSupported(true);
        filterRegistration.setOrder(2);
        return filterRegistration;
    }

    private URL getConfiguredProxy() {
        String proxyParameterName = env.getProperty("http.proxy.parametername", "http.proxy");
        String proxyconfig = env.getProperty(proxyParameterName);
        URL proxy = null;
        if (proxyconfig != null && proxyconfig.trim().length() > 0) {
            logger.info("Proxy configuration found [" + proxyParameterName + "] was " + proxyconfig);
            try {
                proxy = new URL(proxyconfig);
            } catch (MalformedURLException e) {
                throw new RuntimeException("config [" + proxyParameterName + "] is misconfigured: " + e, e);
            }
        } else {
            logger.info("No proxy configuration found [" + proxyParameterName + "]");
        }
        return proxy;
    }

    AnnotationAttributes getEnableOIDCTokenValidation() {
        return enableOIDCTokenValidation;
    }
}
