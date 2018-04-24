package no.nav.security.spring.oidc;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.EnumSet;

import javax.servlet.DispatcherType;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.env.Environment;
import org.springframework.web.context.request.RequestContextListener;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.nimbusds.jose.util.ResourceRetriever;

import no.nav.security.oidc.configuration.OIDCProperties;
import no.nav.security.oidc.configuration.OIDCResourceRetriever;
import no.nav.security.oidc.configuration.OIDCValidationConfiguraton;
import no.nav.security.oidc.context.OIDCRequestContextHolder;
import no.nav.security.oidc.filter.OIDCTokenValidationFilter;
import no.nav.security.spring.oidc.validation.interceptor.BearerTokenClientHttpRequestInterceptor;
import no.nav.security.spring.oidc.validation.interceptor.OIDCTokenControllerHandlerInterceptor;

@Configuration
public class EnableOIDCTokenValidationConfiguration implements WebMvcConfigurer, EnvironmentAware {

	private Logger logger = LoggerFactory.getLogger(EnableOIDCTokenValidationConfiguration.class);
	
	private Environment env;
	
	@Override
	public void addInterceptors(InterceptorRegistry registry) {
		registry.addInterceptor(getControllerInterceptor());
	}
	
	@Override
	public void setEnvironment(Environment env) {
		this.env = env;
	}
	
	@Bean
	public OIDCProperties oidcProperties(){
		SpringOIDCProperties props = new SpringOIDCProperties();
		props.setEnvironment(env);
		return props;
	}
	
	@Bean 
	public OIDCResourceRetriever oidcResourceRetriever(){
		OIDCResourceRetriever resourceRetriever = new OIDCResourceRetriever();
		resourceRetriever.setProxyUrl(getConfiguredProxy());
		resourceRetriever.setUsePlainTextForHttps(Boolean.parseBoolean(env.getProperty("https.plaintext", "false")));
		return resourceRetriever;
	}
	
	@Bean
	public OIDCValidationConfiguraton oidcValidationConfiguration(OIDCProperties props, OIDCResourceRetriever resourceRetriever) {
		OIDCValidationConfiguraton config = new OIDCValidationConfiguraton(props, resourceRetriever);
		return config;
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
	public OIDCTokenValidationFilter tokenValidationFilter(OIDCValidationConfiguraton config, OIDCRequestContextHolder oidcRequestContextHolder) {
		return new OIDCTokenValidationFilter(config, oidcRequestContextHolder);

	}

	@Bean
	public BearerTokenClientHttpRequestInterceptor bearerTokenClientHttpRequestInterceptor(OIDCRequestContextHolder oidcRequestContextHolder){
		logger.info("creating bean for HttpClientOIDCAuthorizationInterceptor");
		return new BearerTokenClientHttpRequestInterceptor(oidcRequestContextHolder);
	}
	
	@Bean
	public OIDCTokenControllerHandlerInterceptor getControllerInterceptor() {
		logger.debug("registering OIDC token controller handler interceptor");
		OIDCTokenControllerHandlerInterceptor c = new OIDCTokenControllerHandlerInterceptor(
				deduceMainApplicationClass(), // read config annotation from main class, deduce from this thread
				new SpringOIDCRequestContextHolder());
		return c;
	}

	
	@Bean
	public FilterRegistrationBean<OIDCTokenValidationFilter> oidcTokenValidationFilterBean(OIDCTokenValidationFilter validationFilter) {
		logger.info("Registering validation filter");
		final FilterRegistrationBean<OIDCTokenValidationFilter> filterRegistration = new FilterRegistrationBean<OIDCTokenValidationFilter>();
		filterRegistration.setFilter(validationFilter);
		filterRegistration.setMatchAfter(false);
		filterRegistration
				.setDispatcherTypes(EnumSet.of(DispatcherType.REQUEST, DispatcherType.FORWARD, DispatcherType.ASYNC));
		filterRegistration.setAsyncSupported(true);
		filterRegistration.setOrder(Ordered.HIGHEST_PRECEDENCE);
		return filterRegistration;
	}
	
	private Class<?> deduceMainApplicationClass() {
		try {
			StackTraceElement[] stackTrace = new RuntimeException().getStackTrace();
			for (StackTraceElement stackTraceElement : stackTrace) {
				if ("main".equals(stackTraceElement.getMethodName())) {
					return Class.forName(stackTraceElement.getClassName());
				}
			}
		}
		catch (ClassNotFoundException ex) {
			// Swallow and continue
		}
		return null;
	}
	
	private URL getConfiguredProxy() {
		String proxyParameterName = env.getProperty("http.proxy.parametername", "http.proxy");
		String proxyconfig = env.getProperty(proxyParameterName);
		URL proxy = null;
		if(proxyconfig != null && proxyconfig.trim().length() > 0) {
			logger.info("Proxy configuration found [" + proxyParameterName +"] was " + proxyconfig);
			try {
				proxy = new URL(proxyconfig);
			} catch (MalformedURLException e) {
				throw new RuntimeException("config [" + proxyParameterName + "] is misconfigured: " + e, e);				
			}
		} else {
			logger.info("No proxy configuration found [" + proxyParameterName +"]");
		}
		return proxy;		
	}
}
