package no.nav.security.spring.oidc;
import java.util.EnumSet;

import javax.servlet.DispatcherType;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.context.request.RequestContextListener;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import no.nav.security.oidc.configuration.OIDCValidationConfiguraton;
import no.nav.security.oidc.configuration.OIDCProperties;
import no.nav.security.oidc.filter.OIDCRequestContextHolder;
import no.nav.security.oidc.filter.OIDCTokenValidationFilter;
import no.nav.security.oidc.http.HttpClient;
import no.nav.security.spring.oidc.validation.interceptor.BearerTokenClientHttpRequestInterceptor;
import no.nav.security.spring.oidc.validation.interceptor.OIDCTokenControllerHandlerInterceptor;

@Configuration
public class OIDCTokenValidationConfiguration implements WebMvcConfigurer {

	private Logger logger = LoggerFactory.getLogger(OIDCTokenValidationConfiguration.class);
	
	@Autowired
	HttpClient client;
	
	@Autowired
	OIDCProperties props;
	
	@Override
	public void addInterceptors(InterceptorRegistry registry) {
		registry.addInterceptor(getControllerInterceptor());
	}
	
	@Bean
	public OIDCValidationConfiguraton config() {
		return new OIDCValidationConfiguraton(props, client);
	}
	
	@Bean
	public OIDCRequestContextHolder oidcRequestContextHolder() {
		return new SpringRequestContextHolder();
	}

	@Bean
	public RequestContextListener requestContextListener() {		
		return new RequestContextListener();
	}

	@Bean
	public OIDCTokenValidationFilter tokenValidationFilter(OIDCValidationConfiguraton config, OIDCRequestContextHolder oidcRequestContextHolder) {
		return new OIDCTokenValidationFilter(config, oidcRequestContextHolder);

	}

	/*@Bean
	@ConditionalOnMissingBean
	public RestTemplate jada(BearerTokenClientHttpRequestInterceptor interceptor) {
		logger.info("Adding interceptor " + interceptor);
		RestTemplate restClient = new RestTemplate();		
		restClient.setInterceptors(asList(interceptor));
		return restClient;
	}*/

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
				new SpringRequestContextHolder());
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
}
