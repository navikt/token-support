package no.nav.security.spring.oidc.validation.interceptor;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import no.nav.security.oidc.OIDCConstants;
import no.nav.security.oidc.context.OIDCValidationContext;
import no.nav.security.oidc.filter.OIDCRequestContextHolder;
import no.nav.security.spring.oidc.validation.api.EnableOIDCTokenValidation;
import no.nav.security.spring.oidc.validation.api.Protected;
import no.nav.security.spring.oidc.validation.api.Unprotected;


public class OIDCTokenControllerHandlerInterceptor implements HandlerInterceptor, EnvironmentAware {
	
	private Logger logger = LoggerFactory.getLogger(OIDCTokenControllerHandlerInterceptor.class);
	private OIDCRequestContextHolder contextHolder;
	private String[] ignoreConfig;
	private Map<Object, Boolean> handlerFlags = new ConcurrentHashMap<>(); 
	private Environment env;
	
	public OIDCTokenControllerHandlerInterceptor(Class<?> annotatedConfigurationClass, OIDCRequestContextHolder contextHolder) {
		this.contextHolder = contextHolder;		
		EnableOIDCTokenValidation config = annotatedConfigurationClass.getAnnotation(EnableOIDCTokenValidation.class);
		if(config != null) {
			ignoreConfig = config.ignore();
			if(ignoreConfig == null || (ignoreConfig.length == 1 && isEmpty(ignoreConfig[0]))) {
				ignoreConfig = new String[0];
			}
		} else {
			// nothing explicitly configured to be ignored, intercept everything
			ignoreConfig = new String[0];
		}
	}

	@Override
	public void afterCompletion(HttpServletRequest arg0, HttpServletResponse arg1, Object handler, Exception arg3)
			throws Exception {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void postHandle(HttpServletRequest arg0, HttpServletResponse arg1, Object handler, ModelAndView arg3)
			throws Exception {
		
	}

	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
		if (handler instanceof HandlerMethod) {
			HandlerMethod handlerMethod = (HandlerMethod) handler;
			if(shouldIgnore(handlerMethod.getBean())) {
				return true;
			}
			OIDCValidationContext validationContext = (OIDCValidationContext)contextHolder.
					getRequestAttribute(OIDCConstants.OIDC_VALIDATION_CONTEXT);
			
            Unprotected unprotectedAnnotation = handlerMethod.getMethodAnnotation(Unprotected.class);
            if(unprotectedAnnotation != null) {
            	logger.debug("method " + handlerMethod + " marked @Unprotected");
            	return true;
            }
			Protected protectedAnnotation = handlerMethod.getMethodAnnotation(Protected.class);			
            if (protectedAnnotation != null) {
            	logger.debug("method " + handlerMethod + " marked @Protected");
            	if(isIssuerSpecific(protectedAnnotation)) {
            		 if(!validationContext.hasTokenFor(protectedAnnotation.issuer())) {
            			 if(shouldRedirectWhenNoValidToken(protectedAnnotation)){
            				 // redirect to authentication endpoint (or whatever uri specified)
            				 String requestUrl = env.getProperty("loginreturnurl", request.getRequestURL() + (request.getQueryString() == null ? "" : "?" + request.getQueryString()));            				 
            				 response.sendRedirect(env.getProperty(protectedAnnotation.redirectEnvKey()) + "?redirect=" + URLEncoder.encode(requestUrl, StandardCharsets.UTF_8.name()));
            				 return false;
            			 } else {
            				 throw new OIDCUnauthorizedException(protectedAnnotation.issuer() + " token required");
            			 }
            		 } else {
            			 return validationContext.hasValidToken();
            		 }
            	} else {
            		if(!validationContext.hasValidToken()) {
            			throw new OIDCUnauthorizedException("Authorization token required");
            		} else {
            			return true;
            		}
            	}
                
            }
        	logger.debug("method " + handlerMethod + " not marked, access denied (returning NOT_IMPLEMENTED)");
        	throw new OIDCUnauthorizedException("Server misconfigured - controller/method [" + 
        			handlerMethod.getBean().getClass().getName() + "." + handlerMethod.getMethod().getName() + "] not annotated @Unprotected, @Protected or added to ignore list");
            
        }
		return false;
	}
	
	private boolean isIssuerSpecific(Protected protectedAnnotation) {
		return !isEmpty(protectedAnnotation.issuer());
	}
	
	private boolean shouldRedirectWhenNoValidToken(Protected protectedAnnotation) {
		return !isEmpty(protectedAnnotation.redirectEnvKey());
	}
	
	private boolean shouldIgnore(Object object) {
		Boolean flag = handlerFlags.get(object);
		if(flag != null) {
			return flag;
		}
		String fullName = object.getClass().getName();
		for(String ignore : ignoreConfig) {
			if(fullName.startsWith(ignore)) {
				logger.info("Adding " + fullName + " to OIDC validation ignore list");
				handlerFlags.put(object, true);
				return true;
			}
		}
		logger.info("Adding " + fullName + " to OIDC validation interceptor list");
		handlerFlags.put(object, false);
		return false;
	}
	
	private boolean isEmpty(String s) {
		if(s == null || s.trim().length() == 0 || s.equalsIgnoreCase("null")) {
			return true;
		}
		return false;
	}

	@Override
	public void setEnvironment(Environment environment) {
		this.env = environment;
	}

}
