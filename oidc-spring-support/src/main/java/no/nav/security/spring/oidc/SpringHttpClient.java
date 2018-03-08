package no.nav.security.spring.oidc;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URI;
import java.net.URL;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;
/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */
import org.springframework.http.HttpEntity;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import no.nav.security.oidc.http.HttpClient;
import no.nav.security.oidc.http.HttpHeaders;

@Component
public class SpringHttpClient implements HttpClient, EnvironmentAware {

	private Environment env;
	private RestTemplate client = null;
	private Logger logger = LoggerFactory.getLogger(SpringHttpClient.class);
	
	@Override
	public <T> T get(String uri, HttpHeaders headers, Class<T> clazz) {
		org.springframework.http.HttpHeaders springHeaders = new org.springframework.http.HttpHeaders();
		if(headers != null) {
			for(int i = 0; i < headers.size(); i++) {
				springHeaders.add(headers.getKey(i), headers.getValue(i));
			}
		}
		HttpEntity<String>entity = new HttpEntity<String>("parameters", springHeaders);
		return client().getForObject(formatUri(uri), clazz, entity);
	}

	@Override
	public <T> T post(String uri, String body, HttpHeaders headers, Class<T> clazz) {
		org.springframework.http.HttpHeaders springHeaders = new org.springframework.http.HttpHeaders();
		for(int i = 0; i < headers.size(); i++) {
			springHeaders.add(headers.getKey(i), headers.getValue(i));
		}
		HttpEntity<String>entity = new HttpEntity<String>(body, springHeaders);
		return client().postForObject(formatUri(uri), entity, clazz);
	}
	
	private RestTemplate client() {
		if(client == null) {
			URL proxy = getConfiguredProxy();
			if(proxy != null) {
				logger.info("Configuring SpringHttpClient with proxy: " + proxy);
				client = new RestTemplate(createWithHttpProxy(proxy));
			} else {
				logger.info("Configuring SpringHttpClient without proxy");
				client = new RestTemplate();
			}			
		}
		return client;
	}

	@Override
	public void setEnvironment(Environment environment) {
		this.env = environment;
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
				throw new RuntimeException("config [" + proxyParameterName + "] is miscofigured: " + e, e);				
			}
		} else {
			logger.info("No proxy configuration found [" + proxyParameterName +"]");
		}
		return proxy;		
	}
	
	private ClientHttpRequestFactory createWithHttpProxy(URL url) {
		SimpleClientHttpRequestFactory clientHttpReq = new SimpleClientHttpRequestFactory();
		Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(url.getHost(), url.getPort()));
		clientHttpReq.setProxy(proxy);
		return clientHttpReq;
	}
	
	private String formatUri(String url) {
		boolean usePlaintextForHttps = Boolean.parseBoolean(env.getProperty("https.plaintext", "false"));
		if(!usePlaintextForHttps){
			return url;
		}
		URI uri = URI.create(url);
		if(!uri.getScheme().equals("https")){
			return url;
		}
		return "http://" + uri.getHost() + ":443" + uri.getPath() + (uri.getQuery() != null && uri.getQuery().length() > 0 ? "?" + uri.getQuery() : "");
	}
	
}
