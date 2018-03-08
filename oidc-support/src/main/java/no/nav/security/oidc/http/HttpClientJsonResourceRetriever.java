package no.nav.security.oidc.http;

import java.io.IOException;
import java.net.URL;

import javax.activation.MimeType;

import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;

public class HttpClientJsonResourceRetriever implements ResourceRetriever {
	
	private HttpClient httpClient;
	public static String JSON_CONTENT_TYPE = "application/json";
		

	public HttpClientJsonResourceRetriever(HttpClient httpClient) {
		super();
		this.httpClient = httpClient;
	}


	@Override
	public Resource retrieveResource(URL url) throws IOException {
		return new Resource(
				httpClient.get(url.toString(), new HttpHeaders("Accept", JSON_CONTENT_TYPE), String.class), 
				JSON_CONTENT_TYPE);
	}

}
