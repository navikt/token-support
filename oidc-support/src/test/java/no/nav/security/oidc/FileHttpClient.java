package no.nav.security.oidc;
/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */
import java.io.IOException;

import com.fasterxml.jackson.databind.ObjectMapper;

import no.nav.security.oidc.configuration.IssuerMetaData;
import no.nav.security.oidc.http.HttpClient;
import no.nav.security.oidc.http.HttpHeaders;

public class FileHttpClient implements HttpClient {
	
	ObjectMapper json = new ObjectMapper();
	@Override
	public <T> T get(String uri, HttpHeaders headers, Class<T> clazz) {
		if(uri.startsWith("https://issuermetadata")) {
			return getIssuerMetaData(clazz);
		} else {
			return null;
		}
	}

	@Override
	public <T> T post(String uri, String body, HttpHeaders headers, Class<T> clazz) {
		// TODO Auto-generated method stub
		return null;
	}
	
	private <T> T getIssuerMetaData(Class<T> clazz) {
		try {
			return json.readValue(new Object().getClass().getResourceAsStream("/"), clazz);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

}
