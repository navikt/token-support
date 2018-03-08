package no.nav.security.oidc.http;
/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */
public interface HttpClient {
	
	<T> T get(String uri, HttpHeaders headers, Class<T> clazz);
	<T> T post(String uri, String body, HttpHeaders headers, Class<T> clazz);

}
