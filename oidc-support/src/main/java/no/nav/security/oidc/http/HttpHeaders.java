package no.nav.security.oidc.http;
/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */
import java.util.ArrayList;
import java.util.List;

public class HttpHeaders {
	
	private final List<HttpHeader> headers = new ArrayList<>();
	private class HttpHeader {
		private String key;
		private String value;
		private HttpHeader(String key, String value) {
			this.key = key;
			this.value = value;
		}
		private String getKey() {
			return key;
		}
		private String getValue() {
			return value;
		}
	}
	public HttpHeaders() {
	}
	public HttpHeaders(String key, String value) {
		addHeader(key, value);
	}

	public HttpHeaders addHeader(String key, String value) {
		headers.add(new HttpHeader(key, value));
		return this;
	}
	public int size(){
		return headers.size();
	}
	public String getKey(int i) {
		return headers.get(i).getKey();
	}
	public String getValue(int i) {
		return headers.get(i).getValue();
	}

}
