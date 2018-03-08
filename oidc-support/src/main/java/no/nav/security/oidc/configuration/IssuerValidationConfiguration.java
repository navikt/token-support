package no.nav.security.oidc.configuration;
/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */
import java.net.MalformedURLException;
import java.net.URL;

import no.nav.security.oidc.http.HttpClient;
import no.nav.security.oidc.validation.OIDCTokenValidator;

public class IssuerValidationConfiguration {
	
	private String name;
	private IssuerMetaData metaData;
	private String acceptedAudience;
	private String cookieName;
	private OIDCTokenValidator tokenValidator; 
	
	public IssuerValidationConfiguration(String name, IssuerMetaData metaData, String acceptedAudience, HttpClient httpClient) throws MalformedURLException {
		this.name = name;
		this.metaData = metaData;
		this.acceptedAudience = acceptedAudience;
		this.tokenValidator = new OIDCTokenValidator(metaData.getIssuer(), acceptedAudience, new URL(metaData.getJwks_uri()), httpClient);
	}
	public String getName(){
		return name;
	}
	public IssuerMetaData getMetaData() {
		return metaData;
	}
	public void setMetaData(IssuerMetaData metaData) {
		this.metaData = metaData;
	}
	public String getAcceptedAudience() {
		return acceptedAudience;
	}
	public void setAcceptedAudience(String acceptedAudience) {
		this.acceptedAudience = acceptedAudience;
	}
	
	public OIDCTokenValidator getTokenValidator() {
		return this.tokenValidator;
	}
	@Override
	public String toString() {
		return "IssuerValidationConfiguration [name=" + name + ", metaData=" + metaData + ", acceptedAudience="
				+ acceptedAudience + ", tokenValidator=" + tokenValidator + "]";
	}
	public String getCookieName() {
		return cookieName;
	}
	public void setCookieName(String cookieName) {
		this.cookieName = cookieName;
	}
}
