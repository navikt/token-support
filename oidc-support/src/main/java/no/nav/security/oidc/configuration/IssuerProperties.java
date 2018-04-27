package no.nav.security.oidc.configuration;

import java.net.URL;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

public class IssuerProperties {
	@NotNull
	private URL discoveryUrl;
	@NotBlank
	private String acceptedAudience;
	private String cookieName;
	
	public IssuerProperties() {}
	
	public IssuerProperties(URL discoveryUrl, String acceptedAudience) {
		this.discoveryUrl = discoveryUrl;
		this.acceptedAudience = acceptedAudience;
	}
	
	public IssuerProperties(URL discoveryUrl, String acceptedAudience, String cookieName){
		this(discoveryUrl, acceptedAudience);
		this.cookieName = cookieName;
	}

	public URL getDiscoveryUrl() {
		return discoveryUrl;
	}

	public void setDiscoveryUrl(URL discoveryUrl) {
		this.discoveryUrl = discoveryUrl;
	}

	public String getCookieName() {
		return cookieName != null ? cookieName.trim() : cookieName;
	}

	public void setCookieName(String cookieName) {
		this.cookieName = cookieName;
	}

	public String getAcceptedAudience() {
		return acceptedAudience != null ? acceptedAudience.trim() : acceptedAudience;
	}

	public void setAcceptedAudience(String acceptedAudience) {
		this.acceptedAudience = acceptedAudience;
	}

	@Override
	public String toString() {
		return "IssuerProperties [discoveryUrl=" + discoveryUrl + ", cookieName="
				+ cookieName + ", acceptedAudience=" + acceptedAudience + "]";
	}
}
