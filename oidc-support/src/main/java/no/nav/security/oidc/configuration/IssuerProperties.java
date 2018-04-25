package no.nav.security.oidc.configuration;

import java.net.URL;

public class IssuerProperties {
	private String shortName;
	private URL discoveryUrl;
	private String cookieName;
	private String acceptedAudience;
	
	public IssuerProperties(String shortName, URL discoveryUrl, String cookieName, String acceptedAudience) {
		this.shortName = shortName;
		this.discoveryUrl = discoveryUrl;
		this.cookieName = cookieName;
		this.acceptedAudience = acceptedAudience;
	}
	public String getShortName() {
		return shortName;
	}
	public URL getDiscoveryUrl() {
		return discoveryUrl;
	}
	public String getCookieName() {
		return cookieName;
	}
	public String getAcceptedAudience() {
		return acceptedAudience;
	}
}
