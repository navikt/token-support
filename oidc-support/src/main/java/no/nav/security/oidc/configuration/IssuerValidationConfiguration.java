package no.nav.security.oidc.configuration;

/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */
import java.net.MalformedURLException;

import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import no.nav.security.oidc.validation.OIDCTokenValidator;

public class IssuerValidationConfiguration {

	private String name;
	private OIDCProviderMetadata metaData;
	private String acceptedAudience;
	private String cookieName;
	private OIDCTokenValidator tokenValidator;

	public IssuerValidationConfiguration(String name) {
		this.name = name;
	}

	public IssuerValidationConfiguration(String name, OIDCProviderMetadata metaData, String acceptedAudience,
			ResourceRetriever jwksResourceRetriever) throws MalformedURLException {
		this.name = name;
		this.metaData = metaData;
		this.acceptedAudience = acceptedAudience;
		this.tokenValidator = new OIDCTokenValidator(metaData.getIssuer().toString(), acceptedAudience,
				metaData.getJWKSetURI().toURL(), jwksResourceRetriever);
	}

	public String getName() {
		return name;
	}

	public String getAcceptedAudience() {
		return acceptedAudience;
	}

	public void setAcceptedAudience(String acceptedAudience) {
		this.acceptedAudience = acceptedAudience;
	}

	public void setTokenValidator(OIDCTokenValidator tokenValidator) {
		this.tokenValidator = tokenValidator;
	}

	public OIDCTokenValidator getTokenValidator() {
		return this.tokenValidator;
	}

	public String getCookieName() {
		return cookieName;
	}

	public void setCookieName(String cookieName) {
		this.cookieName = cookieName;
	}

	public OIDCProviderMetadata getMetaData() {
		return metaData;
	}

	public void setMetaData(OIDCProviderMetadata metaData) {
		this.metaData = metaData;
	}

	public void setName(String name) {
		this.name = name;
	}

	@Override
	public String toString() {
		return "IssuerValidationConfiguration [name=" + name + ", metaData=" + metaData + ", acceptedAudience="
				+ acceptedAudience + ", cookieName=" + cookieName + ", tokenValidator=" + tokenValidator + "]";
	}
}
