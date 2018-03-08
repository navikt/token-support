package no.nav.security.oidc.configuration;
/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import no.nav.security.oidc.exceptions.MetaDataNotAvailableException;
import no.nav.security.oidc.http.HttpClient;

public class OIDCValidationConfiguraton {

	private OIDCProperties properties;
	private Map<String, IssuerValidationConfiguration> issuers = new HashMap<String, IssuerValidationConfiguration>();
	private HttpClient client;
	private List<String> issuerNames;

	public OIDCValidationConfiguraton(OIDCProperties props, HttpClient client) {
		this.properties = props;
		this.client = client;
		this.issuerNames = new ArrayList<>();
		load();
	}

	public IssuerValidationConfiguration getIssuer(String name) {
		return issuers.get(name);
	}

	private void load() {
		String[] issuerNames = properties.get(OIDCProperties.ISSUERS).split(",");
		for (String issuerName : issuerNames) {
			issuerName = issuerName.trim();
			String uri = properties.get(String.format(OIDCProperties.URI, issuerName));
			if (uri.trim().length() > 0) {
				this.issuerNames.add(issuerName);
				IssuerMetaData metaData = null;
				try {
					metaData = client.get(uri, null, IssuerMetaData.class);
					if(metaData == null) {
						
					}

					IssuerValidationConfiguration config = new IssuerValidationConfiguration(issuerName, metaData,
							properties.get(String.format(OIDCProperties.ACCEPTED_AUDIENCE, issuerName)), 
							client);
					
					config.setCookieName(properties.get(String.format(OIDCProperties.COOKIE_NAME, issuerName)));
					
					issuers.put(issuerName, config);
					issuers.put(metaData.getIssuer(), config);
				} catch (Exception e) {
					throw new MetaDataNotAvailableException(e);
				}
			}
		}
	}
	
	public List<String>getIssuerNames() {
		return this.issuerNames;
	}

}
