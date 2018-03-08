package no.nav.security.spring.oidc;
/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import no.nav.security.oidc.configuration.OIDCProperties;


@Component
public class SpringOIDCProperties implements OIDCProperties, EnvironmentAware {

	Environment env;
	
	@Override
	public String get(String key) {
		return env.getProperty(key);
	}

	@Override
	public void setEnvironment(Environment arg0) {
		this.env = arg0;
	}

}
