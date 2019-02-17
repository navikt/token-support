package no.nav.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.AbstractMap;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import no.nav.security.spring.oidc.api.EnableOIDCTokenValidation;

@ExtendWith(SpringExtension.class)
@EnableOIDCTokenValidation(ignore = { EnableOIDCTokenValidationConfigurationTest.PACKAGE_TO_IGNORE })
public class EnableOIDCTokenValidationConfigurationTest {

    static final String PACKAGE_TO_IGNORE = "my.test.code";

    @Autowired
    private EnableOIDCTokenValidationConfiguration config;

    @Test
    public void test() {
        assertThat(config.getEnableOIDCTokenValidation()).isNotNull();
        assertThat(config.getEnableOIDCTokenValidation()).isNotEmpty();
        assertThat(config.getEnableOIDCTokenValidation())
                .containsExactly(new AbstractMap.SimpleEntry<>("ignore", new String[] { PACKAGE_TO_IGNORE }));
    }

}
