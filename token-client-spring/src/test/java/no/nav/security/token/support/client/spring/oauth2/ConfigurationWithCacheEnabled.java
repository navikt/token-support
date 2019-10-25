package no.nav.security.token.support.client.spring.oauth2;

import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableOAuth2Client(cacheEnabled = true, cacheEvictSkew = 5, cacheMaximumSize = 100)
public class ConfigurationWithCacheEnabled {

    @Bean
    RestTemplateBuilder restTemplateBuilder(){
        return new RestTemplateBuilder();
    }
}
