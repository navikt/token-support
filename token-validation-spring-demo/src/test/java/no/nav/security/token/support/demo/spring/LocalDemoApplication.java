package no.nav.security.token.support.demo.spring;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;


@SpringBootApplication
public class LocalDemoApplication {
	public static void main(String[] args) {
		SpringApplication app = new SpringApplication(LocalDemoApplication.class);
		app.setAdditionalProfiles("local");
		app.run(args);
	}
}
