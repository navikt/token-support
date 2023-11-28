package no.nav.security.token.support.spring.test;

import jdk.jshell.EvalException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationPreparedEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.PropertySource;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Order
public class MockOAuth2ServerApplicationListener implements ApplicationListener<ApplicationPreparedEvent> {

    private final Logger log = LoggerFactory.getLogger(MockOAuth2ServerApplicationListener.class);
    static final String PROPERTY_PREFIX = MockOAuth2ServerProperties.PREFIX;
    private static final String PORT_PROPERTY = PROPERTY_PREFIX + ".port";
    private static final String RANDOM_PORT_PROPERTY = PROPERTY_PREFIX + ".random-port";

    @Override
    public void onApplicationEvent(ApplicationPreparedEvent event) {
        System.out.println("XXXXXXX");
        log.debug("received ApplicationPreparedEvent, register random port with environment if not set.");
        registerPort(event);
    }

    private void registerPort(ApplicationPreparedEvent event)  {
        var environment = event.getApplicationContext().getEnvironment();
        Integer httpPortProperty = environment.getProperty(PORT_PROPERTY, Integer.class);
        if (isRandomPort(httpPortProperty)) {
            int port = findAvailableTcpPort();
            MutablePropertySources propertySources = environment.getPropertySources();
            addPropertySource(propertySources);
            //var source = new MapPropertySource(PROPERTY_PREFIX, Map.of(PROPERTY_PREFIX +"." +PORT_PROPERTY, port, PROPERTY_PREFIX +"." +RANDOM_PORT_PROPERTY, true));
           Map<String, Object> source =
              ((MapPropertySource) Objects.requireNonNull(propertySources.get(PROPERTY_PREFIX))).getSource();
            source.put(PORT_PROPERTY, port);
            source.put(RANDOM_PORT_PROPERTY, true);
            source.put(PROPERTY_PREFIX +".interactive-login", false);
            //propertySources.addFirst(source);
            log.debug("Registered property source for dynamic http port={}", port);
           var p =environment.getProperty(PORT_PROPERTY, Integer.class);
        } else {
            log.debug("port provided explicitly from annotation ({}), nothing to register.", httpPortProperty);
        }
    }

    private int findAvailableTcpPort()  {
            try (ServerSocket serverSocket = new ServerSocket(0)) {
                return serverSocket.getLocalPort();
            }
            catch (IOException e) {
                throw new IllegalStateException("Fant ikke random port å starte på",e);
            }
    }


    private boolean isRandomPort(Integer httpPortProperty) {
        return httpPortProperty == null || httpPortProperty <= 0;
    }

    private void addPropertySource(MutablePropertySources propertySources) {
        if (!propertySources.contains(PROPERTY_PREFIX)) {
            propertySources.addFirst(
                new MapPropertySource(PROPERTY_PREFIX, new HashMap<>()));
        } else {
            PropertySource<?> source = propertySources.remove(PROPERTY_PREFIX);
            assert source != null;
            propertySources.addFirst(source);
        }
    }
}