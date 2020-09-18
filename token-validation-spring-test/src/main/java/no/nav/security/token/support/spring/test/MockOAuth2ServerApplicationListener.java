package no.nav.security.token.support.spring.test;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationPreparedEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.PropertySource;
import org.springframework.util.SocketUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Order
public class MockOAuth2ServerApplicationListener implements ApplicationListener<ApplicationPreparedEvent> {

    private final Logger log = LoggerFactory.getLogger(MockOAuth2ServerApplicationListener.class);
    static final String PROPERTY_PREFIX = MockOAuth2ServerProperties.PREFIX;
    private static final String PORT_PROPERTY = PROPERTY_PREFIX + ".port";
    private static final String RANDOM_PORT_PROPERTY = PROPERTY_PREFIX + ".random-port";
    private static final int MIN_PORT = 10000;
    private static final int MAX_PORT = 12000;

    @Override
    public void onApplicationEvent(ApplicationPreparedEvent event) {
        log.debug("received ApplicationPreparedEvent, register random port with environment if not set.");
        registerPort(event);
    }

    private void registerPort(ApplicationPreparedEvent event) {
        ConfigurableEnvironment environment = event.getApplicationContext().getEnvironment();
        Integer httpPortProperty = environment.getProperty(PORT_PROPERTY, Integer.class);
        if (isRandomPort(httpPortProperty)) {
            int port = SocketUtils.findAvailableTcpPort(MIN_PORT, MAX_PORT);
            MutablePropertySources propertySources = environment.getPropertySources();
            addPropertySource(propertySources);
            Map<String, Object> source =
                ((MapPropertySource) Objects.requireNonNull(propertySources.get(PROPERTY_PREFIX))).getSource();
            source.put(PORT_PROPERTY, port);
            source.put(RANDOM_PORT_PROPERTY, true);
            log.debug("Registered property source for dynamic http port=" + port);
        } else {
            log.debug("port provided explicitly from annotation ({}), nothing to register.", httpPortProperty);
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
