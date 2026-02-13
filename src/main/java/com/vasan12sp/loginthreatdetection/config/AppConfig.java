package com.vasan12sp.loginthreatdetection.config;

import tools.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.lang.reflect.Method;

/**
 * Application Configuration.
 * Provides beans for JSON serialization and other utilities.
 */
@Configuration
public class AppConfig {

    /**
     * ObjectMapper bean for JSON serialization/deserialization.
     * Attempts to register available modules (including Java time) at runtime
     * by invoking `findAndRegisterModules()` reflectively so we don't require
     * a compile-time dependency on a specific datatype module.
     */
    @Bean
    public ObjectMapper objectMapper() {
        ObjectMapper mapper = new ObjectMapper();

        // Try to call findAndRegisterModules() if present
        try {
            Method find = mapper.getClass().getMethod("findAndRegisterModules");
            find.invoke(mapper);
        } catch (NoSuchMethodException ignored) {
            // method not present - nothing we can do at compile time
        } catch (Exception ignored) {
            // ignore other runtime reflection issues
        }

        return mapper;
    }
}
