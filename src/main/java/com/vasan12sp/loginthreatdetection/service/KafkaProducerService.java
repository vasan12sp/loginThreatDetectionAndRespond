package com.vasan12sp.loginthreatdetection.service;

import tools.jackson.databind.ObjectMapper;
import com.vasan12sp.loginthreatdetection.model.LoginEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

/**
 * Kafka Producer Service - Part of "The Broker" component.
 * Sends login events to Kafka asynchronously (Fire and Forget).
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class KafkaProducerService {

    private static final String TOPIC = "auth-events";

    private final KafkaTemplate<String, String> kafkaTemplate;
    private final ObjectMapper objectMapper;

    /**
     * Send login event to Kafka topic asynchronously.
     * This is Fire-and-Forget: we don't wait for acknowledgment.
     */
    public void sendLoginEvent(LoginEvent event) {
        try {
            String jsonMessage = objectMapper.writeValueAsString(event);

            // Fire and Forget - async send
            kafkaTemplate.send(TOPIC, event.getIp(), jsonMessage)
                .whenComplete((result, ex) -> {
                    if (ex != null) {
                        log.error("Failed to send event to Kafka for IP: {}", event.getIp(), ex);
                    } else {
                        log.debug("Login event sent to Kafka: {}", event.getIp());
                    }
                });

        } catch (Exception e) {
            log.error("Failed to serialize login event", e);
        }
    }
}
