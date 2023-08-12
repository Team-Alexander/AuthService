package io.github.uptalent.auth.service;

import io.github.uptalent.auth.model.common.EmailMessageDetailInfo;
import lombok.RequiredArgsConstructor;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailProducerService {
    private final RabbitTemplate rabbitTemplate;

    @Value("${rabbitmq.exchange}")
    private String exchange;
    @Value("${rabbitmq.routing-key.verify}")
    private String routingKey;

    public void sendMessage(EmailMessageDetailInfo message) {
        rabbitTemplate.convertAndSend(exchange, routingKey, message);
    }
}
