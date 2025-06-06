package com.ecommerce.userservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate; // For HTTP client

@Configuration
public class AppConfig {

    // Provides RestTemplate for Keycloak HTTP requests
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}