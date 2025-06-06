package com.ecommerce.userservice.dto;

import com.fasterxml.jackson.annotation.JsonProperty; // For JSON mapping
import lombok.Data; // Lombok for getters/setters

@Data // Generates boilerplate code
public class TokenResponse {
    @JsonProperty("access_token") // Matches Keycloak's response field
    private String accessToken; // JWT access token
    @JsonProperty("token_type") // Matches Keycloak's response field
    private String tokenType; // Token type (e.g., Bearer)
    @JsonProperty("expires_in") // Matches Keycloak's response field
    private long expiresIn; // Token expiration time (seconds)
    @JsonProperty("refresh_token") // Matches Keycloak's response field
    private String refreshToken; // Refresh token
}