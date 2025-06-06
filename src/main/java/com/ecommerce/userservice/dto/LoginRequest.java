package com.ecommerce.userservice.dto;

import jakarta.validation.constraints.NotBlank; // For validation
import lombok.Data; // Lombok for getters/setters

@Data // Generates boilerplate code
public class LoginRequest {
    @NotBlank(message = "Username is required")
    private String username; // Username for login

    @NotBlank(message = "Password is required")
    private String password; // Password for login
}