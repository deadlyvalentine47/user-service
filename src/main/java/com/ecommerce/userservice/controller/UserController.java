package com.ecommerce.userservice.controller;

import com.ecommerce.userservice.dto.LoginRequest; // Login DTO
import com.ecommerce.userservice.dto.TokenResponse; // Token response DTO
import com.ecommerce.userservice.entity.User; // User entity
import com.ecommerce.userservice.service.UserService; // User service
import jakarta.validation.Valid; // For validation
import lombok.RequiredArgsConstructor; // Constructor injection
import org.springframework.http.ResponseEntity; // For HTTP responses
import org.springframework.security.access.prepost.PreAuthorize; // For role-based access
import org.springframework.security.core.context.SecurityContextHolder; // For JWT details
import org.springframework.web.bind.annotation.*; // Spring MVC annotations

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    // POST endpoint for registration (public)
    @PostMapping("/register")
    public ResponseEntity<User> register(@Valid @RequestBody User user) {
        return ResponseEntity.ok(userService.registerUser(user));
    }

    // POST endpoint for login (public)
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest loginRequest) {
        return ResponseEntity.ok(userService.login(loginRequest));
    }

    // GET endpoint for profile (ROLE_USER)
    @GetMapping("/profile")
    @PreAuthorize("hasRole('ROLE_USER')")
    public ResponseEntity<User> getProfile() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        return ResponseEntity.ok(userService.getUserByUsername(username));
    }
}