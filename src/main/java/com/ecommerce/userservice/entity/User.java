package com.ecommerce.userservice.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;

import lombok.Data;
import java.time.LocalDateTime;
import java.util.Set;

@Entity
@Table(name = "users")
@Data
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "Username is mandatory")
    @Size(max = 50, message = "Username must be up to 50 characters")
    @Pattern(regexp = "^[a-zA-Z0-9_]+$", message = "Username must contain only letters, numbers, or underscores")
    @Column(unique = true, nullable = false)
    private String username;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    @Size(max = 100, message = "Email must be up to 100 characters")
    @Column(unique = true, nullable = false)
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 8, max = 100, message = "Password must be between between 8 and 100 characters")
    @Column(nullable = false)
    private String password;

    @Size(min = 1, message = "At least one role is required")
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "role")
    private Set<String> roles;

    @Size(max = 50, message = "First name must be up to 50 characters")
    private String firstName;

    @Size(max = 50, message = "Last name must be up to 50 characters")
    private String lastName;

    @NotNull(message = "Creation timestamp is required")
    @PastOrPresent(message = "Creation timestamp must be in the past or present")
    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    @PastOrPresent(message = "Update timestamp must be in the past or present")
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
}
