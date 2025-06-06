package com.ecommerce.userservice.service;

import com.ecommerce.userservice.dto.LoginRequest;
import com.ecommerce.userservice.dto.TokenResponse;
import com.ecommerce.userservice.entity.User;
import com.ecommerce.userservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RestTemplate restTemplate;

    private static final String KEYCLOAK_TOKEN_URL = "http://localhost:8088/realms/ecommerce/protocol/openid-connect/token";
    private static final String KEYCLOAK_USER_URL = "http://localhost:8088/admin/realms/ecommerce/users";
    private static final String KEYCLOAK_ROLE_MAPPING_URL = "http://localhost:8088/admin/realms/ecommerce/users/%s/role-mappings/realm";
    private static final String KEYCLOAK_USERS_URL = "http://localhost:8088/admin/realms/ecommerce/users?username=%s";
    private static final String KEYCLOAK_ROLE_URL = "http://localhost:8088/admin/realms/ecommerce/roles/user";
    private static final String ADMIN_TOKEN_URL = "http://localhost:8088/realms/master/protocol/openid-connect/token";
    private static final String CLIENT_ID = "ecommerce-client";
    private static final String CLIENT_SECRET = "Gnn4dJDSqTFuyHAtNhqQm0cjfgSu5JyS";

    public User registerUser(User user) {
        String username = user.getUsername().toLowerCase(); // Normalize username
        user.setUsername(username);

        if (userRepository.findByUsername(user.getUsername()).isPresent()) {
            throw new IllegalArgumentException("Username already exists in database");
        }
        if (userRepository.findByEmail(user.getEmail()).isPresent()) {
            throw new IllegalArgumentException("Email already exists in database");
        }
        if (!user.getPassword().matches("^(?=.*[a-zA-Z])(?=.*\\d).+$")) {
            throw new IllegalArgumentException("Password must contain at least one letter and one number");
        }

        String adminToken;
        try {
            adminToken = getAdminToken();
        } catch (Exception e) {
            throw new RuntimeException("Failed to obtain admin token: " + e.getMessage());
        }

        if (checkUserExistsInKeycloak(user.getUsername(), adminToken)) {
            throw new IllegalArgumentException("Username already exists in Keycloak");
        }

        String userId;
        try {
            userId = createKeycloakUser(user, adminToken);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create user in Keycloak: " + e.getMessage());
        }

        try {
            assignUserRole(userId, adminToken);
        } catch (Exception e) {
            throw new RuntimeException("Failed to assign role in Keycloak: " + e.getMessage());
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRoles(Collections.singleton("ROLE_USER"));
        user.setCreatedAt(LocalDateTime.now());
        return userRepository.save(user);
    }

    public TokenResponse login(LoginRequest loginRequest) {
        try {
            MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
            formData.add("grant_type", "password");
            formData.add("client_id", CLIENT_ID);
            formData.add("client_secret", CLIENT_SECRET);
            formData.add("username", loginRequest.getUsername());
            formData.add("password", loginRequest.getPassword());
            formData.add("scope", "profile email");

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(formData, headers);

            ResponseEntity<TokenResponse> response = restTemplate.postForEntity(
                    KEYCLOAK_TOKEN_URL, request, TokenResponse.class
            );

            return response.getBody();
        } catch (HttpClientErrorException e) {
            throw new IllegalArgumentException("Invalid username or password");
        } catch (Exception e) {
            throw new RuntimeException("Failed to authenticate with Keycloak: " + e.getMessage());
        }
    }

    public User getUserByUsername(String username) {
        return userRepository.findByUsername(username.toLowerCase())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
    }

    @Value("${<keycloak.admin.client-id>}")
    private String adminClient;

    @Value("${<keycloak.admin.client-secret>}")
    private String adminSecret;

    private String getAdminToken() {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "client_credentials");
        formData.add("client_id", adminClient);
        formData.add("client_secret", adminSecret); // Replace with actual secret

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(formData, headers);

        ResponseEntity<Map> response = restTemplate.postForEntity(
                ADMIN_TOKEN_URL, request, Map.class);

        if (response.getStatusCode().is2xxSuccessful()) {
            return (String) response.getBody().get("access_token");
        }
        throw new RuntimeException("Failed to obtain Keycloak admin token");
    }

    private boolean checkUserExistsInKeycloak(String username, String adminToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + adminToken);

        HttpEntity<Void> request = new HttpEntity<>(headers);

        ResponseEntity<List<Map<String, Object>>> response = restTemplate.exchange(
                String.format(KEYCLOAK_USERS_URL, username),
                HttpMethod.GET,
                request,
                new ParameterizedTypeReference<List<Map<String, Object>>>() {}
        );

        return response.getStatusCode().is2xxSuccessful() && !response.getBody().isEmpty();
    }

    private String createKeycloakUser(User user, String adminToken) {
        Map<String, Object> keycloakUser = new HashMap<>();
        keycloakUser.put("username", user.getUsername());
        keycloakUser.put("email", user.getEmail());
        keycloakUser.put("enabled", true);
        keycloakUser.put("firstName", user.getFirstName());
        keycloakUser.put("lastName", user.getLastName());
        keycloakUser.put("credentials", Collections.singletonList(
                Map.of("type", "password", "value", user.getPassword(), "temporary", false)
        ));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", "Bearer " + adminToken);

        HttpEntity<Map<String, Object>> request = new HttpEntity<>(keycloakUser, headers);

        ResponseEntity<Void> response = restTemplate.postForEntity(
                KEYCLOAK_USER_URL, request, Void.class);

        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new IllegalArgumentException("Failed to create user in Keycloak");
        }

        String locationHeader = response.getHeaders().getFirst("Location");
        return locationHeader.substring(locationHeader.lastIndexOf("/") + 1);
    }

    private void assignUserRole(String userId, String adminToken) {
        String roleId = getRoleId("user", adminToken);

        Map<String, Object> role = new HashMap<>();
        role.put("id", roleId);
        role.put("name", "user");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", "Bearer " + adminToken);

        HttpEntity<List<Map<String, Object>>> request = new HttpEntity<>(Collections.singletonList(role), headers);

        ResponseEntity<Void> response = restTemplate.postForEntity(
                String.format(KEYCLOAK_ROLE_MAPPING_URL, userId), request, Void.class);

        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new IllegalArgumentException("Failed to assign user role in Keycloak");
        }
    }

    private String getRoleId(String roleName, String adminToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + adminToken);

        HttpEntity<Void> request = new HttpEntity<>(headers);

        try {
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                    KEYCLOAK_ROLE_URL,
                    HttpMethod.GET,
                    request,
                    new ParameterizedTypeReference<Map<String, Object>>() {}
            );

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                return (String) response.getBody().get("id");
            }
            throw new IllegalArgumentException("Role " + roleName + " not found in Keycloak");
        } catch (RestClientException e) {
            throw new RuntimeException("Failed to fetch role " + roleName + " from Keycloak: " + e.getMessage());
        }
    }
}