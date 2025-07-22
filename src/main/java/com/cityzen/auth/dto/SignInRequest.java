package com.cityzen.auth.dto;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
public class SignInRequest {
    @Email
    @NotBlank
    private String email;
    @NotBlank
    private String password;
    private boolean rememberMe;
    // Getters and Setters
}