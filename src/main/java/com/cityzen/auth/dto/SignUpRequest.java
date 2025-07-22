package com.cityzen.auth.dto;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
public class SignUpRequest {
    @NotBlank
    private String name;
    @Email
    @NotBlank
    private String email;
    @NotBlank
    private String password;
    @NotBlank
    private String aadhaar;
    // Getters and Setters
}