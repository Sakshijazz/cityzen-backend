package com.cityzen.auth.dto;
import jakarta.validation.constraints.NotBlank;
public class AadhaarVerifyRequest {
    @NotBlank
    private String aadhaar;
    // Getters and Setters
}