package com.cityzen.auth.dto;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
public class SignUpRequest {
    @NotBlank
    private String userName; // New field for first name
    @Email
    @NotBlank
    private String email;
    @NotBlank
    private String password;
    private String aadhaar; // Optional
    @NotBlank
    private String phoneNumber; // New field for phone number
    private String otp; // New field for OTP
    // Getters and Setters
    public String getUserName() {
        return userName; // Return the first name
    }
    public void setUserName(String userName) {
        this.userName = userName; // Set the first name
    }
    public String getEmail() {
        return email; // Return the email
    }
    public void setEmail(String email) {
        this.email = email; // Set the email
    }
    public String getPassword() {
        return password; // Return the password
    }
    public void setPassword(String password) {
        this.password = password; // Set the password
    }
    public String getAadhaar() {
        return aadhaar; // Return the Aadhaar number
    }
    public void setAadhaar(String aadhaar) {
        this.aadhaar = aadhaar; // Set the Aadhaar number
    }
    public String getPhoneNumber() {
        return phoneNumber; // Return the phone number
    }
    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber; // Set the phone number
    }
    public String getOtp() {
        return otp; // Return the OTP
    }
    public void setOtp(String otp) {
        this.otp = otp; // Set the OTP
    }

}