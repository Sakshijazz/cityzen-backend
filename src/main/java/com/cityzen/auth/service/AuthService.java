package com.cityzen.auth.service;
import com.cityzen.auth.dto.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

public interface AuthService {
    void signup(SignUpRequest request); // Register a new user
    JwtResponse signin(SignInRequest request); // Authenticate user and return JWT

    void forgotPassword(ForgotPasswordRequest request); // Handle forgot password requests
    void resetPassword(ResetPasswordRequest request); // Handle password resets
    void changePassword(ChangePasswordRequest request); // Change password for logged-in users
    boolean validateOtp(String aadhaar, String otp);
    String generateOtp(String aadhaar); // Generate OTP for Aadhaar
    boolean verifyAadhaar(String aadhaar); // Verify Aadhaar number
    JwtResponse generateJwtResponse(Authentication authentication);
    //Dont Remove this method
    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}