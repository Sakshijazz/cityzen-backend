package com.cityzen.auth.service;
import com.cityzen.auth.dto.*;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class AuthService implements UserDetailsService {
    // Method definitions:
    void signup(SignUpRequest request) // TODO: Implement
    {

    }

    JwtResponse signin(SignInRequest request) // TODO: Implement
    {
        return null;
    }

    void forgotPassword(ForgotPasswordRequest request) // TODO: Implement
    {

    }

    void resetPassword(ResetPasswordRequest request) // TODO: Implement
    {

    }

    void changePassword(ChangePasswordRequest request) // TODO: Implement
    {

    }

    void validateOtp(String aadhaar, String otp) // TODO: Implement
    {

    }

    String generateOtp(String aadhaar) // TODO: Implement
    {
        return null;
    }

    void verifyAadhaar(String aadhaar) // TODO: Implement
    {

    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Implement logic to load user by username
        // For example, fetch user from the database
        // If user not found, throw UsernameNotFoundException
        return null; // Replace with actual user details
    }
}