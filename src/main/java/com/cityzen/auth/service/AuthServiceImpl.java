package com.cityzen.auth.service;
import com.cityzen.auth.dto.*;
import org.springframework.stereotype.Service;
@Service
public class AuthServiceImpl extends AuthService {

    @Override
    public void signup(SignUpRequest request) {
        // TODO: Handle all auth logic here
        // Signup must check OTP map and Aadhaar existence
    }
    @Override
    public JwtResponse signin(SignInRequest request) {
        // TODO: Signin should issue JWT with correct role
        return null; // Placeholder
    }
    @Override
    public void forgotPassword(ForgotPasswordRequest request) {
        // TODO: Forgot/reset password → token generation and validation
    }
    @Override
    public void resetPassword(ResetPasswordRequest request) {
        // TODO: Implement reset password logic
    }
    @Override
    public void changePassword(ChangePasswordRequest request) {
        // TODO: Validate old password and change to new password
    }
    @Override
    public void validateOtp(String aadhaar, String otp) {
        // TODO: Validate OTP logic
    }
    @Override
    public String generateOtp(String aadhaar) {
        // TODO: Generate OTP logic
        return null; // Placeholder
    }
    @Override
    public void verifyAadhaar(String aadhaar) {
        // TODO: Verify Aadhaar logic
    }
}