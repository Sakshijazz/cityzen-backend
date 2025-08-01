package com.cityzen.auth.controller;
import com.cityzen.auth.dto.*;
import com.cityzen.auth.service.AadhaarRegistryService;
import com.cityzen.auth.service.AuthService;
import com.cityzen.auth.service.EmailService;
import com.cityzen.auth.service.OtpService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private AuthService authService;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private OtpService otpService;
    @Autowired
    private AadhaarRegistryService service;
    @Autowired
    private EmailService emailService;

    @PostMapping("/verify-aadhaar")
    public ResponseEntity<?> verifyAadhaar(@RequestBody AadhaarVerifyRequest request) {
        // Verify the Aadhaar number
        boolean isVerified = authService.verifyAadhaar(request.getAadhaar());
        if (isVerified) {
            return ResponseEntity.ok("Aadhaar number is verified.");
        } else {
            return ResponseEntity.badRequest().body("Aadhaar number not found.");
        }
    }

//    @PostMapping("/validate-otp")
//    public ResponseEntity<?> validateOtp(@RequestBody ValidateOtpRequest request) {
//        // Validate the OTP against the generated OTP
//        return null;
//    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody SignUpRequest request) {
        // Proceed with signup after OTP verification
        authService.signup(request);
//        System.out.println("🚨 SIGNUP called");
//        System.out.println("Request Body: " + request);
        return ResponseEntity.ok("User registered successfully");
    }

//    @PostMapping("/signin")
//    public ResponseEntity<JwtResponse> signin(@RequestBody SignInRequest request) {
//        // Authenticate user and return JWT token
//        JwtResponse jwtResponse = authService.signin(request);
//        return ResponseEntity.ok(jwtResponse);
//    }

    @PostMapping("/signin")
    public ResponseEntity<JwtResponse> signin(@RequestBody SignInRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        JwtResponse jwtResponse = authService.generateJwtResponse(authentication);
        return ResponseEntity.ok(jwtResponse);
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody ForgotPasswordRequest request) {
        // Generate and save reset token, send email to user
        authService.forgotPassword(request);
        return ResponseEntity.ok("Password reset email sent");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody ResetPasswordRequest request) {
        // Reset password using the provided token
        authService.resetPassword(request);
        return ResponseEntity.ok("Password reset successfully");
    }

    @PutMapping("/change-password")
    public ResponseEntity<?> changePassword(@RequestBody ChangePasswordRequest request) {
        // Allow logged-in users to update their password
        authService.changePassword(request);
        return ResponseEntity.ok("Password changed successfully");
    }
    @PostMapping("/generate-otp")
    public ResponseEntity<?> generateOtp(@RequestBody EmailRequest request) {
        String otp = otpService.generateOtp(request.getEmail());
        emailService.sendOtp(request.getEmail(), otp);
        return ResponseEntity.ok("OTP sent to " + request.getEmail());
    }

    @PostMapping("/resend-otp")
    public ResponseEntity<?> resendOtp(@RequestBody EmailRequest request) {
        String otp = otpService.resendOtp(request.getEmail());
        emailService.sendOtp(request.getEmail(), otp);
        return ResponseEntity.ok("OTP resent to " + request.getEmail());
    }

    @PostMapping("/validate-otp")
    public ResponseEntity<?> validateOtp(@RequestBody ValidateOtpRequest request) {
        boolean isValid = otpService.validateOtp(request.getEmail(), request.getOtp());
        if (isValid) {
            return ResponseEntity.ok("OTP is valid");
        } else {
            return ResponseEntity.badRequest().body("Invalid OTP");
        }
    }
    @PostMapping("/add-aadhaar")
    public ResponseEntity<String> addAadhaar(@RequestBody AadhaarRequest request) {
        String response = service.saveAadhaar(request.getAadhaar());
        return ResponseEntity.ok(response);
    }
}




