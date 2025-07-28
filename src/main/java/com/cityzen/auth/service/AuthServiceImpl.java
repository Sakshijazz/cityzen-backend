package com.cityzen.auth.service;

import com.cityzen.auth.dto.*;
import com.cityzen.auth.entity.ForgotPasswordToken;
import com.cityzen.auth.entity.User;
import com.cityzen.auth.enums.Role;
import com.cityzen.auth.exception.CustomException;
import com.cityzen.auth.repository.AadhaarRegistryRepository;
import com.cityzen.auth.repository.ForgotPasswordTokenRepository;
import com.cityzen.auth.repository.UserRepository;
import com.cityzen.auth.util.JwtUtil;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@Primary
public class AuthServiceImpl implements AuthService {

    @Autowired
    private ForgotPasswordTokenRepository forgotPasswordTokenRepository;

    @Autowired
    private AadhaarRegistryRepository aadhaarRegistryRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private EmailService emailService;

    private boolean isValidPassword(String password) {
        return password != null && password.matches("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*#?&]).{8,}$");
    }

    @Override
    public boolean verifyAadhaar(String aadhaar) {
        return aadhaarRegistryRepository.findByAadhaarNumber(aadhaar).isPresent();
    }


    @Override
    public void signup(SignUpRequest request) {
        if (!isValidPassword(request.getPassword())) {
            throw new IllegalArgumentException("Password must be strong (8+ chars with uppercase, lowercase, digit, special char)");
        }

        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new IllegalArgumentException("Email already in use");
        }

        if (userRepository.findByAadhaar(request.getAadhaar()).isPresent()) {
            throw new IllegalArgumentException("Aadhaar already registered");
        }

        User user = new User();
        user.setUserName(request.getUserName());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setAadhaar(request.getAadhaar());
        user.setRole(Role.CITIZEN);

        userRepository.save(user);
    }

    @Override
    public JwtResponse signin(SignInRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + request.getEmail()));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Invalid password");
        }

        String token = jwtUtil.generateToken(user.getEmail(), user.getRole().name());
        return new JwtResponse(
                token,
                user.getRole().name(),
                user.getEmail(),
                System.currentTimeMillis() + 3600000 // 1 hour expiry (or whatever you're using)
        );

    }

    @Override
    public JwtResponse generateJwtResponse(Authentication authentication) {
        String email = authentication.getName(); // extract email from Authentication
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));

        String token = jwtUtil.generateToken(user.getEmail(), user.getRole().name());
        return new JwtResponse(
                token,
                user.getRole().name(),
                user.getEmail(),
                System.currentTimeMillis() + 3600000
        );

    }

    @Override
    public void forgotPassword(ForgotPasswordRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new CustomException("User not found with email: " + request.getEmail(), HttpStatus.NOT_FOUND));

        // Generate a unique reset token
        String token = UUID.randomUUID().toString();

        // Save the token and its expiry date in ForgotPasswordTokenRepository
        ForgotPasswordToken forgotPasswordToken = new ForgotPasswordToken();
        forgotPasswordToken.setEmail(request.getEmail());
        forgotPasswordToken.setToken(token);
        forgotPasswordToken.setExpiryDate(LocalDateTime.now().plusHours(1)); // Set expiry time for the token
        forgotPasswordTokenRepository.save(forgotPasswordToken);
        // Send email with the reset token link
        emailService.sendPasswordResetEmail(user.getEmail(), token);
    }

    @Override
    public void resetPassword(ResetPasswordRequest request) {
        // Step 1: Validate the reset token
        Optional<ForgotPasswordToken> tokenOpt = forgotPasswordTokenRepository.findByToken(request.getToken());
        if (tokenOpt.isPresent() && tokenOpt.get().getExpiryDate().isAfter(LocalDateTime.now())) {
            // Step 2: Retrieve the user associated with the token
            String email = tokenOpt.get().getEmail(); // Get the email from the token
            Optional<User> userOpt = userRepository.findByEmail(email);
            if (userOpt.isPresent()) {
                User user = userOpt.get();

                // Step 3: Validate the new password (you can implement your own validation logic)
                if (!isValidPassword(request.getNewPassword())) {
                    throw new IllegalArgumentException("Password does not meet strength requirements");
                }
                // Step 4: Hash the new password and update the user record
                user.setPassword(passwordEncoder.encode(request.getNewPassword())); // Hash the new password
                userRepository.save(user); // Save the updated user
                // Step 5: Delete the token after use
                forgotPasswordTokenRepository.delete(tokenOpt.get()); // Delete the token
            } else {
                throw new CustomException("User not found", HttpStatus.NOT_FOUND);
            }
        } else {
            throw new CustomException("Invalid or expired token", HttpStatus.BAD_REQUEST);
        }
    }

    @Override
    public void changePassword(ChangePasswordRequest request) {
        // Step 1: Find the user by email from the request
        Optional<User> userOpt = userRepository.findByEmail(request.getEmail());
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            // Step 2: Validate the current password
            if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
                throw new CustomException("Current password is incorrect", HttpStatus.UNAUTHORIZED);
            }
            // Step 3: Validate the new password (you can implement your own validation logic)
            if (!isValidPassword(request.getNewPassword())) {
                throw new IllegalArgumentException("New password does not meet strength requirements");
            }
            // Step 4: Update to the new password
            user.setPassword(passwordEncoder.encode(request.getNewPassword())); // Hash the new password
            userRepository.save(user); // Save the updated user
        } else {
            throw new CustomException("User not found", HttpStatus.NOT_FOUND);
        }
    }
}
