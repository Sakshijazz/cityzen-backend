package com.cityzen.auth.service;
import com.cityzen.auth.dto.*;
import com.cityzen.auth.entity.AadhaarRegistry;
import com.cityzen.auth.entity.ForgotPasswordToken;
import com.cityzen.auth.entity.User;
import com.cityzen.auth.enums.Role;
import com.cityzen.auth.exception.CustomException;
import com.cityzen.auth.repository.AadhaarRegistryRepository;
import com.cityzen.auth.repository.ForgotPasswordTokenRepository;
import com.cityzen.auth.repository.UserRepository;
import com.cityzen.auth.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
//Dont remove this annotation(Primary)
@Primary
public class AuthServiceImpl implements AuthService, UserDetailsService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private ForgotPasswordTokenRepository forgotPasswordTokenRepository;
    @Autowired
    private AadhaarRegistryRepository aadhaarRegistryRepository;
    private final Map<String, String> otpStore = new ConcurrentHashMap<>();

    @Autowired
    public AuthServiceImpl(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtUtil jwtUtil,
            ForgotPasswordTokenRepository forgotPasswordTokenRepository,
            AadhaarRegistryRepository aadhaarRegistryRepository
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.forgotPasswordTokenRepository = forgotPasswordTokenRepository;
        this.aadhaarRegistryRepository = aadhaarRegistryRepository;
    }

    public AuthServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public String generateOtp(String aadhaar) {
        // Generate a 6-digit OTP and store it in otpStore
        String otp = String.valueOf(new Random().nextInt(900000) + 100000); // Generate 6-digit OTP
        otpStore.put(aadhaar, otp);
        return otp; // Return OTP for testing purposes
    }

    @Override
    public boolean validateOtp(String aadhaar, String otp) {
        // Validate OTP against the stored value in otpStore
        String storedOtp = otpStore.get(aadhaar);
        return storedOtp != null && storedOtp.equals(otp);
    }

    @Override
    public void signup(SignUpRequest request) {
        // Validate Aadhaar number length
        if (request.getAadhaar() == null || request.getAadhaar().length() != 12) {
            throw new CustomException("Aadhaar number must be exactly 12 digits", HttpStatus.BAD_REQUEST);
        }
        // Validate Password complexity
        if (!isValidPassword(request.getPassword())) {
            throw new CustomException("Password should have Uppercase, Lowercase, Digit and Special character", HttpStatus.BAD_REQUEST);
        }
        // Validate that the user does not already exist
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new CustomException("User already exists", HttpStatus.BAD_REQUEST);
        }
        User user = new User();
        user.setUserName(request.getUserName());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword())); // Hash the password
        user.setRole(Role.CITIZEN); // Set default role
        userRepository.save(user);
    }

    // Method to validate password
    private boolean isValidPassword(String password) {
        return password != null && password.length() >= 8 &&
                password.matches(".*[A-Z].*") && // At least one uppercase letter
                password.matches(".*[a-z].*") && // At least one lowercase letter
                password.matches(".*[0-9].*") && // At least one digit
                password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?].*"); // At least one special character
    }

//    @Override
//    public JwtResponse signin(SignInRequest request) {
//        Authentication authentication = authenticationManager.authenticate(
//                new UsernamePasswordAuthenticationToken(
//                        request.getEmail(),
//                        request.getPassword()
//                )
//        );
//        SecurityContextHolder.getContext().setAuthentication(authentication);
//
//        String jwt = jwtUtil.generateJwtToken(authentication);
//        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
//
//        // Get user from DB to fetch role
//        User user = userRepository.findByEmail(userDetails.getUsername())
//                .orElseThrow(() -> new RuntimeException("User not found"));
//
//        String role = user.getRole().name();
//        String email = user.getEmail();
//        long expiresAt = jwtUtil.extractAllClaims(jwt).getExpiration().getTime();
//
//        return new JwtResponse(jwt, role, email, expiresAt);
//    }

    @Override
    public JwtResponse signin(SignInRequest request) {
        throw new UnsupportedOperationException("Use AuthController.signin() with AuthenticationManager instead.");
    }

    @Override
    public JwtResponse generateJwtResponse(Authentication authentication) {
        String jwt = jwtUtil.generateJwtToken(authentication);
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        User user = userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));
        String role = user.getRole().name();
        String email = user.getEmail();
        long expiresAt = jwtUtil.extractAllClaims(jwt).getExpiration().getTime();
        return new JwtResponse(jwt, role, email, expiresAt);
    }

    @Override
    public void forgotPassword(ForgotPasswordRequest request) {
        // Generate a reset token and save it to the database
        Optional<User> userOpt = userRepository.findByEmail(request.getEmail());
        if (userOpt.isPresent()) {
            String token = UUID.randomUUID().toString(); // Generate a unique reset token
            ForgotPasswordToken forgotPasswordToken = new ForgotPasswordToken();
            forgotPasswordToken.setEmail(request.getEmail());
            forgotPasswordToken.setToken(token);
            forgotPasswordToken.setExpiryDate(LocalDateTime.now().plusHours(1)); // Set expiry time for the token
            forgotPasswordTokenRepository.save(forgotPasswordToken);
            // TODO: Send email with the reset token link (implement email service)
        } else {
            throw new CustomException("Email not found", HttpStatus.NOT_FOUND);
        }
    }

    @Override
    public void resetPassword(ResetPasswordRequest request) {
        // Validate the reset token and reset the password
        Optional<ForgotPasswordToken> tokenOpt = forgotPasswordTokenRepository.findByToken(request.getToken());
        if (tokenOpt.isPresent() && tokenOpt.get().getExpiryDate().isAfter(LocalDateTime.now())) {
            Optional<User> userOpt = userRepository.findByEmail(tokenOpt.get().getEmail());
            if (userOpt.isPresent()) {
                User user = userOpt.get();
                user.setPassword(passwordEncoder.encode(request.getNewPassword())); // Hash the new password
                userRepository.save(user); // Save the updated user
                forgotPasswordTokenRepository.delete(tokenOpt.get()); // Delete the token after use
            } else {
                throw new CustomException("User not found", HttpStatus.NOT_FOUND);
            }
        } else {
            throw new CustomException("Invalid or expired token", HttpStatus.BAD_REQUEST);
        }
    }

    @Override
    public void changePassword(ChangePasswordRequest request) {
        // Assume you have a way to get the currently logged-in user's email
        String currentUserEmail = "current_user@example.com"; // Replace with actual current user context
        Optional<User> userOpt = userRepository.findByEmail(currentUserEmail);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            // Validate the current password
            if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
                throw new CustomException("Current password is incorrect", HttpStatus.UNAUTHORIZED);
            }
            // Update to the new password
            user.setPassword(passwordEncoder.encode(request.getNewPassword())); // Hash the new password
            userRepository.save(user); // Save the updated user
        } else {
            throw new CustomException("User not found", HttpStatus.NOT_FOUND);
        }
    }

    public boolean verifyAadhaar(String aadhaar) {
        // Check if the Aadhaar number exists in the database
        Optional<AadhaarRegistry> aadhaarOpt = aadhaarRegistryRepository.findByAadhaarNumber(aadhaar);
        return aadhaarOpt.isPresent(); // Return true if Aadhaar exists, false otherwise
    }

    //Dont Remove this method
//    @Override
//    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        // Load user by username (email in this case)
//        Optional<User> userOpt = userRepository.findByEmail(username);
//        if (userOpt.isPresent()) {
//            User user = userOpt.get();
//            return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), new ArrayList<>()); // You can add roles and authorities if needed
//        } else {
//            throw new UsernameNotFoundException("User not found with email: " + username);
//        }
//    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + username));
        return org.springframework.security.core.userdetails.User
                .withUsername(user.getEmail())
                .password(user.getPassword())
                .roles(user.getRole().name()) // Set role for authorization
                .build();
    }
}









