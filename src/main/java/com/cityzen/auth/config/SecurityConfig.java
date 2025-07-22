package com.cityzen.auth.config;
import com.cityzen.auth.filter.JwtAuthenticationFilter;
import com.cityzen.auth.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired
    private AuthService authService; // Ensure AuthService implements UserDetailsService
    @Bean
    public PasswordEncoder passwordEncoder() {
        // Returns a PasswordEncoder that uses BCrypt for hashing passwords
        return new BCryptPasswordEncoder();
    }
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/auth/signup", "/auth/signin", "/auth/verify-aadhaar").permitAll() // Allow unauthenticated access to these endpoints
                        .anyRequest().authenticated() // All other requests require authentication
                )
                .addFilterBefore(new JwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class); // Add JWT filter before the default UsernamePasswordAuthenticationFilter
        return http.build(); // Build and return the SecurityFilterChain
    }
    @Bean
    public AuthenticationManager authManager(HttpSecurity http) throws Exception {
        // Get the shared AuthenticationManagerBuilder from the HttpSecurity instance
        AuthenticationManagerBuilder authenticationManagerBuilder =
                http.getSharedObject(AuthenticationManagerBuilder.class);
        // Set the userDetailsService and password encoder for the authentication manager
        // Ensure AuthService implements UserDetailsService
        authenticationManagerBuilder.userDetailsService(authService).passwordEncoder(passwordEncoder());
        // Build and return the AuthenticationManager
        return authenticationManagerBuilder.build();
    }
}