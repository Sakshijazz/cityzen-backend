package com.cityzen.auth.entity;
import com.cityzen.auth.enums.Role;
import jakarta.persistence.*;
@Entity
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;
    private String email;
    private String password;
    @Enumerated(EnumType.STRING)
    private Role role;
    private String aadhaar; // Nullable for staff
    // Getters and Setters
}