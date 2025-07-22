package com.cityzen.auth.entity;
import jakarta.persistence.*;
@Entity
public class AadhaarRegistry {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(unique = true)
    private String aadhaarNumber;
    // Getters and Setters
}