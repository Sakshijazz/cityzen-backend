package com.cityzen.auth.repository;
import com.cityzen.auth.entity.AadhaarRegistry;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
public interface AadhaarRegistryRepository extends JpaRepository<AadhaarRegistry, Long> {
    // Find Aadhaar by number
    Optional<AadhaarRegistry> findByAadhaarNumber(String aadhaarNumber); // Method to find Aadhaar by number
}