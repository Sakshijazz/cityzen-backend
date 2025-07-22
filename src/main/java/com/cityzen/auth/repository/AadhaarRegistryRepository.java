package com.cityzen.auth.repository;
import com.cityzen.auth.entity.AadhaarRegistry;
import org.springframework.data.jpa.repository.JpaRepository;
public interface AadhaarRegistryRepository extends JpaRepository<AadhaarRegistry, Long> {
    // TODO: Find Aadhaar by number
}