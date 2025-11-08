package com.example.security_api_db.repo;


import com.example.security_api_db.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AppUserRepository extends JpaRepository<AppUser, Integer> {
    Optional<AppUser> findByUsername(String username);
}
