package com.example.security_api_db.service;

import com.example.security_api_db.repo.AppUserRepository;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {

    private final AppUserRepository utilisateurRepository;

    public UserDetailsService(AppUserRepository utilisateurRepository) {
        this.utilisateurRepository = utilisateurRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        var utilisateur = utilisateurRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Utilisateur non trouvé: " + username));

        return User.withUsername(utilisateur.getUsername())
                .password(utilisateur.getPassword())
                .authorities(utilisateur.getRole())
                .build();
    }

}