package com.security.service;

import com.security.entity.Role;
import com.security.entity.User;
import com.security.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.stream.Collectors;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private static final Logger logger = LoggerFactory.getLogger(UserDetailsServiceImpl.class);
    @Value("${oauth.password.placeholder}")
    private String oauthPlaceholderPassword;
    @Autowired
    private UserRepository userRepository;

    @Transactional
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        System.out.println("Checking for user using email " + email);
        User user = userRepository.findByEmail(email);

        if (user == null) {
            UsernameNotFoundException usernameNotFoundException = new UsernameNotFoundException("User : " + email + " | not found");
            logger.error("Error check for user " + email, usernameNotFoundException);
            throw usernameNotFoundException;
        }

        // Handling for users without a password (e.g., OAuth2 users)
        String password = user.getPassword();
        if (password == null || password.trim().isEmpty()) {
            // Set to a non-expiring, secure dummy password, since authentication is handled by OAuth2
            // Ensure this does not compromise security and is only used for OAuth2 authenticated users
            password = oauthPlaceholderPassword;
        }

        return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), mapRolesToAuthorities(user.getRoles()));
    }

    private Collection<? extends GrantedAuthority> mapRolesToAuthorities(Collection<Role> roles) {
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toList());
    }
}
