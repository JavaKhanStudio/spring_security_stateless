package com.security.service;

import com.security.entity.Role;
import com.security.entity.User;
import com.security.repository.RoleRepository;
import com.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class UserService {

    @Value("${oauth.password.placeholder}")
    private String oauthPlaceholderPassword;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    public User findUserById(Long id) {
        return userRepository.findById(id).orElse(null);
    }

    public User registerNewUserAccount(User user, boolean fromOAuth, boolean doSetAsUser) {
        if (fromOAuth) {
            user.setPassword(passwordEncoder().encode(oauthPlaceholderPassword));
        } else {
            user.setPassword(passwordEncoder().encode(user.getPassword()));
        }

        user = userRepository.save(user);

        if (doSetAsUser) {
            user.setRoles(new ArrayList<>());
            user.getRoles().add(roleRepository.getReferenceById(1)); // role User, pourrait être plus propre
            user = userRepository.save(user);
        }

        return user;
    }

    public User getUserByToken(String token) {
        User user = userRepository.findByClaimToken(token);

        if (user == null) {
            throw new UsernameNotFoundException("User not found");
        } else if (user.getTokenExpiration().isBefore(LocalDateTime.now())) {
            throw new UsernameNotFoundException("Token expired");
        } else if (user.isEnabled()) {
            throw new UsernameNotFoundException("User already enabled");
        }

        return user;
    }

    public void deleteUser(Long id) {
        userRepository.deleteById(id);
    }

    public List<String> getUserRoles(String email) {
        User user = findByEmail(email);
        return getUserRoles(user);
    }


    public List<String> getUserRoles(User user) {
        if (user == null) {
            throw new UsernameNotFoundException("User not found");
        }

        return user.getRoles().stream().map(Role::getName).collect(Collectors.toList());
    }

    // Le username est en réalité mon email
    public User getUser(String email) {
        return userRepository.findByEmail(email);
    }


    public User findByEmail(String email) {
        return userRepository.findByEmail(email);
    }
}

