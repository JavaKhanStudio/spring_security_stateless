package com.security.config;

import com.security.entity.Role;
import com.security.entity.User;
import com.security.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.HashSet;

@Service
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    @Bean
    public UserService userService() {
        return new UserService() ;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = delegate.loadUser(userRequest);

        // On extrait l'information de connection du user
        // Par exemple ici j'ai le email et le nom de mon utilisateur
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");
        String providerName = userRequest.getClientRegistration().getRegistrationId();

        // Je vais utilisé cette information pour voir si mon user est déja en base
        // Je vais créer ce user s'il n'existe pas
        User user = userService().findByEmail(email);
        HashSet<SimpleGrantedAuthority> authorities = new HashSet<>();
        if (user == null) {
            // Creation d'un
            user = new User();
            user.setEmail(email);
            user.setEnabled(true);
            user.setOAuthProvider(providerName); // D'ou viens mon Oauth, dans ce cas google

            userService().registerNewUserAccount(user, true, true);
            // Define the user's authorities/roles
            authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        } else {
            for (Role role : user.getRoles()) {
                authorities.add(new SimpleGrantedAuthority(role.getName()));
            }
        }

        // Return an OAuth2User that includes the authorities and attributes
        return new DefaultOAuth2User(authorities, oAuth2User.getAttributes(), "sub");
    }
}