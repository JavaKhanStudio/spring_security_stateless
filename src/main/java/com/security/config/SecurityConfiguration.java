package com.security.config;

import com.security.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Autowired
    private UserService userService;
    @Autowired
    private CustomOAuth2UserService customOAuth2UserService;
    // Injection du cors allowed origins. Cela rend mon application plus flexible,
    // Car les cors ne seront pas les mêmes en fonction de l'environnement
    @Value("${cors.allowedOrigins}")
    private String[] allowedOrigins;

    // Encodeur de mot de passe utilisant bcrypt
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Bean
    public OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler() {
        return new OAuth2AuthenticationSuccessHandler();
    }

    // Gestionnaire d'entrée pour l'authentification JWT
    @Bean
    public JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint() {
        return new JwtAuthenticationEntryPoint();
    }

    // Filtre d'authentification JWT pour les requêtes
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter();
    }

    // Configuration CORS pour autoriser des origines spécifiques
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of(allowedOrigins));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    // Gestionnaire d'authentification central
    @Bean
    public AuthenticationManager authenticationManagerBean(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }


    // Configuration de la chaîne de filtres de sécurité
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // Désactivation de CSRF, nécésaire pour JWT
                .cors(cors -> cors.configurationSource(corsConfigurationSource())) // Application de la config CORS
                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class) // Ajout du filtre JWT, permettant de vérifier le token et le rôle de l'utilisateur
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/admin/**", "/page/admin", "/page/admin/**").hasRole("ADMIN") // Accès admin
                        .requestMatchers("/user/**", "/page/user", "/page/user/**").hasRole("USER") // Accès étudiant
                        .requestMatchers("/tester/**").hasRole("TESTER") // Accès enseignant
                        // Accès public a certaines routes, notamment la page d'accueil, l'inscription et le login
                        .requestMatchers("/", "/index", "/test", "/test/*",
                                "/connectionAPI/register", "/connectionAPI/login", "/connectionAPI/login/page", "/logMeOut",
                                "/page/login/show", "/page/login", "/login").permitAll()
                )
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/page/login/show", "/oauth2/authorization/google").permitAll() // Allow access to the login page and OAuth2 login
                )
                // On créer l'authorisation pour la page de login
                .formLogin(form -> form
                        .loginPage("/page/login/show") // On dit ou devrait tombé la requête si demande de login
                        .permitAll() // Allow access to the login page for all
                )
                // On gère pour le Oauth sur la meme page
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/page/login/show") // On dit ou devrait tombé la requête si demande de login
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(customOAuth2UserService))
                        .successHandler(oAuth2AuthenticationSuccessHandler()))// Use the same login page for OAuth2 login
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated()) // Toutes les autres requêtes nécessitent une authentification

        ;

        return http.build();
    }
}

/*

 */