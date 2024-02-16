package com.security.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import java.io.IOException;

public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    @Autowired
    private JwtTokenProvider tokenProvider;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        // Generate JWT for the authenticated user
        String token = tokenProvider.generateToken(authentication);

        // Add the token to an HTTP-only cookie
        Cookie tokenCookie = new Cookie("Authorization", "Bearer" + token);
        tokenCookie.setHttpOnly(true);
        tokenCookie.setPath("/");
        // If you are using HTTPS, you should also set the Secure flag on the cookie
        // tokenCookie.setSecure(true);
        response.addCookie(tokenCookie);

        // For example, redirecting the user with the token in the URL or in a cookie
        getRedirectStrategy().sendRedirect(request, response, "/page/home");
    }
}
