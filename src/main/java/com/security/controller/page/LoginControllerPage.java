package com.security.controller.page;

import com.security.config.JwtTokenProvider;
import com.security.dto.LoginDTO;
import com.security.entity.User;
import com.security.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;

@Controller
@RequestMapping("/page/login")
public class LoginControllerPage {
    private final AuthenticationManager authenticationManager;
    private final UserService userService;
    private final JwtTokenProvider jwtTokenProvider;

    public LoginControllerPage(AuthenticationManager authenticationManager, UserService userService, JwtTokenProvider jwtTokenProvider) {
        this.authenticationManager = authenticationManager;
        this.userService = userService;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @GetMapping("/show")
    public String showLoginPage(Authentication authentication, Model model) {
        model.addAttribute("loginDTO", new LoginDTO());
        System.out.println("Current login authentication " + authentication);
        if (authentication != null && authentication.isAuthenticated()) {
            // User is already logged in, redirect to home or dashboard
            return "redirect:/page/home";
        }
        // User is not authenticated, show the login page
        return "login";
    }

    @PostMapping("")
    public String loginUserFromPage(@ModelAttribute LoginDTO loginDto, RedirectAttributes redirectAttributes, HttpServletResponse response, Model model) {
        try {
            System.out.println("Debut identification");
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());
            Authentication authentication = authenticationManager.authenticate(authToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Gather the infos on user
            String userName = loginDto.getUsername();
            User user = userService.getUser(loginDto.getUsername());

            List<String> roles = userService.getUserRoles(user);

            // Create security token for user
            String token = jwtTokenProvider.generateToken(userName, roles);
            Cookie tokenCookie = new Cookie("Authorization", "Bearer" + token);
            tokenCookie.setHttpOnly(true); // Make the cookie inaccessible to JavaScript
            tokenCookie.setPath("/"); // Cookie is available for all paths
            // tokenCookie.setSecure(true); // Uncomment if you're using HTTPS
            response.addCookie(tokenCookie); // Add cookie to response

            redirectAttributes.addFlashAttribute("token", token);

            return "redirect:/page/home";

        } catch (AuthenticationException e) {
            redirectAttributes.addFlashAttribute("loginError", "Invalid username or password");
            model.addAttribute("loginError", "Invalid username or password");
            System.out.println("Impossible d'identifier ");
            // Redirect back to the login page
            return "/login";
        }
    }


}
