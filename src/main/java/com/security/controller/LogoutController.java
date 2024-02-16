package com.security.controller;


import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(path = "/logMeOut")
public class LogoutController {

    @GetMapping
    public String logoutUser(HttpServletRequest request, HttpServletResponse response) {
        System.out.println("Logout trial");

        // Invalidate the session and clear the security context
        SecurityContextHolder.clearContext();
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }

        // Clear cookies if they exist
        clearJwtCookie(response, "Authorization"); // Clear Authorization cookie if you are using it
        clearJwtCookie(response, "auth_token"); // Clear auth_token cookie if you are using it

        // Redirect to login page
        return "redirect:/login";
    }

    private void clearJwtCookie(HttpServletResponse response, String cookieName) {
        Cookie cookie = new Cookie(cookieName, null); // name of the cookie should match the one you are trying to clear
        cookie.setPath("/"); // ensure this matches the path of the cookie you are trying to delete
        cookie.setHttpOnly(true); // if your original cookie was HttpOnly
        cookie.setMaxAge(0); // expire the cookie immediately
        response.addCookie(cookie); // add the cookie to the response to send it back to the client
    }

}
