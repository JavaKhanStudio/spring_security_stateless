package com.security.controller.page;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/page/home")
public class HomeControllerPage {

    @GetMapping("")
    public String homePage(Model model, @ModelAttribute("token") String token) {
        // You might want to do some checks or processing here
        // to ensure the token is valid and not just blindly trust the value.

        // Add the token to the model so it can be accessed in the view
        model.addAttribute("token", token);

        // Return the home view name
        return "home";
    }


}
