package com.security.controller.page;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/page/admin")
public class ForOnlyPage_Admin {

    @GetMapping("")
    public String homePage(Model model) {

        // Return the home view name
        return "onlyFor_Admin";
    }

}
