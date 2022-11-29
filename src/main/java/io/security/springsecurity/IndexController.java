package io.security.springsecurity;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class IndexController {

    @GetMapping("/")
    public String index(Model model, Authentication authentication, @AuthenticationPrincipal UserDetails user){

        UserDetails principal = (UserDetails)SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        System.out.println("principal = " + principal);
        System.out.println("authentication = " + authentication + ", user = " + user);

        model.addAttribute("user",user.getUsername());

        return "index";
    }

    @GetMapping("/user")
    public String user(){
        return "user";
    }

    @GetMapping("/admin")
    public String admin(){
        return "admin";
    }

    @GetMapping("/admin/pay")
    public String adminpay(){
        return "adminpay";
    }

}
