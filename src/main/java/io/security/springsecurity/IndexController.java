package io.security.springsecurity;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {

    @GetMapping("/")
    public String index(){
        return "index";
    }

    @GetMapping("/shop/mypage")
    public String mypage(){
        return "mypage";
    }

    @GetMapping("/shop/admin")
    public String admin(){
        return "admin";
    }

    @GetMapping("/shop/admin/pay")
    public String adminpay(){
        return "adminpay";
    }

}
