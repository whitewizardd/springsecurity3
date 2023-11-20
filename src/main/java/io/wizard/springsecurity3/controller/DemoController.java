package io.wizard.springsecurity3.controller;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {
    @GetMapping("/demo")
    public String getMapping(){
        return "i am tired";
    }
}
