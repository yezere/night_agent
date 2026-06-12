package com.example.controller;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.net.URL;
import javax.naming.InitialContext;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @GetMapping("/search")
    public String search(@RequestParam String name) {
        // SSRF: user-controlled URL
        try {
            URL url = new URL(name);
            url.openConnection();
        } catch (Exception e) {
            return "error";
        }
        return "ok";
    }

    @PostMapping("/exec")
    public String exec(@RequestBody String cmd) {
        // Command Injection
        try {
            Runtime.getRuntime().exec(cmd);
        } catch (Exception e) {
            return "error";
        }
        return "ok";
    }

    @GetMapping("/lookup")
    public String lookup(@RequestParam String jndiName) {
        // JNDI Injection
        try {
            new InitialContext().lookup(jndiName);
        } catch (Exception e) {
            return "error";
        }
        return "ok";
    }
}
