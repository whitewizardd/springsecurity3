package io.wizard.springsecurity3.security.config;


import io.wizard.springsecurity3.security.filter.CustomerAuthenticationFilter;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@AllArgsConstructor
public class SecurityConfig {
    private final CustomerAuthenticationFilter authenticationFilter;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{
        Class<BasicAuthenticationFilter> basicAuth = BasicAuthenticationFilter.class;
        return httpSecurity
                .addFilterAt(authenticationFilter, basicAuth)
                .authorizeHttpRequests(b -> b.anyRequest().authenticated())
                .build();
    }
}
