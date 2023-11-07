package io.wizard.springsecurity3.security.filter;

import io.wizard.springsecurity3.security.CustomAuthenticationToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@AllArgsConstructor
@Component
@Slf4j
public class CustomerAuthenticationFilter extends OncePerRequestFilter {
    private final AuthenticationManager authenticationManager;
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        //extract the authentication credentials from the request
        String token = request.getHeader("token");
        //create an authentication object that is yet to be authenticated
        Authentication authentication = new CustomAuthenticationToken(token);
        log.info("authentication status before manager {}", authentication.isAuthenticated());
        //send the unauthenticated authentication to the authentication manager for authentication
        //get back the now authenticated object from the authentication manager
        Authentication authResult = authenticationManager.authenticate(authentication);
        log.info("authentication status after the manager {}", authResult.isAuthenticated());
        // put the authenticated object from the manager in the security context
        if (authResult.isAuthenticated()){
            SecurityContext context = SecurityContextHolder.getContext();
            context.setAuthentication(authentication);
            filterChain.doFilter(request, response);
        }
//        throw new AuthenticationException("Authentication for the user");
    }
}
