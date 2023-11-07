package io.wizard.springsecurity3.security.manager;

import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;



@AllArgsConstructor
public class CustomerAuthenticationManager implements AuthenticationManager {

    private final AuthenticationProvider authenticationProvider;
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authenticationProvider.supports(authentication.getClass())){
            return authenticationProvider.authenticate(authentication);
        }
        throw new AuthenticationServiceException("sorry we don't do that here");
    }
}
