package io.wizard.springsecurity3.security.provider;


import io.wizard.springsecurity3.security.CustomAuthenticationToken;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {
    @Value("${secret.token}")
    private String token;
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        CustomAuthenticationToken customAuthenticationToken = (CustomAuthenticationToken) authentication;
        boolean isAValidAccessToken = customAuthenticationToken.getKey().equals(token);
        if (isAValidAccessToken) {
            return authenticatedRequest();
        }
        throw new  BadCredentialsException("you have supplied an invalid token");
    }

    private static CustomAuthenticationToken authenticatedRequest() {
        CustomAuthenticationToken customAuthenticationToken = new CustomAuthenticationToken(null);
        customAuthenticationToken.setAuthenticated(true);
        return customAuthenticationToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        Class<CustomAuthenticationToken> customToken = CustomAuthenticationToken.class;
        return authentication.equals(customToken);
    }
}
