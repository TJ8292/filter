package se.kuiteul.ss_2022.providers;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;
import se.kuiteul.ss_2022.security.CustomAuthentication;


@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    //@Value("${key}")
    private String keyHeader = "junias";


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String requestKey = authentication.getName();

        if (requestKey.equals(keyHeader)) {

            var auth = new CustomAuthentication(requestKey, null, null);

            return auth;

        } else {
            throw new BadCredentialsException("Bad creds");
        }


    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CustomAuthentication.class.equals(authentication);
    }
}
