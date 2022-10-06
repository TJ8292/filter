package se.kuiteul.ss_2022.filters;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import se.kuiteul.ss_2022.security.CustomAuthentication;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


//@Component
public class CustomAuthorizationFilter implements Filter {


    private final AuthenticationManager manager;

    public CustomAuthorizationFilter(AuthenticationManager manager) {
        this.manager = manager;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String authorization = httpRequest.getHeader("Authorization");

        var usernamePasswordAuthenticationToken = new CustomAuthentication(authorization, null);

        try {
            var result = manager.authenticate(usernamePasswordAuthenticationToken);

            if (result.isAuthenticated()) {
                SecurityContextHolder.getContext().setAuthentication(result);
                filterChain.doFilter(request, response);

            } else {
                httpResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);

            }

        } catch (AuthenticationException e) {
            httpResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);

        }




    }
}
