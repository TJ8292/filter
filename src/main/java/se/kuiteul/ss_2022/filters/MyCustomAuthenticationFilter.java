package se.kuiteul.ss_2022.filters;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import se.kuiteul.ss_2022.security.CustomAuthentication;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


@Component
public class MyCustomAuthenticationFilter extends OncePerRequestFilter {
    private final AuthenticationManager manager;

    public MyCustomAuthenticationFilter(AuthenticationManager manager) {
        this.manager = manager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorization = request.getHeader("Authorization");

        var usernamePasswordAuthenticationToken = new CustomAuthentication(authorization, null);

        try {
            var result = manager.authenticate(usernamePasswordAuthenticationToken);

            if (result.isAuthenticated()) {
                SecurityContextHolder.getContext().setAuthentication(result);
                filterChain.doFilter(request, response);

            } else {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);

            }

        } catch (AuthenticationException e) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);

        }
    }
}
