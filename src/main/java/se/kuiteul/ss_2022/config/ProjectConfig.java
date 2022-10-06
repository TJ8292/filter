package se.kuiteul.ss_2022.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import se.kuiteul.ss_2022.filters.MyCustomAuthenticationFilter;
import se.kuiteul.ss_2022.providers.CustomAuthenticationProvider;

@Configuration
public class ProjectConfig extends WebSecurityConfigurerAdapter {

    private final MyCustomAuthenticationFilter filter;
    private final CustomAuthenticationProvider provider;

    public ProjectConfig(@Lazy MyCustomAuthenticationFilter filter, @Lazy CustomAuthenticationProvider provider) {
        this.filter = filter;
        this.provider = provider;
    }


    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(provider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilterAt(filter, BasicAuthenticationFilter.class);

        http.authorizeRequests().anyRequest().permitAll();
    }
}
