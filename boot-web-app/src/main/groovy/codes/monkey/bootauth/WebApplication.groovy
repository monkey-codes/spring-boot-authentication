package codes.monkey.bootauth

import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso
import org.springframework.cloud.netflix.zuul.EnableZuulProxy
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter

@SpringBootApplication
@EnableOAuth2Sso
@EnableZuulProxy
class WebApplication
        extends WebSecurityConfigurerAdapter
{

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.logout().and().antMatcher("/**").authorizeRequests()
                .antMatchers("/login","/auth/**").permitAll()
                .anyRequest().authenticated().and().csrf().disable()
    }

    public static void main(String[] args) {
        SpringApplication.run WebApplication, args
    }
}
