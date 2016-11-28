package codes.monkey.bootauth

import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.bind.annotation.RestController

import java.security.Principal

/**
 *
 * curl -H "Authorization: Bearer $(curl "client1:@localhost:9999/auth/oauth/token" -d "grant_type=password&username=reader&password=reader" | jq '.access_token' -r)" "http://localhost:9999/resource/foo"
 *
 * curl -H "Authorization: Bearer $(curl "web-app:@localhost:9991/auth/oauth/token" -d "grant_type=password&username=reader&password=reader" | jq '.access_token' -r)" "http://localhost:9992/foo"
 * http://localhost:9999/auth/oauth/authorize?response_type=code&client_id=web-app
 */
@SpringBootApplication
@EnableResourceServer
@RestController
class MicroserviceApplication {

    @RequestMapping(value = '/{id}', method = RequestMethod.GET)
    public Map readFoo(@PathVariable Integer id, Principal principal) {
        [
                id: id,
                name: "${UUID.randomUUID()}" as String
        ]
    }


    @Configuration
    @EnableResourceServer
    public static class ResourceServiceConfiguration extends ResourceServerConfigurerAdapter {

        @Override
        void configure(HttpSecurity http) throws Exception {
            http.csrf().disable()
                    .authorizeRequests()
                    .antMatchers("/**").authenticated()
                    .antMatchers(HttpMethod.GET, "/*").hasAuthority("ROLE_READER")
        }

    }

    public static void main(String[] args) {
        SpringApplication.run(MicroserviceApplication.class, args)
    }
}
