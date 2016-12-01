package codes.monkey.bootauth

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.core.io.ClassPathResource
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer
import org.springframework.security.oauth2.provider.token.TokenStore
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter

@SpringBootApplication
//@EnableResourceServer
class AuthServerApplication extends WebMvcConfigurerAdapter{

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/login").setViewName("login");
    }


    @Configuration
    @Order(-20)
    static class WebSecurityConfig extends WebSecurityConfigurerAdapter {


        @Override
        @Bean
        AuthenticationManager authenticationManagerBean() throws Exception {
          super.authenticationManagerBean()
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {

            http
                    .formLogin().loginPage('/login').permitAll()
                    .and().httpBasic().and()
                    .requestMatchers()
                    //specify urls handled
                    .antMatchers("/login", "/oauth/authorize", "/oauth/confirm_access")
                    .antMatchers("/fonts/**", "/js/**", "/css/**")
                    .and()
                    .authorizeRequests()
                    .antMatchers("/fonts/**", "/js/**", "/css/**").permitAll()
                    .anyRequest().authenticated()


        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.inMemoryAuthentication()
                    .withUser('reader')
                    .password('reader')
                    .authorities('ROLE_READER')
                    .and()
                    .withUser('writer')
                    .password('writer')
                    .authorities('ROLE_READER', 'ROLE_WRITER')
                    .and()
                    .withUser('guest')
                    .password('guest')
                    .authorities('ROLE_GUEST')
        }
    }

    @Configuration
    @EnableAuthorizationServer
    static class OAuth2Configuration extends AuthorizationServerConfigurerAdapter {

        @Autowired
        @Qualifier('authenticationManagerBean')
        AuthenticationManager authenticationManager


        @Override
        void configure(ClientDetailsServiceConfigurer clients) throws Exception {
            clients.inMemory()
                    .withClient('web-app')
                    .scopes('read')
                    .autoApprove(true)
                    .accessTokenValiditySeconds(600)
                    .refreshTokenValiditySeconds(600)
                    .authorizedGrantTypes('implicit', 'refresh_token', 'password', 'authorization_code')
        }

        @Override
        void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
            endpoints.tokenStore(tokenStore()).tokenEnhancer(jwtTokenEnhancer()).authenticationManager(authenticationManager)
        }


        @Bean
        TokenStore tokenStore() {
            new JwtTokenStore(jwtTokenEnhancer())
        }

        @Bean
        protected JwtAccessTokenConverter jwtTokenEnhancer() {
            KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(
                    new ClassPathResource('jwt.jks'), 'mySecretKey'.toCharArray())
            JwtAccessTokenConverter converter = new JwtAccessTokenConverter()
            converter.setKeyPair(keyStoreKeyFactory.getKeyPair('jwt'))
            converter
        }
    }


    public static void main(String[] args) {
        SpringApplication.run AuthServerApplication, args
    }
}
