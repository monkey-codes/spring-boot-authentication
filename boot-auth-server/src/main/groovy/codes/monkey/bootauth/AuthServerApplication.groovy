package codes.monkey.bootauth

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.autoconfigure.security.SecurityProperties
import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices
import org.springframework.boot.context.embedded.FilterRegistrationBean
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.NestedConfigurationProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.core.io.ClassPathResource
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.client.OAuth2ClientContext
import org.springframework.security.oauth2.client.OAuth2RestTemplate
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer
import org.springframework.security.oauth2.provider.token.TokenStore
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.filter.CompositeFilter
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter

import javax.servlet.Filter

@SpringBootApplication
class AuthServerApplication extends WebMvcConfigurerAdapter {

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/login").setViewName("login")
    }


    @Configuration
    @RestController
    @EnableOAuth2Client
    @EnableAuthorizationServer
    @Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
    static class WebSecurityConfig extends WebSecurityConfigurerAdapter {

        @Autowired
        OAuth2ClientContext oauth2ClientContext


        @Override
        @Bean
        AuthenticationManager authenticationManagerBean() throws Exception {
            super.authenticationManagerBean()
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {

            http
                    .formLogin().loginPage('/login').permitAll()
                    .and().httpBasic()
                    .and().requestMatchers()
                    //specify urls handled
                    .antMatchers("/login", "/login/facebook" , "/oauth/authorize", "/oauth/confirm_access")
                    .antMatchers("/fonts/**", "/js/**", "/css/**")
                    .and()
                    .authorizeRequests()
                    .antMatchers("/fonts/**", "/js/**", "/css/**","/login**","/login/facebook").permitAll()
                    .anyRequest().authenticated()
                    .and().addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class)


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

        @Bean
        FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
            FilterRegistrationBean registration = new FilterRegistrationBean()
            registration.setFilter(filter)
            registration.setOrder(-100)
            return registration
        }


        @Bean
        @ConfigurationProperties("facebook")
        ClientResources facebook() {
            return new ClientResources()
        }

        private Filter ssoFilter() {
            CompositeFilter filter = new CompositeFilter()
            List<Filter> filters = new ArrayList<>()
            filters.add(ssoFilter(facebook(), "/login/facebook"))
            filter.setFilters(filters)
            return filter
        }

        private Filter ssoFilter(ClientResources client, String path) {
            OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(
                    path)
            OAuth2RestTemplate template = new OAuth2RestTemplate(client.getClient(), oauth2ClientContext)
            filter.setRestTemplate(template)
            UserInfoTokenServices tokenServices = new UserInfoTokenServices(
                    client.getResource().getUserInfoUri(), client.getClient().getClientId())
            tokenServices.setRestTemplate(template)
            //define the roles for users authenticating through facebook
            tokenServices.setAuthoritiesExtractor(new AuthoritiesExtractor() {
                @Override
                List<GrantedAuthority> extractAuthorities(Map<String, Object> map) {
                    return [new SimpleGrantedAuthority("ROLE_READER")]
                }
            })
            filter.setTokenServices(tokenServices)
            return filter
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

class ClientResources {

    @NestedConfigurationProperty
    AuthorizationCodeResourceDetails client = new AuthorizationCodeResourceDetails()

    @NestedConfigurationProperty
    ResourceServerProperties resource = new ResourceServerProperties()

}
