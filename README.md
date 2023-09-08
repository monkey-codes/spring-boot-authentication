# spring-boot-authentication
A sample project to show [how to use JWT and OAuth with Spring Boot](https://johanzietsman.com/how-to-use-jwt-and-oauth-with-spring-boot/).

The sample consists of three distinct applications:

* Auth Server - Provides SSO and OAuth endpoints
* Web App - Basic stateful web application with a Zuul API Gateway configured.
* Microservice - Stateless protected API Resource.

![system architecture](https://res.cloudinary.com/monkey-codes/image/upload/v1480053775/boot-auth/boot-auth-architecture_fct4nj.svg)

##Usage
```
$ git clone git@github.com:monkey-codes/spring-boot-authentication.git
$ cd spring-boot-authentication
$ ./gradlew bootRun --parallel 
```

*Web App* starts on `http://localhost:8080:/web-app`
