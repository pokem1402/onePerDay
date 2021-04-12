package com.example.Oauth2;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;


import static org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

@SpringBootApplication
@RestController
public class SpringOauth2Application extends WebSecurityConfigurerAdapter {


	@Autowired
	HttpServletRequest request;
	
	public static void main(String[] args) {
		SpringApplication.run(SpringOauth2Application.class, args);
	}

	@GetMapping("/user")
	public Map<String, Object> user(@AuthenticationPrincipal OAuth2User principal) {
		return Collections.singletonMap("name", principal.getAttribute("name"));
	}
	
	@GetMapping("/error")
	public String error() {
		String message = (String) request.getSession().getAttribute("error.message");
		request.getSession().removeAttribute("error.message");
		return message;
	}
	
	@RequestMapping("/me")
	public void profile(){
	
//		get UserInfo
		DefaultOAuth2User user = (DefaultOAuth2User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		
		System.out.println(user.getName());
		System.out.println(user.getAuthorities());
		System.out.println(user.getAttributes());
		System.out.println(user.toString());
		
	}
	
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		AuthenticationFailureHandler handler = new SimpleUrlAuthenticationFailureHandler();

		// @formatter:off
		http
		//login
			.authorizeRequests(a ->a
								.antMatchers("/", "/error", "/webjars/**").permitAll() // unauthorized user can access
								.anyRequest().authenticated())
								.logout(l -> l // for logout
										.logoutSuccessUrl("/").permitAll())
								.csrf(c -> c // for Cross Site Request Forgery
										.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
								.exceptionHandling(e -> e
										.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
										)
								.oauth2Login(
										o -> o
							            .failureHandler((request, response, exception) -> {
										    request.getSession().setAttribute("error.message", exception.getMessage());
										    handler.onAuthenticationFailure(request, response, exception);
							            })
							        );
		// @formatter:on
	}
	
	@Autowired
	WebClient rest;
	
	@Bean
	public WebClient rest(ClientRegistrationRepository clients, OAuth2AuthorizedClientRepository authz) {
	    ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2 =
	            new ServletOAuth2AuthorizedClientExchangeFilterFunction(clients, authz);
	    return WebClient.builder()
	            .filter(oauth2).build();
	}
	
	// WebClient instance is for accessing the Github API on behalf of the authenticated user (GitHub User Filtering)
	@Bean
	public OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService(WebClient rest) {
	    DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
	    return request -> {
	        OAuth2User user = delegate.loadUser(request);


	        System.out.println(user.toString());
	        
	        System.out.println("github, "+ request.getClientRegistration().getRegistrationId());
	        System.out.println(user.getAttribute("organization_url")+"");
	        if (!"github".equals(request.getClientRegistration().getRegistrationId())) {
	        	
	        	
	        	return user;
	        }

	        OAuth2AuthorizedClient client = new OAuth2AuthorizedClient
	                (request.getClientRegistration(), user.getName(), request.getAccessToken());
	        String url = user.getAttribute("organizations_url");
	        String url1 = user.getAttribute("repos_url");

//	        System.out.println(rest.toString());
//	        System.out.println(rest.get().uri(url).toString());
//	        System.out.println(rest.get().uri(url).attributes(oauth2AuthorizedClient(client)).toString());
//	        System.out.println(rest.get().uri(url).attributes(oauth2AuthorizedClient(client)).retrieve().toString());
//	        System.out.println(rest.get().uri(url).attributes(oauth2AuthorizedClient(client)).retrieve().bodyToMono(List.class).block().toString());
//	        
//	        System.out.println(rest.toString());
//	        System.out.println(rest.get().uri(url1).toString());
//	        System.out.println(rest.get().uri(url1).attributes(oauth2AuthorizedClient(client)).toString());
//	        System.out.println(rest.get().uri(url1).attributes(oauth2AuthorizedClient(client)).retrieve().toString());
//	        System.out.println(rest.get().uri(url1).attributes(oauth2AuthorizedClient(client)).retrieve().bodyToMono(List.class).block().toString());

	        List<Map<String, String>> repos = rest.get().uri(url1).attributes(oauth2AuthorizedClient(client)).retrieve().bodyToMono(List.class).block();
	        
	        repos.forEach(e -> {System.out.println(e.toString());});
	        
	        List<Map<String, Object>> orgs = rest
	                .get().uri(url)
	                .attributes(oauth2AuthorizedClient(client))
	                .retrieve()
	                .bodyToMono(List.class)
	                .block();

	        System.out.println(orgs.toString());
	        
	        String teamFilterText = "spring-projects";
	        
	        if (orgs.stream().anyMatch(org -> teamFilterText.equals(org.get("login")))) {	 
	            return user;
	        }else if(repos.size() > 6)
	        	return user;

	        throw new OAuth2AuthenticationException(new OAuth2Error("invalid_token", "Not in Spring Team", ""));
	    };
	}
}
