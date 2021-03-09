package co.springcoders.security;

import co.springcoders.security.jwt.JwtTokenEnhancer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@EnableWebSecurity
@Order(2)
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	@Qualifier("passwordEncoder")
	BCryptPasswordEncoder passwordEncoder;

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication()
			.withUser("user")
			.password(passwordEncoder.encode("password"))
			.roles("VIEW", "MANAGE", "CREATE", "DESTROY", "DEPLOY", "SCHEDULE", "MODIFY");
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring()
				.antMatchers(HttpMethod.PUT, "/users/")
				.antMatchers("/users/facebook/**")
				.antMatchers("/v2/api-docs", "/configuration/ui",
						"/swagger-resources/**", "/configuration/security", "/swagger-ui.html", "/webjars/**")
				.antMatchers( "/configuration/security", "/swagger-ui.html", "/webjars/**");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and().anonymous().disable()
				.requestMatchers()
				.antMatchers("/login", "/oauth/authorize", "/oauth/confirm_access")
				.and()
				.authorizeRequests().anyRequest().authenticated()
				.and()
				.httpBasic().and()
				.csrf().disable();
	}
	
	@Bean("authenticationManager")
	AuthenticationManager getAuthenticationManager() throws Exception {
		return super.authenticationManager();
	}

//	@Bean
	JwtTokenStore getAccessTokenConverter() {
		return new JwtTokenStore(JwtTokenEnhancer.getInstance());
	}

//	@Bean
	DefaultTokenServices tokenServices() {
		DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
		defaultTokenServices.setTokenStore(getAccessTokenConverter());
		defaultTokenServices.setSupportRefreshToken(true);
		return defaultTokenServices;
	}

}