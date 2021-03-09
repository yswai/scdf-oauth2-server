package co.springcoders.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import co.springcoders.security.jwt.JwtTokenEnhancer;

@SuppressWarnings("deprecation")
@Configuration
@EnableAuthorizationServer
public class AuthServerConfig extends AuthorizationServerConfigurerAdapter {

//	@Autowired
	private JwtTokenStore tokenStore;

	@Value("${redirectUrl}")
	private String redirectUrls;

	@Autowired
	@Qualifier("authenticationManager")
	private AuthenticationManager authenticationManager;

	 @Bean("passwordEncoder")
	 BCryptPasswordEncoder passwordEncoder() {
		 return new BCryptPasswordEncoder();
	 }
	 
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		 clients
		 	.inMemory()
		 		.withClient("clientId")
		 			.secret(passwordEncoder().encode("client-secret"))
		 			.scopes("dataflow.view",
							"dataflow.deploy",
							"dataflow.destroy",
							"dataflow.manage",
							"dataflow.modify",
							"dataflow.schedule",
							"dataflow.create")
		 			.authorizedGrantTypes("authorization_code", "refresh_token")
		 			.redirectUris(redirectUrls.split(","))
		 			.autoApprove(true);
	 }

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
//		endpoints.tokenStore(tokenStore)
//				.accessTokenConverter(JwtTokenEnhancer.getInstance())
//				.authenticationManager(authenticationManager);
		endpoints.authenticationManager(authenticationManager);
	}

}
