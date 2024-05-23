package com.bezkoder.spring.security.login.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.bezkoder.spring.security.login.security.jwt.AuthEntryPointJwt;
import com.bezkoder.spring.security.login.security.jwt.AuthTokenFilter;
import com.bezkoder.spring.security.login.security.service.UserDetailsServiceImpl;
//Indica che questa classe è una configurazione di Spring.
@Configuration
@EnableMethodSecurity
//(securedEnabled = true,
//jsr250Enabled = true,
//prePostEnabled = true) --- by default
public class WebSecurityConfig {

	//Un servizio che carica i dettagli dell'utente.
	@Autowired
	UserDetailsServiceImpl userDetailsService;

	//Gestore per le risposte non autorizzate.
	@Autowired
	private AuthEntryPointJwt unauthorizedHandler;

//	Questo definisce un filtro personalizzato (AuthTokenFilter) 
//	per la gestione dei token JWT nelle richieste HTTP.
//  Intercetta le richieste e verifica la validità del token JWT.
	@Bean
	public AuthTokenFilter authenticationJwtTokenFilter() {
		return new AuthTokenFilter();
	}

//	Configura un DaoAuthenticationProvider, 
//	è responsabile dell'autenticazione degli utenti,
//	utilizza UserDetailsServiceImpl per caricare 
//	i dettagli dell'utente e BCryptPasswordEncoder 
//	per codificare e confrontare le password.
	@Bean
	public DaoAuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

		authProvider.setUserDetailsService(userDetailsService);
		authProvider.setPasswordEncoder(passwordEncoder());

		return authProvider;
	}

//	crea e configura un AuthenticationManager,
//	è responsabile della gestione delle autenticazioni nell'applicazione.
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
		return authConfig.getAuthenticationManager();
	}


//	Definisce un bean di PasswordEncoder usando
//	BCryptPasswordEncoder per codificare le password.
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	/*
	 * Configura la catena di filtri di sicurezza (SecurityFilterChain) 
	 * Disabilita la protezione CSRF (Cross-Site Request Forgery), non è necessaria per le API stateless.
	 * Configura il gestore di eccezioni per risposte non autorizzate.
	 * Configura la gestione delle sessioni per essere senza stato (stateless), tipicamente usato per applicazioni RESTful.
	 * Permette tutte le richieste agli endpoint /api/auth/** e /api/test/**.
	 * Richiede autenticazione per tutte le altre richieste.
	 * Aggiunge il DaoAuthenticationProvider configurato.
	 * Aggiunge il filtro AuthTokenFilter per la gestione dei token JWT 
	 * prima del filtro di autenticazione username/password predefinito di Spring Security.
	 * 
	 * Autenticazione e Autorizzazione:
	 * 		Le richieste agli endpoint /api/auth/** e /api/test/** sono permesse senza autenticazione.
	 * 		Tutte le altre richieste richiedono autenticazione.
	 * Gestione dei Token JWT:
	 * 		AuthTokenFilter intercetta le richieste e verifica la validità del token JWT.
	 * 		Se il token è valido, autentica l'utente e imposta il contesto di sicurezza.
	 * Gestione delle Password:
	 * 		Utilizza BCryptPasswordEncoder per codificare e verificare le password.
	 * Gestione degli Errori di Autenticazione:
	 * 		AuthEntryPointJwt gestisce le risposte per le richieste non autorizzate.
	 */
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.csrf(csfr -> csfr.disable())
				.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler))
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.authorizeHttpRequests(auth -> 
							auth
							.requestMatchers("/api/auth/**").permitAll()
							.requestMatchers("/api/test/**").permitAll()
							.anyRequest().authenticated());
		
		httpSecurity.authenticationProvider(authenticationProvider());
		
		httpSecurity.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
	
		
		return httpSecurity.build();
	}
	/*
	Flusso di Autenticazione
	Login:

	Quando un utente invia una richiesta di login con email e password, il AuthenticationManager autentica l'utente utilizzando DaoAuthenticationProvider.
	DaoAuthenticationProvider utilizza UserDetailsServiceImpl per caricare i dettagli dell'utente dal database.
	Se l'autenticazione ha successo, viene generato un token JWT e inviato al client.
	
	Verifica del Token JWT:

	Per ogni richiesta successiva, AuthTokenFilter intercetta la richiesta e verifica il token JWT.
	Se il token è valido, l'utente viene autenticato automaticamente.
	
	Accesso agli Endpoint:

	Gli endpoint configurati come permitAll sono accessibili senza autenticazione.
	Tutti gli altri endpoint richiedono autenticazione.
	*/
}
