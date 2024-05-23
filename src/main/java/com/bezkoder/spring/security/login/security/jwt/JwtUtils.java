package com.bezkoder.spring.security.login.security.jwt;

import java.security.Key;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import com.bezkoder.spring.security.login.security.service.UserDetailsImpl;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

@Component
public class JwtUtils {

	// Logger per registrare informazioni e messaggi di errore durante
	// l'elaborazione dei JWT.
	private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

	// @Value: Inietta i valori delle proprietà configurate nel file
	// application.properties o application.yml
	@Value("${login.app.jwtSecret}")
	private String jwtSecret;

	@Value("${login.app.jwtExpirationMs}")
	private int jwtExpirationMs;

	@Value("${login.app.jwtCookieName}")
	private String jwtCookie;

//	Questo metodo estrae il JWT dai cookie della richiesta HTTP.
//	Utilizza WebUtils.getCookie per ottenere il cookie con il nome specificato (jwtCookie). 
//	Se il cookie è presente, restituisce il valore del cookie (il token JWT), altrimenti restituisce null.
	public String getJwtFromCookies(HttpServletRequest request) {
		Cookie cookie = WebUtils.getCookie(request, jwtCookie);
		if (cookie != null) {
			return cookie.getValue();
		} else {
			return null;
		}
	}

//	Questo metodo genera un cookie contenente un JWT. 
//	Prende come parametro un oggetto UserDetailsImpl, che rappresenta i dettagli dell'utente autenticato. 
//	Il token JWT viene generato utilizzando il metodo generateTokenFromUsername e poi viene creato un ResponseCookie 
//	con il nome del cookie, il token JWT come valore, un percorso /api, una durata di 24 ore e l'opzione httpOnly impostata a true
//	per prevenire accessi da script lato client.(esempio JS)
	public ResponseCookie generateJwtCookie(UserDetailsImpl userPrincipal) {
		String jwt = generateTokenFromUsername(userPrincipal.getUsername());
		ResponseCookie cookie = ResponseCookie.from(jwtCookie, jwt).path("/api").maxAge(24 * 60 * 60).httpOnly(true)
				.build();
		return cookie;
	}

//	Questo metodo restituisce un ResponseCookie con il valore null, utile per cancellare il cookie JWT. 
//	Imposta solo il nome del cookie e il percorso /api
	public ResponseCookie getCleanJwtCookie() {
		ResponseCookie cookie = ResponseCookie.from(jwtCookie, null).path("/api").build();
		return cookie;
	}

//	Questo metodo estrae il nome utente dal token JWT. Utilizza Jwts.
//	parserBuilder per configurare il parser JWT con la chiave di firma (key()). 
//	Il metodo parseClaimsJws analizza il token e restituisce le Claims (le informazioni contenute nel token), 
//	da cui viene estratto il soggetto (getSubject()), che di solito è il nome utente.

	public String getUserNameFromJwtToken(String token) {
		return Jwts.parserBuilder().setSigningKey(key()).build().parseClaimsJws(token).getBody().getSubject();
	}

//	Questo metodo restituisce la chiave utilizzata per firmare i token JWT. 
//	Decodifica la chiave segreta base64 (jwtSecret) e crea una chiave HMAC-SHA utilizzabile con JWT.
	private Key key() {
		return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
	}

//	Questo metodo valida un token JWT. 
//	Tenta di analizzare il token con Jwts.parserBuilder e 
//	la chiave di firma. Se il token è valido, restituisce true.
//	Se ci sono errori durante la validazione, come token malformato,
//	scaduto, non supportato o con una stringa di claims vuota, 
//	registra un messaggio di errore e restituisce false.
	public boolean validateJwtToken(String authToken) {
		try {
			Jwts.parserBuilder().setSigningKey(key()).build().parse(authToken);
			return true;
		} catch (MalformedJwtException e) {
			logger.error("Invalid JWT token: {}", e.getMessage());
		} catch (ExpiredJwtException e) {
			logger.error("JWT token is expired: {}", e.getMessage());
		} catch (UnsupportedJwtException e) {
			logger.error("JWT token is unsupported: {}", e.getMessage());
		} catch (IllegalArgumentException e) {
			logger.error("JWT claims string is empty: {}", e.getMessage());
		}
		return false;
	}

//		Questo metodo genera un token JWT a partire dal nome utente.
// 		Configura il Jwts.builder con:
//		setSubject(username): imposta il soggetto del token (di solito il nome utente).
//		setIssuedAt(new Date()): imposta la data di emissione del token.
//		setExpiration(new Date((new Date()).getTime() + jwtExpirationMs)): imposta la data di scadenza del token.
//		signWith(key(), SignatureAlgorithm.HS256): firma il token con la chiave HMAC-SHA e l'algoritmo HS256.
//		compact(): compatta il tutto in un token JWT in formato stringa.
	private String generateTokenFromUsername(String username) {
		return Jwts.builder().setSubject(username).setIssuedAt(new Date())
				.setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
				.signWith(key(), SignatureAlgorithm.HS256).compact();
	}

}

/*
 * La classe JwtUtils gestisce la generazione, la validazione e l'estrazione
 * delle informazioni dai token JWT. Utilizza le configurazioni iniettate per
 * determinare la chiave di firma, la durata del token e il nome del cookie JWT.
 * Le principali funzioni sono:
 * 
 * Estrarre il JWT dai cookie delle richieste HTTP.
 * Generare un cookie contenente il JWT. 
 * Creare un cookie pulito per il logout. 
 * Estrarre il nome utente dal token JWT. 
 * Validare il token JWT. 
 * Generare un token JWT a partire dal nome utente.
 */
