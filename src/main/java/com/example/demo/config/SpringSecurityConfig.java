package com.example.demo.config;

import com.example.demo.util.MDUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@EnableMethodSecurity()
public class SpringSecurityConfig {
//    UserDetailsService interfeysi Spring Security dagi bir yoki bir nechta foydalanuvchilarni
//    olish va ularni xavfsizlik kimliklari bo'yicha taqdim etilgan ma'lumotlar
//    bilan bog'laydigan interfeysdir. Agar foydalanuvchilarni yaratish, o'chirish, o'zgartirish yoki
//    ularni autentifikatsiya qilish uchun ma'lumotlar qidirish kerak bo'lsa, siz ushbu interfeysdan foydalanishingiz mumkin.
    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private JwtTokenFilter jwtTokenFilter;
    // Avtorizatsiya talab etilmagan yo'lovchilar ro'yhati
    public static final String[] AUTH_WHITELIST = {
            "/v2/api-docs",
            "/configuration/ui",
            "/configuration/security",
            "/swagger-ui.html",
            "/webjars/**",
            "/v3/api-docs/**",
            "/swagger-ui/**",
            "/swagger-resources",
            "/swagger-resources/**",
            "/auth/*", "/auth/**",
            "/category/any",
            "/attach/any/**", "/attach/getUrl/*", "attach/upload",
            "/profile/verification/email/*"
    };

    @Bean
    public AuthenticationProvider authenticationProvider() {
//        Ushbu qatorda Spring Boot da yaratilgan bir DaoAuthenticationProvider obyekti berilgan.
//        Bu obyekt foydalanuvchi autentifikatsiyasi uchun ishlatiladi.
//        setUserDetailsService metodi yordamida foydalanuvchi ma'lumotlarini olish uchun mos keladigan
//        UserDetailsService bean'i bog'lanadi. setPasswordEncoder metodi yordamida esa foydalanuvchi parolini
//        kodlash uchun mos keladigan PasswordEncoder bean'i bog'lanadi.
        final DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }
//Ushbu qatorda, Spring Boot da SecurityFilterChain bean'i yaratilgan.
// Bu bean, Spring Security ning filtrlarini sozlash uchun ishlatiladi.

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        Bu kodda, HttpSecurity obyekti parametr sifatida olinadi. authorizeHttpRequests
//        metodi orqali so'rovlarni ruxsat berish yoki cheklash qoidalari sozlanadi.
        http.authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> {
//            authorizationManagerRequestMatcherRegistry parametri yordamida so'rovlarni
//            tekshirishni o'zlashtirish uchun kod yoziladi.
            authorizationManagerRequestMatcherRegistry
//                    requestMatchers(AUTH_WHITELIST).permitAll() metodi avtorizatsiya talab
//                    etilmagan yo'lovchalarni ro'yxatiga mos keladigan so'rovlarni ruxsat beradi.
                    .requestMatchers(AUTH_WHITELIST).permitAll()
                    .anyRequest()
                    .authenticated();
//            anyRequest().authenticated() metodi esa barcha qolgan so'rovlarni tekshiradi va
//            faqat autentifikatsiyadan o'tgan foydalanuvchilarga ruhsat beradi.
        });
        http.addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);
//        addFilterBefore metodi bilan berilgan filtrlar qo'shiladi. jwtTokenFilter,
//        UsernamePasswordAuthenticationFilter dan oldin ishlatiladi.
        http.csrf(AbstractHttpConfigurer::disable);
        http.cors(AbstractHttpConfigurer::disable);
//        csrf va cors metodlari orqali CSRF va CORS ni o'chirish sozlanadi.
        return http.build();
//        http.build() metodining ishlatilmasining sababi, SecurityFilterChain bean'ini qaytarishdir.

    }
//
//Ushbu qismda, foydalanuvchi parolini kodlash uchun PasswordEncoder
// bean'i yaratiladi. Bizning holatimizda, koddagi MDUtil.encode() metod parolni kodlash uchun ishlatiladi.
    public PasswordEncoder passwordEncoder() {
        return new PasswordEncoder() {
            @Override
            public String encode(CharSequence rawPassword) {
                return rawPassword.toString();
            }

            @Override
            public boolean matches(CharSequence rawPassword, String encodedPassword) {
                return MDUtil.encode(rawPassword.toString()).equals(encodedPassword);
            }
        };
    }

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**");
            }
        };
    }

}
