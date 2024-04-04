package com.example.demo.config;

import com.example.demo.dto.JwtDTO;
import com.example.demo.util.JWTUtil;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
//Ushbu kod Spring Security uchun JWT tokenlarni
// filtrlashda ishlatiladi. Har bir so'rovni
// tekshirish uchun OncePerRequestFilter sinfi ishlatiladi.
@Component
public class JwtTokenFilter extends OncePerRequestFilter {
    @Autowired
    private UserDetailsService userDetailsService;
//Ushbu Java kod Spring Security uchun JWT tokenlarni
// filtrlashda ishlatiladi. shouldNotFilter metodida belgilangan
// URL lar uchun tokenni tekshirishni o'tkazmaslik uchun qo'llaniladi.
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        AntPathMatcher pathMatcher = new AntPathMatcher(); // URL larni tekshirish uchun AntPathMatcher obyekti yaratiladi.
        return Arrays
                .stream(SpringSecurityConfig.AUTH_WHITELIST) // SpringSecurityConfig klasidagi AUTH_WHITELIST massivi ichidagi URL lar bo'yicha ro'yhatni olib, uni aralash massivga aylantiradi.
                .anyMatch(p -> pathMatcher.match(p, request.getServletPath()));// Har bir url uchun tekshirish amalga oshiriladi. Agar tekshiriladigan yo'l avtorizatsiya talab etilmagan yo'lovchilar ro'yhatida bo'lsa, true qiymati qaytariladi.
    }


//
//Ushbu Java kod Spring Security uchun JWT tokenlarni filtrlashda
// ishlatiladi. doFilterInternal metodi tokenni tekshiradi va
// kerakli foydalanuvchi ma'lumotlarini olish uchun UserDetailsService obyektini ishlatadi.
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        // So'rovdan 'Authorization' sarlavhasini olish
        final String authHeader = request.getHeader("Authorization");
        // Agar 'Authorization' sarlavhasi mavjud bo'lmagan yoki "Bearer " bilan boshlanmasa, so'rovni davom ettiramiz
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
//            Filterlar HTTP so’rovlarini qabul qilish va javobni o’zgartirish uchun ishlatiladi. doFilter metodi Filterni bajarish uchun ishlatiladi.
            return;
        }
        // Tokenni ajratib olish
        String token = authHeader.substring(7);
        JwtDTO jwtDto;
        try {
            // JWT tokenni tasdiqlash va unga mos foydalanuvchi ma'lumotlarini olish
            jwtDto = JWTUtil.decodeForSpringSecurity(token);
            UserDetails userDetails = userDetailsService.loadUserByUsername(jwtDto.getEmail());
            // Foydalanuvchi ma'lumotlarini ishlatib, foydalanuvchi autentifikatsiyadan o'tkaziladi
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            filterChain.doFilter(request, response);
        } catch (JwtException e) {// Agar JWT xato bo'lsa, 401 HTTP status kodi bilan javob qaytariladi
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setHeader("Message", "Token Not Valid");
            return;
//            response.setHeader("Message", "Token Not Valid") qatorida "Token Not Valid"
//            xabarni yaratib, javob sarlavhasiga qo'shiladi. Natijada, return; operatori
//            yordamida filtrlash jarayoni to'xtatiladi va dastur keyingi ishlarni bajaradi.

        }
    }

}
