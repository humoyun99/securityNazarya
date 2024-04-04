package com.example.demo.util;

import com.example.demo.dto.JwtDTO;
import com.example.demo.enums.ProfileRole;
import io.jsonwebtoken.*;

import javax.crypto.spec.SecretKeySpec;
import java.util.Date;

public class JWTUtil {
    private static final int tokenLiveTime = 1000 * 3600 * 24; // 1-day
    private static final int emailTokenLiveTime = 1000 * 3600; // 1-hour
    private static final String secretKey = "mazgissddfskfekssssssssssssssssssssssssssssssssssssssssssssssssssssfkekekgekgkegkekerkgkegkrkgrkgkrgkrgkrkkrgkrkrkgnrgrgjrgkjrkjfdjekfekf";
//Ushbu Java kodining maqsadi foydalanuvchi
// profili ID va rolini o'z ichiga olgan JWT (JSON Web Token) yaratishdir.
    public static String encode(Integer profileId, ProfileRole role) {
        JwtBuilder jwtBuilder = Jwts.builder();// JWT yaratish uchun builder obyekti yaratiladi.
        jwtBuilder.issuedAt(new Date());// Tokenning berilgan sanada yaratilganini belgilaydi.
        SignatureAlgorithm sa = SignatureAlgorithm.HS512;// Shifrlash algoritmi tanlanadi.
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), sa.getJcaName());// Maxfiy kalit o`zgaruvchisi yaratiladi
        jwtBuilder.signWith(secretKeySpec);// Maxfiy kalit bilan imzolanadi.
        jwtBuilder.claim("id", profileId);// JWT da foydalanuvchi ID si kiritiladi.
        jwtBuilder.claim("role", role);// JWT da foydalanuvchi roli kiritiladi.
        jwtBuilder.expiration(new Date(System.currentTimeMillis() + (tokenLiveTime)));// Tokenning amal qilish muddati sozlanadi.
        jwtBuilder.issuer("Youtube");// JWT ning ishlab chiqaruvchisi sozlanadi.
        return jwtBuilder.compact();// JWT ni kompakt xususiyatida qaytaradi.
    }

//Ushbu Java funksiya berilgan JWT ni ajratib o'qib, uning ma'lumotlarini
// tahlil qiladi va shu asosda JwtDTO obyektini qaytaradi.
    public static JwtDTO decode(String token) {
        SignatureAlgorithm sa = SignatureAlgorithm.HS512;// Shifrlash algoritmi tanlanadi.
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), sa.getJcaName()); // Maxfiy kalit o`zgaruvchisi yaratiladi
        JwtParser jwtParser = Jwts.parser()
                .verifyWith(secretKeySpec)// Maxfiy kalit bilan tasdiqlanadi.
                .build();

        Jws<Claims> jws = jwtParser.parseSignedClaims(token);// JWT ni ajratib o'qib, o'zgaruvchiga o'zlashtiriladi.
        Claims claims = jws.getPayload();// JWT ning ma'lumotlari o'zgaruvchiga o'zlashtiriladi.

        Integer id = (Integer) claims.get("id");// JWT dan foydalanuvchi ID si olinadi.
        String role = (String) claims.get("role");// JWT dan foydalanuvchi roli olinadi.
        if (role != null) {
            ProfileRole profileRole = ProfileRole.valueOf(role);// Foydalanuvchi rolini ProfileRole enumiga aylantiradi.
            return new JwtDTO(id, profileRole);// JWT dan foydalanuvchi ID si va roli bilan JwtDTO obyekti yaratiladi.
        }
        return new JwtDTO(id);// JWT dan foydalanuvchi ID si bilan JwtDTO obyekti yaratiladi.
    }
//Ushbu Java funksiya elektron pochta uchun berilgan foydalanuvchi
// profili ID sini o'z ichiga olgan JWT ni yaratadi.
    public static String encodeForEmail(Integer profileId) {
        JwtBuilder jwtBuilder = Jwts.builder(); // JWT yaratish uchun builder obyekti yaratiladi.
        jwtBuilder.issuedAt(new Date());// Tokenning berilgan sanada yaratilganini belgilaydi.
        SignatureAlgorithm sa = SignatureAlgorithm.HS512;// Shifrlash algoritmi tanlanadi.
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), sa.getJcaName());// Maxfiy kalit o`zgaruvchisi yaratiladi.
        jwtBuilder.signWith(secretKeySpec);// Maxfiy kalit bilan imzolanadi.
        jwtBuilder.claim("id", profileId);// JWT da foydalanuvchi ID si kiritiladi.
        jwtBuilder.expiration(new Date(System.currentTimeMillis() + (emailTokenLiveTime)));// Tokenning amal qilish muddati sozlanadi.
        jwtBuilder.issuer("Youtube");// JWT ning ishlab chiqaruvchisi sozlanadi.
        return jwtBuilder.compact();// JWT ni kompakt xususiyatida qaytaradi.
    }

//Ushbu Java funksiya berilgan JWT ni ajratib o'qib, uning ma'lumotlarini tahlil qiladi
// va Spring xavfsizlik tizimi uchun foydalanuvchi ma'lumotlarini JwtDTO obyektiga o'zlashtiradi.
    public static JwtDTO decodeForSpringSecurity(String token) {
        SignatureAlgorithm sa = SignatureAlgorithm.HS512;// Shifrlash algoritmi tanlanadi.
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), sa.getJcaName());// Maxfiy kalit o`zgaruvchisi yaratiladi.
        JwtParser jwtParser = Jwts.parser()
                .verifyWith(secretKeySpec)// Maxfiy kalit bilan tasdiqlanadi.
                .build();
        Jws<Claims> jws = jwtParser.parseSignedClaims(token);// JWT ni ajratib o'qib, o'zgaruvchiga o'zlashtiriladi.
        Claims claims = jws.getPayload();// JWT ning ma'lumotlari o'zgaruvchiga o'zlashtiriladi.
        String email = (String) claims.get("email");// JWT dan foydalanuvchi e-mail manzili olinadi.
        String role = (String) claims.get("role");// JWT dan foydalanuvchi roli olinadi.
        ProfileRole profileRole = ProfileRole.valueOf(role);// Foydalanuvchi rolini ProfileRole enumiga aylantiradi.
        return new JwtDTO(email, profileRole);// Foydalanuvchi e-mail manzili va roli bilan JwtDTO obyekti yaratiladi.
    }

    public static String encode(String email, ProfileRole role) {
        JwtBuilder jwtBuilder = Jwts.builder();
        jwtBuilder.issuedAt(new Date());
        SignatureAlgorithm sa = SignatureAlgorithm.HS512;
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), sa.getJcaName());
        jwtBuilder.signWith(secretKeySpec);
        jwtBuilder.claim("email", email);
        jwtBuilder.claim("role", role);
        jwtBuilder.expiration(new Date(System.currentTimeMillis() + (tokenLiveTime)));
        jwtBuilder.issuer("Youtube");
        return jwtBuilder.compact();
    }

}
