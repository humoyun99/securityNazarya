package com.example.demo.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MDUtil {
//    encode - Matnni MD5 formatiga kodlash uchun ishlatiladi.
//    Matn beriladi va uni MD5 shifrlash uchun kodlaydi.
    public static String encode(String password) {
        try {
//            MessageDigest.getInstance("MD5"): MD5 shifrlash algoritmini
//            olish uchun MessageDigest obyekti yaratiladi.
            MessageDigest md = MessageDigest.getInstance("MD5");
//            md.digest(password.getBytes()): Berilgan matnning baytlarini
//            MD5 algoritmi orqali shifrlaydi.
            byte[] array = md.digest(password.getBytes());
//            StringBuilder sb = new StringBuilder(): Matnlar
//            ustida amal qilish uchun StringBuilder obyekti yaratiladi.
            StringBuilder sb = new StringBuilder();
//            for (byte b : array): Shifrlangan baytlarning
//            har biri uchun sikl ochiladi.
            for (byte b : array) {
//                sb.append(Integer.toHexString((b & 0xFF) | 0x100), 1, 3): Baytlarni
//                hexadecimal formatda kodlab, 2 raqamli belgilarni qo`shib chiqadi.
                sb.append(Integer.toHexString((b & 0xFF) | 0x100), 1, 3);
            }
//            return sb.toString(): Shifrlangan matnni Stringga aylantirib, uni qaytaradi.
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return "";
    }
}
