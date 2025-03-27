package ru.neoflex.wso2.blitz.client;

import java.util.Random;

public class PasswordGenerator {
    private static final Random random = new Random();

    public static String generatePassword() {
        StringBuilder password = new StringBuilder();
        for (int i = 0; i < BlitzConstants.PASSWORD_LENGTH; i++) {
            password.append(getRandomChar(BlitzConstants.AVAILABLE_SYMBOLS));
        }
        return password.toString();
    }

    private static char getRandomChar(String availableSymbols) {
        int randomIndex = random.nextInt(availableSymbols.length());
        return availableSymbols.charAt(randomIndex);
    }
}
