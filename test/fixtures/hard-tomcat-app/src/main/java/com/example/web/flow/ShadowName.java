package com.example.web.flow;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

public final class ShadowName {
    private ShadowName() {
    }

    public static String stage(String value) {
        if (value == null) return "";
        return new StringBuilder(value.trim()).reverse().toString();
    }

    public static String restore(String value) {
        String reversed = new StringBuilder(value == null ? "" : value).reverse().toString();
        return URLDecoder.decode(reversed, StandardCharsets.UTF_8);
    }
}
