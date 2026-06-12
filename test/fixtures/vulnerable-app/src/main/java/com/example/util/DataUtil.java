package com.example.util;

import com.alibaba.fastjson.JSON;
import java.io.ObjectInputStream;

public class DataUtil {

    public static <T> T parseJson(String json, Class<T> clazz) {
        // Fastjson deserialization
        return JSON.parseObject(json, clazz);
    }

    public static Object readObject(ObjectInputStream in) throws Exception {
        // Insecure deserialization
        return in.readObject();
    }
}
