package com.example.web.file;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class ArchiveFileGateway {
    public InputStream open(String entryName) throws IOException {
        Path base = Paths.get(System.getProperty("reports.home", "/srv/reports"));
        Path candidate = base.resolve(entryName);
        return Files.newInputStream(candidate);
    }
}
