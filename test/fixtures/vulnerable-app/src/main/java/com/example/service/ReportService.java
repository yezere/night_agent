package com.example.service;

import java.io.*;
import java.sql.Statement;

public class ReportService {

    public void generateReport(String templatePath, Object data) throws Exception {
        // SSTI: Freemarker Template.process
        freemarker.template.Template tpl = new freemarker.template.Template("report", new StringReader(""), null);
        tpl.process(data, new java.io.StringWriter());
    }

    public void queryDatabase(String sql, Statement stmt) throws Exception {
        // SQL Injection
        stmt.execute(sql);
    }

    public void readUserFile(String path) throws Exception {
        // Path Traversal
        File file = new File(path);
    }
}
