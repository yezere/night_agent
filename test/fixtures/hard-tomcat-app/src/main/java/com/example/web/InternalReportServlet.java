package com.example.web;

import com.example.web.flow.ShadowName;
import com.example.web.file.ArchiveFileGateway;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;

public class InternalReportServlet extends HttpServlet {
    private final ArchiveFileGateway archiveGateway = new ArchiveFileGateway();

    @Override
    protected void service(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String shadow = request.getParameter("shadow");
        String entry = ShadowName.restore(shadow);
        response.setContentType("application/octet-stream");
        try (InputStream in = archiveGateway.open(entry);
             ServletOutputStream out = response.getOutputStream()) {
            in.transferTo(out);
        }
    }
}
