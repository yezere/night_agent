package com.example.web;

import com.example.web.flow.ShadowName;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AliasServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String value = request.getParameter("k");
        request.getSession(true).setAttribute("dl_alias", ShadowName.stage(value));
        RequestDispatcher dispatcher = request.getRequestDispatcher("/WEB-INF/views/bridge.jsp");
        dispatcher.forward(request, response);
    }
}
