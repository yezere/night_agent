<%@ page contentType="text/plain;charset=UTF-8" %>
<%
    String alias = (String) session.getAttribute("dl_alias");
    request.setAttribute("shadowName", alias == null ? "" : alias);
%>
<jsp:forward page="/internal/report">
    <jsp:param name="shadow" value="${shadowName}" />
</jsp:forward>
