package jar;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;

/**
 * Created by Suavek on 14/03/2017.
 */
public class CRHttpServer {

    public CRHttpServer(int portNumber) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(portNumber), 0);
        server.createContext("/", new CRHttpServer.InfoHandler());
        server.createContext("/caroot.cer", new CRHttpServer.GetCACertificateHandler());
        server.createContext("/ra.cer", new CRHttpServer.GetRACertificateHandler());
        server.createContext("/va.cer", new CRHttpServer.GetVACertificateHandler());
        server.createContext("/repository.cer", new CRHttpServer.GetRepositoryCertificateHandler());
        server.createContext("/certificaterevocationlist.crl", new CRHttpServer.GetCRLHandler());
        server.createContext("/get", new CRHttpServer.GetCertificateHandler());
        server.setExecutor(Executors.newCachedThreadPool()); // creates a default executor
        server.start();
        System.out.println(">>>>> The service is running.");
    }

    private class InfoHandler implements HttpHandler {
        public void handle(HttpExchange httpExchange) throws IOException {
            StringBuilder response = new StringBuilder();
            String url = "http://" + Configuration.get("IP_REPOSITORY") + ":" + Configuration.get("PORT_REPOSITORY_HTTP");
            response.append("<html><body>");
            response.append("<h3>System Certificates:</h3>");
            String certCA = url + "/caroot.cer";
            response.append("<p>1.  : <a href=" + certCA + ">Root Certification Authority </a></p>");
            String certRA = url + "/ra.cer";
            response.append("<p>2.  : <a href=" + certRA + ">Registration Authority</a></p>");
            String certVA = url + "/va.cer";
            response.append("<p>3.  : <a href=" + certVA + ">Validation Authority </a></p>");


            response.append("<h3>Certificate Revocation List:</h3>");
            String crl = url + "certificaterevocationlist.crl";
            response.append("<p>1.  : <a href=" + crl + ">Certificate Revocation List</a></p>");

            response.append("<h3>User Certificates:</h3>");
            response.append("<p>1.  : " + url + "/get?CN=<font color =\"red\">subject</font></p>");


            response.append("<p>2.  : Click the button to make the query" +
                    "        <button onclick=\"myFunction()\">Get Certificate</button>\n" +
                    "        <p id=\"certquery\"></p>\n" +
                    "        <script>\n" +
                    "         function myFunction()\n" +
                    "         {\n" +
                    "            var x;\n" +
                    "            var person=prompt(\"Subject Common Name:\",\"\");\n" +
                    "            if (person!=null)\n" +
                    "            {\n" +
                    "               window.location = '" + url + "/get?CN='+person;" +
                    "              }\n" +
                    "            }\n" +
                    "        </script>");

            response.append("</body></html>");
            writeResponse(httpExchange, response.toString().getBytes());
        }
    }

    private class GetCACertificateHandler implements HttpHandler {
        public void handle(HttpExchange httpExchange) throws IOException {
            String caCertAlias = Configuration.get("CA_KS_ALIAS_CERT");
            try {
                X509Certificate cert = RepositoryUtils.getCertificate(caCertAlias);
                byte[] data = cert.getEncoded();
                writeResponse(httpExchange, cert.getEncoded());
            } catch (Exception e) {
                String msg = "Could not retrieve root certificate";
                writeResponse(httpExchange, msg.getBytes());
            }
        }
    }

    private class GetRACertificateHandler implements HttpHandler {
        public void handle(HttpExchange httpExchange) throws IOException {
            String raCertAlias = Configuration.get("RA_KS_ALIAS_CERT");
            try {
                X509Certificate cert = RepositoryUtils.getCertificate(raCertAlias);
                byte[] data = cert.getEncoded();
                writeResponse(httpExchange, cert.getEncoded());
            } catch (Exception e) {
                String msg = "Could not retrieve RA certificate";
                writeResponse(httpExchange, msg.getBytes());
            }
        }
    }

    private class GetVACertificateHandler implements HttpHandler {
        public void handle(HttpExchange httpExchange) throws IOException {
            String caCertAlias = Configuration.get("VA_KS_ALIAS_CERT");
            try {
                X509Certificate cert = RepositoryUtils.getCertificate(caCertAlias);
                byte[] data = cert.getEncoded();
                writeResponse(httpExchange, cert.getEncoded());
            } catch (Exception e) {
                String msg = "Could not retrieve VA certificate";
                writeResponse(httpExchange, msg.getBytes());
            }
        }
    }

    private class GetRepositoryCertificateHandler implements HttpHandler {
        public void handle(HttpExchange httpExchange) throws IOException {
            String repositoryCertAlias = Configuration.get("REPOSITORY_KS_ALIAS_CERT");
            try {
                X509Certificate cert = RepositoryUtils.getCertificate(repositoryCertAlias);
                byte[] data = cert.getEncoded();
                writeResponse(httpExchange, cert.getEncoded());
            } catch (Exception e) {
                String msg = "Could not retrieve repository certificate";
                writeResponse(httpExchange, msg.getBytes());
            }
        }
    }

    private class GetCRLHandler implements HttpHandler {
        public void handle(HttpExchange httpExchange) throws IOException {
            writeResponse(httpExchange, RepositoryUtils.getCRL().getEncoded());
        }
    }

    private class GetCertificateHandler implements HttpHandler {
        public void handle(HttpExchange httpExchange) throws IOException {

            Map<String, String> query = queryToMap(httpExchange.getRequestURI().getQuery());
            String certSubject = query.get("CN");
            try {
                X509Certificate cert = RepositoryUtils.getCertificate(certSubject);
                if (cert == null) throw new Exception("Could not retrieve certificate");
                httpExchange.getResponseHeaders().add("Content-Disposition", "attachment; filename=" + certSubject + ".cer");
                writeResponse(httpExchange, cert.getEncoded());
            } catch (Exception e) {
                String msg = e.getMessage();
                writeResponse(httpExchange, msg.getBytes());
            }
        }
    }

    private void writeResponse(HttpExchange httpExchange, byte[] response) throws IOException {
        httpExchange.sendResponseHeaders(200, response.length);
        OutputStream os = httpExchange.getResponseBody();
        os.write(response);
        os.close();
    }

    /**
     * returns the url parameters in a map
     *
     * @param query
     * @return map
     */
    public Map<String, String> queryToMap(String query) {
        Map<String, String> result = new HashMap<String, String>();
        for (String param : query.split("&")) {
            String pair[] = param.split("=");
            if (pair.length > 1) {
                result.put(pair[0], pair[1]);
            } else {
                result.put(pair[0], "");
            }
        }
        return result;
    }

}
