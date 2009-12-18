package com.ign.oauth.filter;

import com.ign.oauth.model.Consumer;
import com.ign.oauth.util.PersistenceService;
import java.io.IOException;
import java.util.StringTokenizer;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.*;
import javax.ws.rs.core.Response;
import javax.persistence.EntityManager;
import net.oauth.*;
import net.oauth.signature.RSA_SHA1;
import net.oauth.server.OAuthServlet;
import net.oauth.server.HttpRequestMessage;
import org.apache.log4j.Logger;

public class OAuthFilter implements Filter {
    private static final Logger logger = Logger.getLogger(OAuthFilter.class);
    private String[] httpMethods;

    public void init(FilterConfig config) throws ServletException {
        if (config.getInitParameter("httpMethods") != null && !"".equals(config.getInitParameter("httpMethods"))) {
            StringTokenizer strTok = new StringTokenizer(config.getInitParameter("httpMethods"), ",");
            httpMethods = new String[strTok.countTokens()];
            int i = 0;
            while (strTok.hasMoreTokens()) {
                httpMethods[i++] = strTok.nextToken().trim();
            }
        }
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException {
        HttpServletRequest hsRequest = (HttpServletRequest) request;
        HttpServletResponse hsResponse = (HttpServletResponse) response;

        Response.Status status = validateRequest(hsRequest);

        if (status.equals(Response.Status.OK)) {
            chain.doFilter(request, response);
        } else {
            hsResponse.setStatus(status.getStatusCode());
        }
    }

    public void destroy() {
        // Nothing here.
    }

    /**
     * Validates the request.
     *
     * @param request the request to be validated.
     * @return <code>true</code> if the request validates properly, otherwise, <code>null</code>
     */
    private Response.Status validateRequest(HttpServletRequest request) {
        Response.Status status;

        if (requireValidation(request.getMethod())) {
            if (request != null) {
                OAuthMessage message = new HttpRequestMessage(request, getRequestUrl(request));
                String consumerKey;

                try {
                    consumerKey = message.getConsumerKey();
                    if (consumerKey != null && !"".equals(consumerKey)) {
                        EntityManager em = PersistenceService.getInstance().getEntityManager();
                        Consumer consumer = em.find(Consumer.class, consumerKey);

                        if (consumer != null) {
                            OAuthConsumer OAuthConsumer;

                            if (message.getSignatureMethod() != null && !"".equals(message.getSignatureMethod())
                                && message.getSignatureMethod().equalsIgnoreCase(OAuth.RSA_SHA1)) {
                                OAuthConsumer = new OAuthConsumer(null, consumerKey, null, null);
                                OAuthConsumer.setProperty(
                                    RSA_SHA1.PUBLIC_KEY, getCleanRSAPublicKey(consumer.getConsRSAKey()));
                            } else if (message.getSignatureMethod() != null && !"".equals(message.getSignatureMethod())
                                && message.getSignatureMethod().equalsIgnoreCase(OAuth.HMAC_SHA1)) {
                                OAuthConsumer = new OAuthConsumer(null, consumerKey, consumer.getConsSecret(), null);
                            } else {
                                logger.warn("A null or unsupported signature method: "
                                    + message.getSignatureMethod() + " has been detected.");
                                return Response.Status.BAD_REQUEST;
                            }

                            OAuthConsumer.setProperty(OAuth.OAUTH_SIGNATURE_METHOD, message.getSignatureMethod());
                            OAuthAccessor accessor = new OAuthAccessor(OAuthConsumer);

                            message.validateMessage(accessor, new SimpleOAuthValidator());

                            // The authentication process have been successful if the code gets here without any exceptions.
                            status = Response.Status.OK;
                        } else {
                            logger.warn("Authentication has failed due to the consumer key "
                                + consumerKey + " does not exist in the database. ");
                            status = Response.Status.UNAUTHORIZED;
                        }
                    } else {
                        logger.warn("Authentication has failed due to the consumer key does not exist in the HTTP request header. ");
                        status = Response.Status.UNAUTHORIZED;
                    }
                } catch (OAuthProblemException ope) {
                    logger.warn("Authentication has failed due to an OAuthValidationException: "
                        + OAuthServlet.htmlEncode(ope.getProblem()));
                    status = Response.Status.UNAUTHORIZED;
                } catch (Exception e) {
                    logger.warn("Authentication has failed due to an exception occurred when looking up an OAuthConsumer object: "
                        + e.getMessage());
                    status = Response.Status.UNAUTHORIZED;
                }
            } else {
                logger.warn("Authentication has failed due to a null HTTPRequest object has been detected. ");
                status = Response.Status.BAD_REQUEST;
            }
        } else {
            status = Response.Status.OK;
        }
        return status;
    }

    /**
     * Constructs and returns the full URL associated with the passed request object.
     *
     * @param request the HttpServletRequest object
     * @return the requestURL.
     */
    private String getRequestUrl(HttpServletRequest request) {
        StringBuffer sb = request.getRequestURL();
        if (request.getQueryString() != null) {
            sb.append("?").append(request.getQueryString());
        }
        return sb.toString();
    }

    /**
     * Helper method to remove the public key header and footer.
     *
     * @param publicKey the public key String
     * @return a clean RSAPublicKey if successful, otherwise, it returns <code>false</code>
     */
    private String getCleanRSAPublicKey(String publicKey) {
        String returnValue;
        final String HEADER = "-----BEGIN PUBLIC KEY-----";
        final String FOOTER = "-----END PUBLIC KEY-----";

        if (publicKey != null && !"".equals(publicKey)) {
            int headerIndex = publicKey.indexOf(HEADER);
            if (headerIndex != -1) {
                publicKey = publicKey.substring(headerIndex + HEADER.length());
            }
            int footerIndex = publicKey.indexOf(FOOTER);
            if (footerIndex != -1) {
                publicKey = publicKey.substring(0, footerIndex);
            }
            returnValue = publicKey;
        } else {
            returnValue = null;
        }
        return returnValue;
    }

    /**
     * Determine if the HTTP Method requires validation.
     *
     * @param requestHttpMethod the method to be validated
     * @return <code>true</code> if the method requires validation, otherwise it returns <code>false</code>.
     */
    private boolean requireValidation(String requestHttpMethod) {
        boolean returnValue = false;
        if (httpMethods != null && httpMethods.length > 0) {
            for (String httpMethod : httpMethods) {
                if (httpMethod.equalsIgnoreCase(requestHttpMethod)) {
                    returnValue = true;
                    break;
                }
            }
        }
        return returnValue;
    }
}