package burp;

import java.net.URL;

/**
 * Created by Vincent Tan on 10/3/2017.
 */
public class HTTPMethodIssue implements IScanIssue {

    private final IHttpRequestResponse[] httpMessages;
    private final URL url;
    private final String results;


    public HTTPMethodIssue(IHttpRequestResponse baseRequestResponse, URL url, String results) throws IllegalArgumentException {
        httpMessages = new IHttpRequestResponse[]{baseRequestResponse};
        this.url = url;
        this.results = results;
    }

    @Override
    public String getIssueName() {
        return "HTTP Methods Discovered";
    }

    @Override
    public String getIssueBackground() {
        return "A Web Server can respond to different HTTP Methods. Some methods are considered dangerous if not properly secured.";
    }

    @Override
    public String getIssueDetail() {
        return "HTTP Methods found support on this URL: " + results;
    }

    @Override
    public String getSeverity() {
        return "Information";
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getRemediationDetail() {
        return "Modify the server to accept only the HTTP Methods required for normal application functionality";
    }

    @Override
    public String getConfidence() {
        return "Firm";
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpMessages[0].getHttpService();
    }

    @Override
    public int getIssueType() {
        return 0x08000000; // Extension Generated Issue
    }

    @Override
    public URL getUrl() {
        return url;
    }





}

//    @Override public String getIssueDetail() {
//        int v = uuid.version();
//        final String prefix = "The request contains the version " + v +
//                " UUID <b>" + uuid + "</b> which is ";
//        switch (v) {
//            case 1:
//                StringBuilder mac = new StringBuilder(6 * 3);
//                for (long n = uuid.node(); n > 0; n >>= 8) mac.insert(0,
//                        String.format(":%02X", n & 0xFF));
//                return prefix + "generated from <ul>" +
//                        "<li>the timestamp <b>" + new Date(getTimeFromUUID(uuid)) + "</b>,</li>" +
//                        "<li>the clock sequence <b>" + uuid.clockSequence() + "</b> and</li>" +
//                        "<li>the node (MAC address) <b>" + mac.substring(1) + "</b>.</li>" +
//                        "</ul>This means that it's not fit for authorization purposes, as " +
//                        "it can be easily regenerated once the node and the approximate time is known.";
//            case 2:
//                return prefix + "generated using the DCE algorithm from a " +
//                        "timestamp, a clock sequence, a domain ID and a node value. " +
//                        "This means that it's not fit for authorization purposes, as " +
//                        "it can be easily regenerated once the node and the approximate time is known.";
//            case 3:
//                return prefix + "derived from a name using MD5.";
//            case 4:
//                return prefix + "randomly generated, although its entropy should be checked.";
//            case 5:
//                return prefix + "derived from a name using SHA-1.";
//            default:
//                return prefix + "generated/derived from an unknown data source.";
//        }
//    }
//
