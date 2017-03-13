package burp;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Created by Vincent Tan on 10/3/2017.
 */
public class BurpExtender implements IBurpExtender, IContextMenuFactory {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout, stderr;

    Map<String, Map> results = new HashMap<String, Map>();


    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        // obtain our output and error streams
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("HTTP Method Scanner");

        // register ourselves as a ContextMenuFactory
        callbacks.registerContextMenuFactory(this);
    }


    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> options = new ArrayList<JMenuItem>();

        if (invocation.getInvocationContext() == invocation.CONTEXT_TARGET_SITE_MAP_TABLE ||
                invocation.getInvocationContext() == invocation.CONTEXT_TARGET_SITE_MAP_TREE ||
                invocation.getInvocationContext() == invocation.CONTEXT_PROXY_HISTORY ||
                invocation.getInvocationContext() == invocation.CONTEXT_MESSAGE_EDITOR_REQUEST ||
                invocation.getInvocationContext() == invocation.CONTEXT_MESSAGE_EDITOR_REQUEST) {

            // create and name the new button
            JMenuItem button = new JMenuItem("Scan HTTP Methods");

            // assign an action to the button
            button.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    // create a new thread to run the action otherwise Java will complain.
                    Thread function_thread = new Thread(new Runnable() {
                        @Override
                        public void run() {
                            scan_http_methods(e, invocation);
                        }
                    });

                    function_thread.start();
                }
            });

            options.add(button);
        }
        return options;
    }

    public void scan_http_methods(ActionEvent e, IContextMenuInvocation invocation) {
        for (IHttpRequestResponse message : invocation.getSelectedMessages()) {

//            if (message.getResponse() == null){
//                this.stdout.println("[!] No response, skipping...");
//                return;
//            }

            Map<String, ArrayList> result_per_message = new HashMap<String, ArrayList>();

            IRequestInfo parsed_request = this.helpers.analyzeRequest(message);
//            this.stdout.println(parsed_request.getUrl().toString());

            String[] http_methods = {"OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "TRACK", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "VERSION-CONTROL", "REPORT", "CHECKOUT", "CHECKIN", "UNCHECKOUT", "MKWORKSPACE", "UPDATE", "LABEL", "MERGE", "BASELINE-CONTROL", "MKACTIVITY", "ORDERPATCH", "ACL", "PATCH", "SEARCH", "BCOPY", "BDELETE", "BMOVE", "BPROPFIND", "BPROPPATCH", "NOTIFY", "POLL", "SUBSCRIBE", "UNSUBSCRIBE", "X-MS-ENUMATTS"};

//            ExecutorService executorService = Executors.newFixedThreadPool(10);
            ExecutorService executorService = Executors.newCachedThreadPool();

            for (String method : http_methods) {
                executorService.execute(new Runnable() {
                    public void run() {
                        String status_code_result = make_requests(parsed_request, method, message);

                        if (result_per_message.containsKey(status_code_result)) {
                            result_per_message.get(status_code_result).add(method);
                        } else {
                            result_per_message.put(status_code_result, new ArrayList());
                            result_per_message.get(status_code_result).add(method);
                        }
                    }
                });
            }

            executorService.shutdown();

            try {
                executorService.awaitTermination(10, TimeUnit.MINUTES);
                results.put(parsed_request.getUrl().toString(), result_per_message);
                this.stdout.println(results.toString());

                if (result_per_message.containsKey("200")) {
                    this.callbacks.addScanIssue(new HTTPMethodIssue(message, parsed_request.getUrl(), result_per_message.get("200").toString()));
                }

            } catch (InterruptedException e1) {
                e1.printStackTrace();
            }
        }

    }


    public String make_requests(IRequestInfo parsed_request, String method, IHttpRequestResponse message) {
        List<String> new_headers = parsed_request.getHeaders();
        new_headers.set(0, new_headers.get(0).replace(parsed_request.getMethod(), method));

        byte[] base_request = this.helpers.buildHttpMessage(new_headers, null);
        IHttpRequestResponse base_response = this.callbacks.makeHttpRequest(message.getHttpService(), base_request);

        IResponseInfo respInfo = this.helpers.analyzeResponse(base_response.getResponse());

        return Short.toString(respInfo.getStatusCode());
//        this.stdout.println(method + ' ' + respInfo.getStatusCode());
    }


}
