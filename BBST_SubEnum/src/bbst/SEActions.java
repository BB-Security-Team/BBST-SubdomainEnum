/**
 * $Project (c) Bug Busters Security Team 2020
 */
package bbst;

import com.google.gson.Gson;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

public class SEActions extends SETabForm {

    List<String> domainList = new ArrayList<>();
    List<String> aliveDomainList = new ArrayList<>();

    protected SwingWorker<Void, Void> queueWorker = null;
    protected SEnumQueueMutex queueWorkerMutex = new SEnumQueueMutex(true);
    protected int checkQueueTableCurrentRow = 0;

    public SEActions () {
        enumButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                String domain = domainTextField.getText();
                if (domain.equals("") && enumButton.getText().equals("Enumerate")) {
                    alertMsg("Domain field is empty!");
                } else {
                    if (enumButton.getText().equals("Enumerate")) {
                        checkQueueTableModel.addRow(new Object[]{domain, "Queued"});
                        queueWorkerMutex.resume();
                        enumButton.setText("Pause");
                    } else if (enumButton.getText().equals("Pause")) {
                        queueWorkerMutex.pause();
                        enumButton.setText("Resume");
                    } else if (enumButton.getText().equals("Resume")) {
                        queueWorkerMutex.resume();
                        enumButton.setText("Pause");
                    }
                }
            }
        });
        // XXX: make swingworker https://stackoverflow.com/questions/17391239/process-other-gui-events-while-in-a-loop
        // XXX: http://chuwiki.chuidiang.org/index.php?title=Ejemplo_sencillo_con_SwingWorker
        // XXX: http://www.java2s.com/Tutorials/Java/Swing_How_to/SwingWorker/Start_and_stop_SwingWorker.htm
        queueWorker = new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() {
                while (!isCancelled()) {
                    try {
                        queueWorkerMutex.step();
                        if (checkQueueTableCurrentRow < checkQueueTableModel.getRowCount()) {
                            String domain = (String) checkQueueTableModel.getValueAt(checkQueueTableCurrentRow, 0);
                            List<String> subdomains = doEnumeration(domain);
                            if (subdomains.size() == 0) {
                                checkQueueTableUpdateCurrentRow(new Object[]{null, "No subdomains"});
                            } else {
                                checkQueueTableUpdateCurrentRow(new Object[]{null, "Checking results..."});
                                //System.out.println(subdomains);
                                checkAndUpdateDomainList(subdomains);
                                checkQueueTableUpdateCurrentRow(new Object[]{null, "Done"});
                            }
                            checkQueueTableCurrentRow++;
                        }
                        Thread.sleep(10, 300);
                        enumButton.setText("Enumerate");
                    } catch (Exception e) {
                        checkQueueTableUpdateCurrentRow(new Object[]{null, e.getMessage()});
                        enumButton.setText("Resume");
                    } finally {
                        queueWorkerMutex.pause();
                    }
                }
                return null;
            }
        };
    }

    private void alertMsg(String msg) {
        JOptionPane.showMessageDialog(null, msg, extensionName + " Alert", JOptionPane.INFORMATION_MESSAGE);
    }

    private void errorMsg(String msg) {
        JOptionPane.showMessageDialog(null, msg, extensionName + " Error", JOptionPane.INFORMATION_MESSAGE);
    }

    private void checkQueueTableUpdateCurrentRow(Object[] row) {
        if (checkQueueTableModel.getRowCount() > checkQueueTableCurrentRow) {
            for (int col = 0; col < row.length; col++) {
                if (row[col] != null) { /* skip null values because this is Update, use Delete instead of */
                    checkQueueTableModel.setValueAt(row[col], checkQueueTableCurrentRow, col);
                }
            }
        }
    }

    private void checkAndUpdateDomainList(List<String> domlist) {
        domlist.forEach(new Consumer<String>() {
            @Override
            public void accept(String domain) {
                try {
                    queueWorkerMutex.step();
                    if (!domainList.contains(domain)) {
                        domainList.add(domain);
                        checkIsDomainAlive(domain);
                    }
                } catch (InterruptedException e) {
                } catch (IOException e) {
                }
            }
        });
    }

    private void checkIsDomainAlive(String domain) throws IOException, InterruptedException {
        String file = "/";
        String protocol = "http";
        int port = 80;
        checkIsDomainAliveGET(protocol, domain, port, file);
        protocol = "https";
        port = 443;
        checkIsDomainAliveGET(protocol, domain, port, file);
    }

    private void checkIsDomainAliveGET(String protocol, String domain, int port, String file) throws IOException, InterruptedException {
        int status_code = 0;
        queueWorkerMutex.step();

        Thread.sleep(10, 300);

        OkHttpClient client = new OkHttpClient.Builder().connectTimeout(3, TimeUnit.SECONDS).build();

        Request request = new Request.Builder()
                .url(protocol + "://" + domain + ":" + port + file)
                .get()
                .addHeader("Connection", "close")
                .build();

        Response response = client.newCall(request).execute();

        status_code = response.code();
        onSEDomainAlive(protocol, "GET", domain, port, file, status_code);
    }

    public List<String> doEnumeration(String domain) throws IOException, InterruptedException {
        List<String> result = new ArrayList<>();

        if (!useCRTShAPICheckBox.isSelected() && !useSecuirtyTrailsAPICheckBox.isSelected()) {
            throw new InterruptedException("No API(s) is selected");
        }

        if (useSecuirtyTrailsAPICheckBox.isSelected()) {
            String APIKey = securityTrailsAPI.getText();
            if (APIKey.equals("")) {
                throw new InterruptedException("No API Key");
            }
            checkQueueTableUpdateCurrentRow(new Object[]{null, "SecurityTrails enum..."});
            result.addAll(doCallAPISecurityTrails(domain, APIKey));
        }

        if (useCRTShAPICheckBox.isSelected()) {
            checkQueueTableUpdateCurrentRow(new Object[]{null, "CRT.sh enum..."});
            result.addAll(doCallCRTsh(domain));
        }

        // add the main domain also to check if alive or not
        if (!result.contains(domain)) {
            result.add(domain);
        }

        Set<String> set = new HashSet<>(result);
        result.clear();
        result.addAll(set);

        return result;
    }

    private List<String> doCallCRTsh(String domain) throws InterruptedException, IOException {
        List<String> result = new ArrayList<>();

        queueWorkerMutex.step();

        Thread.sleep(10,300);

        OkHttpClient client = new OkHttpClient.Builder().connectTimeout(3, TimeUnit.SECONDS).build();

        Request request = new Request.Builder()
                .url("https://crt.sh/?q=" + domain + "&output=json")
                .get()
                .addHeader("accept", "application/json")
                .build();

        Response response = client.newCall(request).execute();

        if (response.code() != 200){
            throw new IOException(response.toString());
        } else {
            String json = response.body().string();
            Gson g = new Gson();
            SECRTshModel[] entries = g.fromJson(json, SECRTshModel[].class);
            if (entries == null) {
                errorMsg(response.toString());
            } else {
                for (SECRTshModel entry : entries) {
                    for (String subdomain : entry.name_value.split("\n")) {
                        result.add(subdomain);
                    }
                }
            }
        }
        return result;
    }

    private List<String> doCallAPISecurityTrails(String hostname, String APIKey) throws AssertionError, InterruptedException, IOException {
        List<String> result = new ArrayList<>();

        queueWorkerMutex.step();

        Thread.sleep(10,300);

        OkHttpClient client = new OkHttpClient.Builder().connectTimeout(3, TimeUnit.SECONDS).build();

        Request request = new Request.Builder()
                .url("https://api.securitytrails.com/v1/domain/" + hostname + "/subdomains?children_only=false")
                .get()
                .addHeader("APIKEY", APIKey)
                .addHeader("accept", "application/json")
                .build();

        Response response = client.newCall(request).execute();

        if (response.code() != 200){
            throw new IOException(response.toString());
        } else {
            String json = response.body().string();
            Gson g = new Gson();
            SecurityTrailsModel obj = g.fromJson(json, SecurityTrailsModel.class);
            obj.subdomains.forEach(new Consumer<String>() {
                @Override
                public void accept(String s) {
                    result.add(s + "." + hostname);
                }
            });
        }
        return result;
    }

    public void onSEDomainAlive(String protocol, String method, String domain, int port, String file, int status_code) {
        checkedResultTableModel.addRow(new Object[]{domain, protocol, method, port, status_code});
        if (!aliveDomainList.contains(domain)) {
            aliveDomainList.add(domain);
        }
    }
}
