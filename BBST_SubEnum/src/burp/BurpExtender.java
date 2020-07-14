/**
 * $Project (c) Bug Busters Security Team 2020
 */
package burp;

import bbst.SEActions;

public class BurpExtender extends SEActions implements IBurpExtender
{
    private IContextMenuFactory context;

    public BurpExtender() {
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // your extension code here
        this.callbacks = callbacks;

        // prepare worker before the GUI
        queueWorker.execute();

        callbacks.setExtensionName(extensionName);
        callbacks.customizeUiComponent(this);
    	callbacks.addSuiteTab(this);

    	/*
    	context = new SEIContextFactory(callbacks);
    	callbacks.registerContextMenuFactory(context);
    	*/
        callbacks.printOutput(extensionName + " Loaded.  Version: " + VERSION);
    }
}