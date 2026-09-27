
package com.torchat;

import android.os.Bundle;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        // Local (non-npm) native plugins must be registered explicitly before
        // super.onCreate() builds the bridge.
        registerPlugin(TorPlugin.class);
        super.onCreate(savedInstanceState);
    }
}
