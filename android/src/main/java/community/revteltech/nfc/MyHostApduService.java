package community.revteltech.nfc;

import android.content.Context;
import android.content.Intent;
import android.nfc.NdefRecord;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.util.Log;
import android.view.Gravity;
import android.widget.Toast;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.Arrays;

public class MyHostApduService extends HostApduService {

    private static final String TAG = "JDR HostApduService";

    //
    // We use the default AID from the HCE Android documentation
    // https://developer.android.com/guide/topics/connectivity/nfc/hce.html
    //
    // Ala... <aid-filter android:name="F0394148148100" />
    //
    private static final byte[] APDU_SELECT = {
        (byte)0x00, // CLA	- Class - Class of instruction
        (byte)0xA4, // INS	- Instruction - Instruction code
        (byte)0x04, // P1	- Parameter 1 - Instruction parameter 1
        (byte)0x00, // P2	- Parameter 2 - Instruction parameter 2
        (byte)0x07, // Lc field	- Number of bytes present in the data field of the command
        (byte)0xF0, (byte)0x39, (byte)0x41, (byte)0x48, (byte)0x14, (byte)0x81, (byte)0x00, // NDEF Tag Application name
        (byte)0x00  // Le field	- Maximum number of bytes expected in the data field of the response to the command
    };

    private static final byte[] APDU_SELECT_1 = {
        (byte)0x00, // CLA	- Class - Class of instruction
        (byte)0xA4, // INS	- Instruction - Instruction code
        (byte)0x04, // P1	- Parameter 1 - Instruction parameter 1
        (byte)0x00, // P2	- Parameter 2 - Instruction parameter 2
        (byte)0x07, // Lc field	- Number of bytes present in the data field of the command
        (byte)0xA0, (byte)0x00, (byte)0x00, (byte)0x02, (byte)0x47, (byte)0x10, (byte)0x01, // NDEF Tag Application name
        (byte)0x00  // Le field	- Maximum number of bytes expected in the data field of the response to the command
    };

    private static final byte[] APDU_SELECT_2 = {
            (byte)0x00, // CLA	- Class - Class of instruction
            (byte)0xA4, // INS	- Instruction - Instruction code
            (byte)0x04, // P1	- Parameter 1 - Instruction parameter 1
            (byte)0x00, // P2	- Parameter 2 - Instruction parameter 2
            (byte)0x07, // Lc field	- Number of bytes present in the data field of the command
            (byte)0xD2, (byte)0x76, (byte)0x00, (byte)0x00, (byte)0x85, (byte)0x01, (byte)0x01, // NDEF Tag Application name
            (byte)0x00  // Le field	- Maximum number of bytes expected in the data field of the response to the command
    };

    private static final byte[] CAPABILITY_CONTAINER = {
            (byte)0x00, // CLA	- Class - Class of instruction
            (byte)0xa4, // INS	- Instruction - Instruction code
            (byte)0x00, // P1	- Parameter 1 - Instruction parameter 1
            (byte)0x0c, // P2	- Parameter 2 - Instruction parameter 2
            (byte)0x02, // Lc field	- Number of bytes present in the data field of the command
            (byte)0xe1, (byte)0x03 // file identifier of the CC file
    };

    private static final byte[] READ_CAPABILITY_CONTAINER = {
            (byte)0x00, // CLA	- Class - Class of instruction
            (byte)0xb0, // INS	- Instruction - Instruction code
            (byte)0x00, // P1	- Parameter 1 - Instruction parameter 1
            (byte)0x00, // P2	- Parameter 2 - Instruction parameter 2
            (byte)0x0f  // Lc field	- Number of bytes present in the data field of the command
    };

    // In the scenario that we have done a CC read, the same byte[] match
    // for ReadBinary would trigger and we don't want that in succession
    private boolean READ_CAPABILITY_CONTAINER_CHECK = false;

    private static final byte[] READ_CAPABILITY_CONTAINER_RESPONSE = {
            (byte)0x00, (byte)0x0F, // CCLEN length of the CC file
            (byte)0x20, // Mapping Version 2.0
            (byte)0x00, (byte)0x3B, // MLe maximum 59 bytes R-APDU data size
            (byte)0x00, (byte)0x34, // MLc maximum 52 bytes C-APDU data size
            (byte)0x04, // T field of the NDEF File Control TLV
            (byte)0x06, // L field of the NDEF File Control TLV
            (byte)0xE1, (byte)0x04, // File Identifier of NDEF file
            (byte)0x00, (byte)0x32, // Maximum NDEF file size of 50 bytes
            (byte)0x00, // Read access without any security
            (byte)0x00, // Write access without any security
            (byte)0x90, (byte)0x00 // A_OKAY
    };

    private static final byte[] NDEF_SELECT = {
            (byte)0x00, // CLA	- Class - Class of instruction
            (byte)0xa4, // Instruction byte (INS) for Select command
            (byte)0x00, // Parameter byte (P1), select by identifier
            (byte)0x0c, // Parameter byte (P1), select by identifier
            (byte)0x02, // Lc field	- Number of bytes present in the data field of the command
            (byte)0xE1, (byte)0x04 // file identifier of the NDEF file retrieved from the CC file
    };

    private static final byte[] NDEF_READ_BINARY_NLEN = {
            (byte)0x00, // Class byte (CLA)
            (byte)0xb0, // Instruction byte (INS) for ReadBinary command
            (byte)0x00, (byte)0x00, // Parameter byte (P1, P2), offset inside the CC file
            (byte)0x02  // Le field
    };

    private static final byte[] NDEF_READ_BINARY_GET_NDEF = {
            (byte)0x00, // Class byte (CLA)
            (byte)0xb0, // Instruction byte (INS) for ReadBinary command
            (byte)0x00, (byte)0x00, // Parameter byte (P1, P2), offset inside the CC file
            (byte)0x0f  //  Le field
    };

    private static final byte[] A_OKAY = {
            (byte)0x90,  // SW1	Status byte 1 - Command processing status
            (byte)0x00   // SW2	Status byte 2 - Command processing qualifier
    };

    private static final byte[] NDEF_ID = {
            (byte)0xE1,
            (byte)0x04
    };

    private static final byte[] UNKNOWN_CMD_SW = {
        (byte)0X00,
        (byte)0x00
    };

    private byte[] NDEF_BYTES;
    private byte[] NDEF_LEN;

    @Override
    public void onCreate() {
        super.onCreate();
        Log.d(TAG, getClass().getName() + " HCE service created");
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String data = IDWarehouse.GetID(this.getApplicationContext());
        if (data.getBytes()) {
            NDEF_BYTES = data.getBytes();
            NDEF_LEN = BigInteger.valueOf(NDEF_BYTES.length).toByteArray();
        }
        return 0;
    }

    @Override
    public byte[] processCommandApdu(byte[] commandApdu, Bundle extras) {

        //
        // The following flow is based on Appendix E "Example of Mapping Version 2.0 Command Flow"
        // in the NFC Forum specification
        //
        Log.i(TAG, "processCommandApdu() | incoming commandApdu: " + Util.bytesToHex(commandApdu));

        //
        // First command: NDEF Tag Application select (Section 5.5.2 in NFC Forum spec)
        //
        if (Util.isEqual(APDU_SELECT, commandApdu)) {
            Log.i(TAG, "APDU_SELECT triggered. Our Response: " + Util.bytesToHex(A_OKAY));
            return A_OKAY;
        }
        else if (Util.isEqual(APDU_SELECT_1, commandApdu)) {
            Log.i(TAG, "APDU_SELECT triggered. Our Response: " + Util.bytesToHex(A_OKAY));
            return A_OKAY;
        }
        else if (Util.isEqual(APDU_SELECT_2, commandApdu)) {
            Log.i(TAG, "APDU_SELECT triggered. Our Response: " + Util.bytesToHex(A_OKAY));
            return A_OKAY;
        }

        //
        // Second command: Capability Container select (Section 5.5.3 in NFC Forum spec)
        //
        if (Util.isEqual(CAPABILITY_CONTAINER, commandApdu)) {
            Log.i(TAG, "CAPABILITY_CONTAINER triggered. Our Response: " + Util.bytesToHex(A_OKAY));
            return A_OKAY;
        }

        //
        // Third command: ReadBinary data from CC file (Section 5.5.4 in NFC Forum spec)
        //
        if (Util.isEqual(READ_CAPABILITY_CONTAINER, commandApdu) && !READ_CAPABILITY_CONTAINER_CHECK) {
            Log.i(TAG, "READ_CAPABILITY_CONTAINER triggered. Our Response: " + Util.bytesToHex(READ_CAPABILITY_CONTAINER_RESPONSE));
            READ_CAPABILITY_CONTAINER_CHECK = true;
            return READ_CAPABILITY_CONTAINER_RESPONSE;
        }

        //
        // Fourth command: NDEF Select command (Section 5.5.5 in NFC Forum spec)
        //
        if (Util.isEqual(NDEF_SELECT, commandApdu)) {
            Log.i(TAG, "NDEF_SELECT triggered. Our Response: " + Util.bytesToHex(A_OKAY));
            return A_OKAY;
        }

        //
        // Fifth command:  ReadBinary, read NLEN field
        //
        if (Util.isEqual(NDEF_READ_BINARY_NLEN, commandApdu)) {

            getData();

            byte[] start = {
                (byte)0x00
            };

            // Build our response
            byte[] response = new byte[start.length + NDEF_LEN.length + A_OKAY.length];

            System.arraycopy(start, 0, response, 0, start.length);
            System.arraycopy(NDEF_LEN, 0, response, start.length, NDEF_LEN.length);
            System.arraycopy(A_OKAY, 0, response, start.length + NDEF_LEN.length, A_OKAY.length);

            Log.i(TAG, response.toString());
            Log.i(TAG, "NDEF_READ_BINARY_NLEN triggered. Our Response: " + Util.bytesToHex(response));

            return response;
        }

        //
        // Sixth command: ReadBinary, get NDEF data
        //
        if (Util.isEqual(NDEF_READ_BINARY_GET_NDEF, commandApdu)) {
            Log.i(TAG, "processCommandApdu() | NDEF_READ_BINARY_GET_NDEF triggered");

            getData();

            byte[] start = {
                (byte)0x00
            };

            // Build our response
            byte[] response = new byte[start.length + NDEF_LEN.length + NDEF_BYTES.length + A_OKAY.length];

            System.arraycopy(start, 0, response, 0, start.length);
            System.arraycopy(NDEF_LEN, 0, response, start.length, NDEF_LEN.length);
            System.arraycopy(NDEF_BYTES, 0, response, start.length + NDEF_LEN.length, NDEF_BYTES.length);
            System.arraycopy(A_OKAY, 0, response, start.length + NDEF_LEN.length + NDEF_BYTES.length, A_OKAY.length);

            Log.i(TAG, "NDEF_READ_BINARY_GET_NDEF triggered. Our Response: " + Util.bytesToHex(response));

            READ_CAPABILITY_CONTAINER_CHECK = false;
            return response;
        }

        //
        // We're doing something outside our scope
        //
        Log.wtf(TAG, "processCommandApdu() | I don't know what's going on!!!.");
        return UNKNOWN_CMD_SW;
    }

    @Override
    public void onDeactivated(int reason) {
        Log.i(TAG, "onDeactivated() Fired! Reason: " + reason);
    }

    private void getData() {
        String data = IDWarehouse.GetID(this.getApplicationContext());
        if (data.getBytes()) {
            NDEF_BYTES = data.getBytes();
            NDEF_LEN = BigInteger.valueOf(NDEF_BYTES.length).toByteArray();
        }
    }
}
